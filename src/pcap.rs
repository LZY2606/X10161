//! 简化经典 pcap 读取器（不含 pcapng）：仅解析全局头与逐包记录，
//! 链路类型支持 Ethernet(1)、RAW(101)、LINKTYPE_IPV4(228)。

use crate::model::Frame;

const MAGIC_US_LE: u32 = 0xa1b2_c3d4;
const MAGIC_US_BE: u32 = 0xd4c3_b2a1;
const MAGIC_NS_LE: u32 = 0xa1b2_3c4d;
const MAGIC_NS_BE: u32 = 0x4d3c_b2a1;

pub fn looks_like_pcap(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    matches!(magic, MAGIC_US_LE | MAGIC_US_BE | MAGIC_NS_LE | MAGIC_NS_BE)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    big_endian: bool,
}

impl<'a> Reader<'a> {
    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(if self.big_endian {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        })
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(if self.big_endian {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        })
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.data.len() {
            return Err("truncated pcap".into());
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
}

pub fn parse_pcap(data: &[u8]) -> Result<Vec<Frame>, String> {
    if data.len() < 24 {
        return Err("pcap shorter than global header".into());
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (big_endian, nanos) = match magic {
        MAGIC_US_LE => (false, false),
        MAGIC_US_BE => (true, false),
        MAGIC_NS_LE => (false, true),
        MAGIC_NS_BE => (true, true),
        _ => return Err("bad pcap magic".into()),
    };
    let mut r = Reader {
        data,
        pos: 4,
        big_endian,
    };
    let _version_major = r.u16()?;
    let _version_minor = r.u16()?;
    let _thiszone = r.u32()? as i32;
    let _sigfigs = r.u32()?;
    let _snaplen = r.u32()?;
    let linktype = r.u32()? & 0xffff;

    let wrap = |pkt: &[u8]| -> Vec<u8> {
        match linktype {
            1 => pkt.to_vec(),
            101 | 228 => pkt.to_vec(), // 裸 IP：解析器按首字节 nibble 识别
            _ => pkt.to_vec(),
        }
    };

    let mut frames = Vec::new();
    let mut index = 0u32;
    while r.pos < data.len() {
        let ts_sec = r.u32()? as u64;
        let ts_frac = r.u32()? as u64;
        let incl_len = r.u32()? as usize;
        let orig_len = r.u32()? as usize;
        let _ = orig_len;
        let pkt = r.take(incl_len)?;
        let ts_ns = if nanos {
            ts_sec * 1_000_000_000 + ts_frac
        } else {
            ts_sec * 1_000_000_000 + ts_frac * 1_000
        };
        let _ = r;
        frames.push(Frame {
            index,
            ts_ns,
            raw: wrap(pkt),
        });
        index += 1;
    }
    Ok(frames)
}
