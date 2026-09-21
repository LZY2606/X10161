//! 经典 libpcap 文件读取器（microsecond/nanosecond、小端/大端）。

pub struct PcapHeader {
    pub link_type: u32,
    pub snaplen: u32,
    pub nanosecond: bool,
}

#[derive(Debug, Clone)]
pub struct RawFrame {
    /// 微秒时间戳（纳秒精度被除以 1000）。
    pub ts_us: i64,
    pub data: Vec<u8>,
    /// 包含的原始长度（可能大于 data.len()，说明被 snaplen 截断）。
    pub orig_len: u32,
}

#[derive(Debug, Clone, Copy)]
struct Endian {
    little: bool,
}

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        if self.little {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        let arr = [b[0], b[1], b[2], b[3]];
        if self.little {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        }
    }
    fn i32(self, b: &[u8]) -> i32 {
        self.u32(b) as i32
    }
}

/// 解析整个 pcap，返回全局头与帧列表。
pub fn parse(input: &[u8]) -> Result<(PcapHeader, Vec<RawFrame>), String> {
    if input.len() < 24 {
        return Err("pcap: 文件短于 24 字节全局头".into());
    }
    let magic = &input[0..4];
    let (endian, nanosecond) = match magic {
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian { little: false }, false),
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian { little: true }, false),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian { little: false }, true),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian { little: true }, true),
        _ => {
            if &magic[..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
                return Err("pcap: 检测到 pcapng，本工具仅支持经典 pcap".into());
            }
            return Err("pcap: 非法 magic number".into());
        }
    };

    let version_major = endian.u16(&input[4..6]);
    if version_major != 2 {
        return Err(format!("pcap: 不支持的主版本 {}", version_major));
    }
    let snaplen = endian.u32(&input[16..20]);
    let link_type = endian.u32(&input[20..24]) & 0x0fff_ffff;

    let mut frames = Vec::new();
    let mut pos = 24usize;
    while pos < input.len() {
        if pos + 16 > input.len() {
            return Err(format!("pcap: 位置 {} 的记录头不完整", pos));
        }
        let ts_sec = endian.i32(&input[pos..pos + 4]) as i64;
        let ts_frac = endian.u32(&input[pos + 4..pos + 8]);
        let incl_len = endian.u32(&input[pos + 8..pos + 12]) as usize;
        let orig_len = endian.u32(&input[pos + 12..pos + 16]);
        pos += 16;
        if pos + incl_len > input.len() {
            return Err("pcap: 帧数据超出文件末尾".into());
        }
        let data = input[pos..pos + incl_len].to_vec();
        pos += incl_len;
        let ts_us = if nanosecond {
            ts_sec * 1_000_000 + (ts_frac as i64) / 1000
        } else {
            ts_sec * 1_000_000 + ts_frac as i64
        };
        frames.push(RawFrame {
            ts_us,
            data,
            orig_len,
        });
    }

    Ok((
        PcapHeader {
            link_type,
            snaplen,
            nanosecond,
        },
        frames,
    ))
}

/// 将帧编码为小端微秒 pcap，供导出/往返测试使用。
pub fn encode(link_type: u32, frames: &[RawFrame]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&262144u32.to_le_bytes());
    out.extend_from_slice(&link_type.to_le_bytes());
    for f in frames {
        let sec = f.ts_us / 1_000_000;
        let us = f.ts_us % 1_000_000;
        out.extend_from_slice(&(sec as i32).to_le_bytes());
        out.extend_from_slice(&(us as u32).to_le_bytes());
        out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&f.orig_len.to_le_bytes());
        out.extend_from_slice(&f.data);
    }
    out
}
