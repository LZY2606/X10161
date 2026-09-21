//! 经典 libpcap 文件格式（micro/nano、大小端）只读解析，以及小端 micro 写出。

use crate::model::RawFrame;

const MAGIC_MICRO_LE: u32 = 0xa1b2c3d4;
const MAGIC_NANO_LE: u32 = 0xa1b23c4d;

pub struct PcapFile {
    pub linktype: u32,
    pub frames: Vec<RawFrame>,
}

pub fn parse_pcap(input: &[u8]) -> Result<PcapFile, String> {
    if input.len() < 24 {
        return Err("pcap: 文件短于 24 字节全局头".into());
    }
    let magic = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let (nano, big_endian) = match magic {
        MAGIC_MICRO_LE | MAGIC_NANO_LE => (magic == MAGIC_NANO_LE, false),
        _ => {
            let be = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
            match be {
                MAGIC_MICRO_LE => (false, true),
                MAGIC_NANO_LE => (true, true),
                _ => return Err("pcap: 无法识别的 magic（仅支持经典 pcap，不支持 pcapng）".into()),
            }
        }
    };

    let rd16 = |b: &[u8]| if big_endian { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) };
    let rd32 = |b: &[u8]| if big_endian { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) } else { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) };

    let linktype = rd32(&input[20..24]);
    let mut pos = 24;
    let mut frames = Vec::new();
    let mut frame_no = 1u64;

    while pos < input.len() {
        if pos + 16 > input.len() {
            return Err(format!("pcap: 第 {} 个记录头不完整", frame_no));
        }
        let ts_sec = rd32(&input[pos..pos + 4]) as i64;
        let ts_frac = rd32(&input[pos + 4..pos + 8]) as i64;
        let incl_len = rd32(&input[pos + 8..pos + 12]) as usize;
        let _orig_len = rd32(&input[pos + 12..pos + 16]) as usize;
        pos += 16;
        if pos + incl_len > input.len() {
            return Err(format!("pcap: 第 {} 个记录数据被截断", frame_no));
        }
        let ts_ns = if nano {
            ts_sec * 1_000_000_000 + ts_frac
        } else {
            ts_sec * 1_000_000_000 + ts_frac * 1_000
        };
        let bytes = input[pos..pos + incl_len].to_vec();
        pos += incl_len;
        frames.push(RawFrame { frame_no, ts_ns, bytes });
        frame_no += 1;
    }

    let _ = rd16;
    Ok(PcapFile { linktype, frames })
}

/// 以 LINKTYPE_ETHERNET(1)、小端微秒精度写出经典 pcap。
pub fn write_pcap(frames: &[RawFrame]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + frames.iter().map(|f| f.bytes.len() + 16).sum::<usize>());
    out.extend_from_slice(&MAGIC_MICRO_LE.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes()); // major
    out.extend_from_slice(&4u16.to_le_bytes()); // minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&262144u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    for f in frames {
        let sec = f.ts_ns.div_euclid(1_000_000_000) as u32;
        let usec = f.ts_ns.rem_euclid(1_000_000_000) / 1000;
        out.extend_from_slice(&sec.to_le_bytes());
        out.extend_from_slice(&(usec as u32).to_le_bytes());
        out.extend_from_slice(&(f.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&f.bytes);
    }
    out
}
