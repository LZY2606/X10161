//! 抓包来源：项目自定义确定性帧夹具（JSON）与简化 pcap 的解析/导出。

use crate::packet::LinkType;
use serde::{Deserialize, Serialize};
use std::fmt;

/// 一帧原始数据。时间戳相同的情况下以 `index`（原始帧序号）排序。
#[derive(Clone, Debug)]
pub struct Frame {
    pub index: u64,
    pub ts_ns: u64,
    pub link: LinkType,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct CaptureError(pub String);

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "capture error: {}", self.0)
    }
}

impl std::error::Error for CaptureError {}

impl From<serde_json::Error> for CaptureError {
    fn from(e: serde_json::Error) -> Self {
        CaptureError(format!("json: {e}"))
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, CaptureError> {
    Err(CaptureError(msg.into()))
}

// ---------- 自定义夹具格式 ----------

pub const FIXTURE_FORMAT: &str = "pairwise-gsb-fixture";

#[derive(Serialize, Deserialize)]
pub struct FixtureFile {
    pub format: String,
    pub version: u32,
    pub frames: Vec<FixtureFrame>,
}

#[derive(Serialize, Deserialize)]
pub struct FixtureFrame {
    pub index: u64,
    pub ts_ns: u64,
    pub link: LinkType,
    pub data_hex: String,
}

pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, CaptureError> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return err("odd hex length");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16);
        let lo = (bytes[i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push(((h << 4) | l) as u8),
            _ => return err("invalid hex digit"),
        }
    }
    Ok(out)
}

/// 帧列表 -> 确定性夹具 JSON（字段顺序固定，逐字节确定）。
pub fn frames_to_fixture_json(frames: &[Frame]) -> String {
    let file = FixtureFile {
        format: FIXTURE_FORMAT.to_string(),
        version: 1,
        frames: frames
            .iter()
            .map(|f| FixtureFrame {
                index: f.index,
                ts_ns: f.ts_ns,
                link: f.link,
                data_hex: hex_encode(&f.data),
            })
            .collect(),
    };
    serde_json::to_string_pretty(&file).expect("fixture serialize")
}

pub fn fixture_json_to_frames(json: &str) -> Result<Vec<Frame>, CaptureError> {
    let file: FixtureFile = serde_json::from_str(json)?;
    if file.format != FIXTURE_FORMAT {
        return err(format!("unknown fixture format: {}", file.format));
    }
    let mut frames = Vec::with_capacity(file.frames.len());
    for ff in &file.frames {
        frames.push(Frame {
            index: ff.index,
            ts_ns: ff.ts_ns,
            link: ff.link,
            data: hex_decode(&ff.data_hex)?,
        });
    }
    Ok(frames)
}

// ---------- 简化 pcap ----------

const PCAP_MAGIC_USEC: u32 = 0xA1B2_C3D4;
const PCAP_MAGIC_NSEC: u32 = 0xA1B2_3C4D;
const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_RAW: u32 = 101;

fn linktype_to_u32(link: LinkType) -> u32 {
    match link {
        LinkType::Ethernet => LINKTYPE_ETHERNET,
        LinkType::Raw => LINKTYPE_RAW,
    }
}

fn linktype_from_u32(v: u32) -> Result<LinkType, CaptureError> {
    match v {
        LINKTYPE_ETHERNET => Ok(LinkType::Ethernet),
        LINKTYPE_RAW => Ok(LinkType::Raw),
        other => err(format!("unsupported pcap linktype {other}")),
    }
}

/// 帧列表 -> 简化 pcap（微秒精度，小端写出魔数 d4 c3 b2 a1）。
pub fn frames_to_pcap(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PCAP_MAGIC_USEC.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    let link = frames.first().map(|f| f.link).unwrap_or(LinkType::Ethernet);
    out.extend_from_slice(&linktype_to_u32(link).to_le_bytes());
    for f in frames {
        let secs = (f.ts_ns / 1_000_000_000) as u32;
        let usecs = ((f.ts_ns % 1_000_000_000) / 1_000) as u32;
        out.extend_from_slice(&secs.to_le_bytes());
        out.extend_from_slice(&usecs.to_le_bytes());
        out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&f.data);
    }
    out
}

pub fn pcap_to_frames(data: &[u8]) -> Result<Vec<Frame>, CaptureError> {
    if data.len() < 24 {
        return err("short pcap global header");
    }
    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (le, nsec) = match magic_le {
        PCAP_MAGIC_USEC => (true, false),
        PCAP_MAGIC_NSEC => (true, true),
        _ => {
            let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            match magic_be {
                PCAP_MAGIC_USEC => (false, false),
                PCAP_MAGIC_NSEC => (false, true),
                _ => return err("bad pcap magic"),
            }
        }
    };
    let u16rd = |b: &[u8]| -> u16 {
        if le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    };
    let u32rd = |b: &[u8]| -> u32 {
        if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let major = u16rd(&data[4..6]);
    if major != 2 {
        return err(format!("unsupported pcap version {major}"));
    }
    let link = linktype_from_u32(u32rd(&data[20..24]))?;
    let mut frames = Vec::new();
    let mut off = 24usize;
    let mut index = 0u64;
    while off + 16 <= data.len() {
        let secs = u32rd(&data[off..off + 4]) as u64;
        let frac = u32rd(&data[off + 4..off + 8]) as u64;
        let incl = u32rd(&data[off + 8..off + 12]) as usize;
        off += 16;
        if off + incl > data.len() {
            return err("truncated pcap packet");
        }
        let ts_ns = if nsec {
            secs * 1_000_000_000 + frac
        } else {
            secs * 1_000_000_000 + frac * 1_000
        };
        frames.push(Frame {
            index,
            ts_ns,
            link,
            data: data[off..off + incl].to_vec(),
        });
        off += incl;
        index += 1;
    }
    Ok(frames)
}

/// 自动识别输入格式并解析为帧列表。
pub fn detect_and_parse(data: &[u8]) -> Result<Vec<Frame>, CaptureError> {
    if data.len() >= 4 {
        let m = [data[0], data[1], data[2], data[3]];
        if m == [0xd4, 0xc3, 0xb2, 0xa1]
            || m == [0xa1, 0xb2, 0xc3, 0xd4]
            || m == [0x4d, 0x3c, 0xb2, 0xa1]
            || m == [0xa1, 0xb2, 0x3c, 0x4d]
        {
            return pcap_to_frames(data);
        }
    }
    let text = std::str::from_utf8(data).map_err(|_| CaptureError("not utf8 json".into()))?;
    fixture_json_to_frames(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frames() -> Vec<Frame> {
        vec![
            Frame {
                index: 0,
                ts_ns: 1_700_000_000_123_456_000,
                link: LinkType::Ethernet,
                data: vec![1, 2, 3, 4],
            },
            Frame {
                index: 1,
                ts_ns: 1_700_000_000_123_456_000,
                link: LinkType::Ethernet,
                data: vec![5, 6],
            },
        ]
    }

    #[test]
    fn fixture_roundtrip() {
        let frames = sample_frames();
        let json = frames_to_fixture_json(&frames);
        let back = fixture_json_to_frames(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].data, vec![1, 2, 3, 4]);
        assert_eq!(back[1].ts_ns, frames[1].ts_ns);
        // 确定性：再次序列化结果一致
        assert_eq!(frames_to_fixture_json(&back), json);
    }

    #[test]
    fn pcap_roundtrip() {
        let frames = sample_frames();
        let pcap = frames_to_pcap(&frames);
        let back = pcap_to_frames(&pcap).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].ts_ns, frames[0].ts_ns);
        assert_eq!(back[1].data, vec![5, 6]);
    }

    #[test]
    fn detect_both() {
        let frames = sample_frames();
        assert!(detect_and_parse(&frames_to_pcap(&frames)).is_ok());
        assert!(detect_and_parse(frames_to_fixture_json(&frames).as_bytes()).is_ok());
    }
}
