//! Frame model and capture input formats (simplified pcap + deterministic fixture).

use crate::json::{hex_decode, hex_encode, Json};
use crate::sha256::sha256_hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    RawIp,
}

impl LinkType {
    pub fn name(&self) -> &'static str {
        match self {
            LinkType::Ethernet => "eth",
            LinkType::RawIp => "raw",
        }
    }
    pub fn from_name(s: &str) -> Option<LinkType> {
        match s {
            "eth" | "ethernet" => Some(LinkType::Ethernet),
            "raw" | "ip" => Some(LinkType::RawIp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    /// Original capture order; the final tie-breaker for equal timestamps.
    pub index: u64,
    /// Seconds (fractional) timestamp.
    pub ts: f64,
    pub link: LinkType,
    pub data: Vec<u8>,
    /// Content address of the raw frame bytes.
    pub hash: String,
}

impl Frame {
    pub fn new(index: u64, ts: f64, link: LinkType, data: Vec<u8>) -> Frame {
        let hash = sha256_hex(&data);
        Frame { index, ts, link, data, hash }
    }
}

/// Parse a capture input: either classic pcap bytes or the project fixture JSON.
pub fn parse_capture(input: &[u8]) -> Result<Vec<Frame>, String> {
    if input.len() >= 4 && is_pcap_magic(&input[..4]) {
        parse_pcap(input)
    } else {
        let text = std::str::from_utf8(input).map_err(|_| "input is neither pcap nor UTF-8 fixture JSON".to_string())?;
        parse_fixture(text)
    }
}

fn is_pcap_magic(b: &[u8]) -> bool {
    matches!(
        b,
        [0xa1, 0xb2, 0xc3, 0xd4]
            | [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d]
            | [0x4d, 0x3c, 0xb2, 0xa1]
    )
}

/// Classic (simplified) pcap: global header + packet records.
pub fn parse_pcap(data: &[u8]) -> Result<Vec<Frame>, String> {
    if data.len() < 24 {
        return Err("pcap: truncated global header".to_string());
    }
    let magic = &data[0..4];
    let (le, nano) = match magic {
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        _ => return Err("pcap: bad magic".to_string()),
    };
    let u32_at = |off: usize| -> u32 {
        let b = &data[off..off + 4];
        if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let linktype = {
        let b = &data[20..24];
        (if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }) & 0xffff
    };
    let link = match linktype {
        1 => LinkType::Ethernet,
        101 | 228 => LinkType::RawIp,
        other => return Err(format!("pcap: unsupported linktype {}", other)),
    };
    let mut frames = Vec::new();
    let mut off = 24usize;
    let mut index = 0u64;
    while off + 16 <= data.len() {
        let ts_sec = u32_at(off) as u64;
        let ts_frac = u32_at(off + 4) as u64;
        let incl = u32_at(off + 8) as usize;
        off += 16;
        if off + incl > data.len() {
            return Err(format!("pcap: truncated record {} (need {} bytes)", index, incl));
        }
        let ts = if nano {
            ts_sec as f64 + ts_frac as f64 / 1_000_000_000.0
        } else {
            ts_sec as f64 + ts_frac as f64 / 1_000_000.0
        };
        frames.push(Frame::new(index, ts, link, data[off..off + incl].to_vec()));
        off += incl;
        index += 1;
    }
    if off != data.len() {
        return Err("pcap: trailing garbage after last record".to_string());
    }
    Ok(frames)
}

/// Deterministic project fixture format:
/// {"format":"pairwise-fixture-v1","frames":[{"ts":1.0,"link":"eth","data":"deadbeef"}]}
pub fn parse_fixture(text: &str) -> Result<Vec<Frame>, String> {
    let v = Json::parse(text)?;
    let frames = v
        .get("frames")
        .and_then(|f| f.as_arr())
        .ok_or_else(|| "fixture: missing \"frames\" array".to_string())?;
    let mut out = Vec::new();
    for (i, f) in frames.iter().enumerate() {
        let ts = f
            .get("ts")
            .and_then(|t| t.as_num())
            .ok_or_else(|| format!("fixture: frame {} missing ts", i))?;
        let link = f
            .get("link")
            .and_then(|l| l.as_str())
            .and_then(LinkType::from_name)
            .ok_or_else(|| format!("fixture: frame {} bad link", i))?;
        let data = f
            .get("data")
            .and_then(|d| d.as_str())
            .ok_or_else(|| format!("fixture: frame {} missing data", i))?;
        let bytes = hex_decode(data).map_err(|e| format!("fixture: frame {} data: {}", i, e))?;
        out.push(Frame::new(i as u64, ts, link, bytes));
    }
    Ok(out)
}

/// Canonical fixture export; re-importing yields identical frames (stable fingerprint).
pub fn export_fixture(frames: &[Frame]) -> String {
    let mut arr = Vec::new();
    for f in frames {
        let mut o = Json::obj();
        o.set("ts", Json::num(f.ts));
        o.set("link", Json::str(f.link.name()));
        o.set("data", Json::str(hex_encode(&f.data)));
        arr.push(o);
    }
    let mut root = Json::obj();
    root.set("format", Json::str("pairwise-fixture-v1"));
    root.set("frames", Json::Arr(arr));
    root.to_canonical()
}
