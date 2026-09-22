use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct Frame {
    pub index: u64,
    pub ts_ns: u64,
    pub data: Vec<u8>,
}

pub fn to_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".into());
    }
    let nib = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("invalid hex char {}", c as char)),
        }
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Ok(out)
}

#[derive(Serialize, Deserialize)]
pub struct FixtureFrame {
    pub ts_ns: u64,
    pub data: String,
}

#[derive(Serialize, Deserialize)]
pub struct Fixture {
    pub format: String,
    pub frames: Vec<FixtureFrame>,
}

pub const FIXTURE_FORMAT: &str = "frame-fixture-v1";

pub fn export_fixture(frames: &[Frame]) -> String {
    let f = Fixture {
        format: FIXTURE_FORMAT.to_string(),
        frames: frames
            .iter()
            .map(|fr| FixtureFrame {
                ts_ns: fr.ts_ns,
                data: to_hex(&fr.data),
            })
            .collect(),
    };
    serde_json::to_string_pretty(&f).expect("fixture serialization is infallible")
}

pub fn parse_fixture(text: &str) -> Result<Vec<Frame>, String> {
    let f: Fixture = serde_json::from_str(text).map_err(|e| format!("invalid fixture JSON: {e}"))?;
    if f.format != FIXTURE_FORMAT {
        return Err(format!("unsupported fixture format {}", f.format));
    }
    let mut out = Vec::with_capacity(f.frames.len());
    for (i, fr) in f.frames.iter().enumerate() {
        out.push(Frame {
            index: i as u64,
            ts_ns: fr.ts_ns,
            data: from_hex(&fr.data)?,
        });
    }
    Ok(out)
}

/// Parse a simplified classic pcap (Ethernet linktype only).
pub fn parse_pcap(b: &[u8]) -> Result<Vec<Frame>, String> {
    if b.len() < 24 {
        return Err("pcap too short".into());
    }
    let magic = &b[0..4];
    let (le, nano) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err("unsupported pcap magic".into()),
    };
    let u16 = |o: usize| -> u16 {
        if le {
            u16::from_le_bytes([b[o], b[o + 1]])
        } else {
            u16::from_be_bytes([b[o], b[o + 1]])
        }
    };
    let u32 = |o: usize| -> u32 {
        if le {
            u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
        } else {
            u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
        }
    };
    if u16(4) != 2 {
        return Err("unsupported pcap major version".into());
    }
    let linktype = u32(20);
    if linktype != 1 {
        return Err(format!("unsupported linktype {linktype} (only Ethernet=1)"));
    }
    let mut off = 24usize;
    let mut frames = Vec::new();
    while off + 16 <= b.len() {
        let ts_sec = u32(off) as u64;
        let ts_frac = u32(off + 4) as u64;
        let incl = u32(off + 8) as usize;
        off += 16;
        if off + incl > b.len() {
            return Err("truncated pcap record".into());
        }
        let ts_ns = if nano {
            ts_sec * 1_000_000_000 + ts_frac
        } else {
            ts_sec * 1_000_000_000 + ts_frac * 1_000
        };
        frames.push(Frame {
            index: frames.len() as u64,
            ts_ns,
            data: b[off..off + incl].to_vec(),
        });
        off += incl;
    }
    Ok(frames)
}

/// Write a simplified little-endian microsecond pcap (used by tests and export).
pub fn write_pcap(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for f in frames {
        out.extend_from_slice(&(f.ts_ns / 1_000_000_000).to_le_bytes());
        out.extend_from_slice(&((f.ts_ns % 1_000_000_000) / 1_000).to_le_bytes());
        out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&f.data);
    }
    out
}

/// Auto-detect input format: JSON fixture or pcap.
pub fn parse_capture(bytes: &[u8]) -> Result<Vec<Frame>, String> {
    let head: String = bytes
        .iter()
        .take(64)
        .map(|&c| c as char)
        .collect::<String>()
        .trim_start()
        .chars()
        .take(1)
        .collect();
    if head.starts_with('{') {
        let text = std::str::from_utf8(bytes).map_err(|_| "fixture is not valid UTF-8".to_string())?;
        parse_fixture(text)
    } else {
        parse_pcap(bytes)
    }
}
