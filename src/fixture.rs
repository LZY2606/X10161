//! Frame model plus parsers/emitters for the deterministic text fixture
//! format and classic libpcap (Ethernet linktype).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub index: u32,
    pub ts_micros: i64,
    pub data: Vec<u8>,
}

pub const FIXTURE_MAGIC: &str = "PGSB-FIXTURE v1";

/// Parse either a text fixture or a pcap byte stream, auto-detected.
pub fn parse_frames(bytes: &[u8]) -> Result<Vec<Frame>, String> {
    if is_pcap(bytes) {
        parse_pcap(bytes)
    } else {
        let text = std::str::from_utf8(bytes).map_err(|_| "input is neither pcap nor UTF-8 text fixture".to_string())?;
        parse_text_fixture(text)
    }
}

fn is_pcap(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    matches!(
        &bytes[0..4],
        [0xd4, 0xc3, 0xb2, 0xa1] | [0xa1, 0xb2, 0xc3, 0xd4] | [0x4d, 0x3c, 0xb2, 0xa1] | [0xa1, 0xb2, 0x3c, 0x4d]
    )
}

pub fn parse_text_fixture(text: &str) -> Result<Vec<Frame>, String> {
    let mut frames = Vec::new();
    let mut saw_magic = false;
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !saw_magic {
            if line == FIXTURE_MAGIC {
                saw_magic = true;
                continue;
            }
            return Err(format!("line {}: expected '{}'", lineno + 1, FIXTURE_MAGIC));
        }
        let mut parts = line.split_whitespace();
        let kw = parts.next().unwrap_or("");
        if kw != "frame" {
            return Err(format!("line {}: expected 'frame'", lineno + 1));
        }
        let index: u32 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("line {}: bad frame index", lineno + 1))?;
        let ts_micros: i64 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("line {}: bad timestamp", lineno + 1))?;
        let hex: String = parts.collect();
        let data = crate::packet::from_hex(&hex)
            .ok_or_else(|| format!("line {}: bad hex payload", lineno + 1))?;
        frames.push(Frame { index, ts_micros, data });
    }
    if !saw_magic {
        return Err(format!("missing '{}' header", FIXTURE_MAGIC));
    }
    Ok(frames)
}

pub fn emit_text_fixture(frames: &[Frame]) -> String {
    let mut out = String::new();
    out.push_str(FIXTURE_MAGIC);
    out.push('\n');
    out.push_str("# frame <index> <ts_micros> <hex L2 frame>\n");
    let mut ordered: Vec<&Frame> = frames.iter().collect();
    ordered.sort_by_key(|f| f.index);
    for f in ordered {
        out.push_str(&format!("frame {} {} {}\n", f.index, f.ts_micros, crate::sha256::to_hex(&f.data)));
    }
    out
}

fn parse_pcap(bytes: &[u8]) -> Result<Vec<Frame>, String> {
    if bytes.len() < 24 {
        return Err("pcap: truncated global header".into());
    }
    let (little, nano) = match &bytes[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err("pcap: bad magic".into()),
    };
    let u32_at = |off: usize| -> Result<u32, String> {
        let b = bytes.get(off..off + 4).ok_or("pcap: truncated")?;
        Ok(if little {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    };
    let network = u32_at(20)?;
    if network != 1 {
        return Err(format!("pcap: unsupported linktype {} (only Ethernet=1)", network));
    }
    let mut frames = Vec::new();
    let mut off = 24usize;
    let mut index: u32 = 0;
    while off + 16 <= bytes.len() {
        let ts_sec = u32_at(off)? as i64;
        let ts_frac = u32_at(off + 4)? as i64;
        let incl = u32_at(off + 8)? as usize;
        off += 16;
        let data = bytes
            .get(off..off + incl)
            .ok_or("pcap: truncated packet data")?
            .to_vec();
        off += incl;
        let ts_micros = if nano {
            ts_sec * 1_000_000 + ts_frac / 1_000
        } else {
            ts_sec * 1_000_000 + ts_frac
        };
        frames.push(Frame { index, ts_micros, data });
        index += 1;
    }
    Ok(frames)
}

/// Stable ordering: timestamp first, original frame index breaks ties.
pub fn ordered_frames(frames: &[Frame]) -> Vec<&Frame> {
    let mut v: Vec<&Frame> = frames.iter().collect();
    v.sort_by_key(|f| (f.ts_micros, f.index));
    v
}
