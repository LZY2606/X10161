//! Ingestion of custom JSON frame fixtures and classic pcap capture files.

use crate::types::{LinkKind, RawFrame};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureFile {
    frames: Vec<RawFrame>,
}

pub fn parse_input(bytes: &[u8]) -> Result<Vec<RawFrame>, String> {
    let trimmed = strip_utf8_bom(bytes);
    // pcap magic: 0xa1b2c3d4 / byte-swapped / nanosecond variants.
    if trimmed.len() >= 4 {
        let magic = u32::from_be_bytes([trimmed[0], trimmed[1], trimmed[2], trimmed[3]]);
        if matches!(
            magic,
            0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1
        ) {
            return parse_pcap(trimmed);
        }
    }
    parse_json(trimmed)
}

fn strip_utf8_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes)
}

fn parse_json(bytes: &[u8]) -> Result<Vec<RawFrame>, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("fixture is not valid UTF-8: {e}"))?;
    // Accept either a bare array or {"frames": [...]}.
    if let Ok(frames) = serde_json::from_str::<Vec<RawFrame>>(text) {
        return Ok(frames);
    }
    let file = serde_json::from_str::<FixtureFile>(text)
        .map_err(|e| format!("invalid fixture JSON: {e}"))?;
    Ok(file.frames)
}

fn linktype_to_kind(linktype: u32) -> Result<LinkKind, String> {
    match linktype {
        1 => Ok(LinkKind::Ethernet),
        0 => Ok(LinkKind::Null),
        12 => Ok(LinkKind::Ipv4Raw),
        101 => Ok(LinkKind::Raw),
        113 => Ok(LinkKind::LinuxSll),
        other => Err(format!("unsupported pcap linktype {other}")),
    }
}

fn parse_pcap(bytes: &[u8]) -> Result<Vec<RawFrame>, String> {
    if bytes.len() < 24 {
        return Err("pcap global header too short".to_string());
    }
    let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (little_endian, nanos) = match magic {
        0xa1b2_c3d4 => (false, false),
        0xd4c3_b2a1 => (true, false),
        0xa1b2_3c4d => (false, true),
        0x4d3c_b2a1 => (true, true),
        _ => return Err("unrecognized pcap magic".to_string()),
    };
    let read_u32 = |b: &[u8]| -> u32 {
        if little_endian {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let network = read_u32(&bytes[20..24]);
    let raw_link = linktype_to_kind(network)?;
    // Raw linktype 101 is IPv6 on OpenBSD and "raw IPv4/IPv6" on Linux; try IPv4
    // first by version nibble at parse time is not possible statically, so the
    // parser selects per packet below.
    let mut cursor = 24usize;
    let mut frames = Vec::new();
    let mut order = 0usize;
    while cursor + 16 <= bytes.len() {
        let ts_sec = read_u32(&bytes[cursor..cursor + 4]);
        let ts_frac = read_u32(&bytes[cursor + 4..cursor + 8]);
        let incl_len = read_u32(&bytes[cursor + 8..cursor + 12]) as usize;
        let _orig_len = read_u32(&bytes[cursor + 12..cursor + 16]);
        cursor += 16;
        if cursor + incl_len > bytes.len() {
            return Err("truncated pcap record".to_string());
        }
        let data = &bytes[cursor..cursor + incl_len];
        cursor += incl_len;
        let timestamp = ts_sec as f64
            + if nanos {
                ts_frac as f64 / 1_000_000_000.0
            } else {
                ts_frac as f64 / 1_000_000.0
            };
        let link = if raw_link == LinkKind::Raw {
            match data.first().map(|b| b >> 4) {
                Some(6) => LinkKind::Ipv6Raw,
                _ => LinkKind::Ipv4Raw,
            }
        } else {
            raw_link
        };
        frames.push(RawFrame {
            index: Some(order),
            timestamp,
            link,
            bytes_hex: crate::hash::hex(data),
            comment: None,
        });
        order += 1;
    }
    Ok(frames)
}


/// Emit a classic big-endian microsecond pcap for the given frames.
pub fn write_pcap(frames: &[RawFrame]) -> Vec<u8> {
    let linktype: u32 = match frames.first().map(|f| f.link).unwrap_or(LinkKind::Ethernet) {
        LinkKind::Ethernet => 1,
        LinkKind::Null => 0,
        LinkKind::LinuxSll => 113,
        LinkKind::Ipv4Raw | LinkKind::Ipv6Raw => 12,
        LinkKind::Raw => 101,
    };
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_be_bytes());
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&65535u32.to_be_bytes());
    out.extend_from_slice(&linktype.to_be_bytes());
    for f in frames {
        let data = crate::types::decode_hex(&f.bytes_hex).unwrap_or_default();
        let secs = f.timestamp.floor() as u32;
        let micros = ((f.timestamp - f.timestamp.floor()) * 1_000_000.0) as u32;
        out.extend_from_slice(&secs.to_be_bytes());
        out.extend_from_slice(&micros.to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&data);
    }
    out
}
