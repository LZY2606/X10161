//! Capture ingestion: simplified classic pcap + deterministic JSON fixture,
//! plus link-layer / IPv4 / IPv6 / TCP metadata decoding.

use crate::frame::{Frame, LinkType};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

pub fn tcp_flags_str(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & TCP_SYN != 0 { parts.push("SYN"); }
    if flags & TCP_ACK != 0 { parts.push("ACK"); }
    if flags & TCP_FIN != 0 { parts.push("FIN"); }
    if flags & TCP_RST != 0 { parts.push("RST"); }
    if flags & TCP_PSH != 0 { parts.push("PSH"); }
    if flags & TCP_URG != 0 { parts.push("URG"); }
    if parts.is_empty() { "NONE".to_string() } else { parts.join(",") }
}

/// A parsed capture: frames in original order.
pub struct Capture {
    pub name: String,
    pub linktype: LinkType,
    pub frames: Vec<Frame>,
}

impl Capture {
    /// Processing order: ascending (ts_ns, original frame index).
    pub fn processing_order(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.frames.len()).collect();
        idx.sort_by_key(|&i| (self.frames[i].ts_ns, self.frames[i].index));
        idx
    }
}

// ---------------------------------------------------------------------------
// Fixture format (deterministic JSON)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct FixtureFile {
    pub format: String,
    #[serde(default = "default_linktype")]
    pub linktype: LinkType,
    pub frames: Vec<FixtureFrame>,
}

#[derive(Serialize, Deserialize)]
pub struct FixtureFrame {
    pub ts_ns: i64,
    /// hex-encoded raw frame bytes (including link layer)
    pub data: String,
}

fn default_linktype() -> LinkType {
    LinkType::Ethernet
}

pub const FIXTURE_FORMAT: &str = "reasm-fixture/1";

pub fn fixture_to_json(linktype: LinkType, frames: &[(i64, Vec<u8>)]) -> String {
    let f = FixtureFile {
        format: FIXTURE_FORMAT.to_string(),
        linktype,
        frames: frames
            .iter()
            .map(|(ts, data)| FixtureFrame { ts_ns: *ts, data: hex::encode(data) })
            .collect(),
    };
    serde_json::to_string_pretty(&f).expect("fixture serialize")
}

pub fn capture_to_fixture_json(cap: &Capture) -> String {
    let frames: Vec<(i64, Vec<u8>)> = cap
        .frames
        .iter()
        .map(|f| (f.ts_ns, f.raw.clone()))
        .collect();
    fixture_to_json(cap.linktype, &frames)
}

fn parse_fixture(name: &str, bytes: &[u8]) -> Result<Capture, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not a pcap and not UTF-8 JSON fixture".to_string())?;
    let file: FixtureFile = serde_json::from_str(text).map_err(|e| format!("fixture JSON parse: {e}"))?;
    if file.format != FIXTURE_FORMAT {
        return Err(format!("unsupported fixture format {:?}", file.format));
    }
    let mut frames = Vec::with_capacity(file.frames.len());
    for (i, ff) in file.frames.iter().enumerate() {
        let raw = hex::decode(&ff.data).map_err(|e| format!("frame {i}: bad hex: {e}"))?;
        frames.push(Frame::new(i as u64, ff.ts_ns, raw));
    }
    Ok(Capture { name: name.to_string(), linktype: file.linktype, frames })
}

// ---------------------------------------------------------------------------
// Simplified classic pcap
// ---------------------------------------------------------------------------

fn parse_pcap(name: &str, bytes: &[u8]) -> Result<Capture, String> {
    if bytes.len() < 24 {
        return Err("pcap: truncated global header".into());
    }
    let (little, nano) = match &bytes[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err("pcap: bad magic".into()),
    };
    let u16_at = |off: usize| -> u16 {
        let b = &bytes[off..off + 2];
        if little { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) }
    };
    let u32_at = |off: usize| -> u32 {
        let b = &bytes[off..off + 4];
        if little { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) } else { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) }
    };
    let _version = (u16_at(4), u16_at(6));
    let network = u32_at(20);
    let linktype = match network {
        1 => LinkType::Ethernet,
        113 => LinkType::LinuxSll,
        101 => LinkType::Raw,
        other => return Err(format!("pcap: unsupported linktype {other}")),
    };
    let mut frames = Vec::new();
    let mut off = 24usize;
    let mut index = 0u64;
    while off + 16 <= bytes.len() {
        let ts_sec = u32_at(off) as i64;
        let ts_frac = u32_at(off + 4) as i64;
        let incl_len = u32_at(off + 8) as usize;
        off += 16;
        if off + incl_len > bytes.len() {
            return Err(format!("pcap: truncated record at frame {index}"));
        }
        let ts_ns = ts_sec * 1_000_000_000 + if nano { ts_frac } else { ts_frac * 1000 };
        frames.push(Frame::new(index, ts_ns, bytes[off..off + incl_len].to_vec()));
        off += incl_len;
        index += 1;
    }
    Ok(Capture { name: name.to_string(), linktype, frames })
}

/// Auto-detect input: classic pcap magic, otherwise JSON fixture.
pub fn parse_capture(name: &str, bytes: &[u8]) -> Result<Capture, String> {
    if bytes.len() >= 4 {
        match &bytes[..4] {
            [0xd4, 0xc3, 0xb2, 0xa1] | [0xa1, 0xb2, 0xc3, 0xd4] | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d] => return parse_pcap(name, bytes),
            _ => {}
        }
    }
    parse_fixture(name, bytes)
}

// ---------------------------------------------------------------------------
// Packet decoding
// ---------------------------------------------------------------------------

/// Returns (ip_version, ip_packet_bytes).
pub fn link_payload(linktype: LinkType, frame: &[u8]) -> Result<(u8, &[u8]), String> {
    match linktype {
        LinkType::Ethernet => {
            if frame.len() < 14 {
                return Err("ethernet: short frame".into());
            }
            let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            let mut off = 14usize;
            // skip up to two VLAN tags
            for _ in 0..2 {
                if ethertype == 0x8100 || ethertype == 0x88a8 {
                    if frame.len() < off + 4 {
                        return Err("ethernet: short vlan".into());
                    }
                    ethertype = u16::from_be_bytes([frame[off + 2], frame[off + 3]]);
                    off += 4;
                } else {
                    break;
                }
            }
            match ethertype {
                0x0800 => Ok((4, &frame[off..])),
                0x86dd => Ok((6, &frame[off..])),
                other => Err(format!("ethernet: non-IP ethertype 0x{other:04x}")),
            }
        }
        LinkType::LinuxSll => {
            if frame.len() < 16 {
                return Err("sll: short frame".into());
            }
            let proto = u16::from_be_bytes([frame[14], frame[15]]);
            match proto {
                0x0800 => Ok((4, &frame[16..])),
                0x86dd => Ok((6, &frame[16..])),
                other => Err(format!("sll: non-IP protocol 0x{other:04x}")),
            }
        }
        LinkType::Raw => {
            if frame.is_empty() {
                return Err("raw: empty".into());
            }
            match frame[0] >> 4 {
                4 => Ok((4, frame)),
                6 => Ok((6, frame)),
                v => Err(format!("raw: unknown ip version {v}")),
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ipv4Header {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub ident: u16,
    pub frag_offset: u16, // bytes
    pub more_frags: bool,
    pub header_len: usize,
    pub total_len: usize,
}

pub fn parse_ipv4(pkt: &[u8]) -> Result<(Ipv4Header, &[u8]), String> {
    if pkt.len() < 20 {
        return Err("ipv4: short header".into());
    }
    if pkt[0] >> 4 != 4 {
        return Err("ipv4: bad version".into());
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return Err("ipv4: bad ihl".into());
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < ihl || total_len > pkt.len() {
        return Err("ipv4: bad total length".into());
    }
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    let more_frags = flags_frag & 0x2000 != 0;
    let frag_offset = (flags_frag & 0x1fff) * 8;
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let hdr = Ipv4Header {
        src,
        dst,
        proto: pkt[9],
        ident: u16::from_be_bytes([pkt[4], pkt[5]]),
        frag_offset,
        more_frags,
        header_len: ihl,
        total_len,
    };
    Ok((hdr, &pkt[ihl..total_len]))
}

#[derive(Clone, Debug)]
pub struct Ipv6Header {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_header: u8,
    pub payload_len: usize,
}

pub fn parse_ipv6(pkt: &[u8]) -> Result<(Ipv6Header, &[u8]), String> {
    if pkt.len() < 40 {
        return Err("ipv6: short header".into());
    }
    if pkt[0] >> 4 != 6 {
        return Err("ipv6: bad version".into());
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if 40 + payload_len > pkt.len() {
        return Err("ipv6: truncated payload".into());
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap());
    let hdr = Ipv6Header { src, dst, next_header: pkt[6], payload_len };
    Ok((hdr, &pkt[40..40 + payload_len]))
}

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_IPV6_FRAGMENT: u8 = 44;

/// Parsed IPv6 fragment header view.
pub struct Ipv6Fragment {
    pub next_header: u8,
    pub offset_bytes: u16,
    pub more: bool,
    pub ident: u32,
    pub header_len: usize, // always 8
}

pub fn parse_ipv6_fragment(payload: &[u8]) -> Result<Ipv6Fragment, String> {
    if payload.len() < 8 {
        return Err("ipv6-frag: short".into());
    }
    let off_m = u16::from_be_bytes([payload[2], payload[3]]);
    Ok(Ipv6Fragment {
        next_header: payload[0],
        offset_bytes: ((off_m >> 3) & 0x1fff) * 8,
        more: off_m & 1 != 0,
        ident: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        header_len: 8,
    })
}

/// Length of a generic IPv6 extension header (hop-by-hop / routing / dest-opts).
pub fn ipv6_ext_len(payload: &[u8]) -> Result<usize, String> {
    if payload.len() < 2 {
        return Err("ipv6-ext: short".into());
    }
    Ok((payload[1] as usize + 1) * 8)
}

#[derive(Clone, Debug)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub header_len: usize,
}

pub fn parse_tcp(pkt: &[u8]) -> Result<(TcpHeader, &[u8]), String> {
    if pkt.len() < 20 {
        return Err("tcp: short header".into());
    }
    let data_offset = (pkt[12] >> 4) as usize * 4;
    if data_offset < 20 || data_offset > pkt.len() {
        return Err("tcp: bad data offset".into());
    }
    let hdr = TcpHeader {
        src_port: u16::from_be_bytes([pkt[0], pkt[1]]),
        dst_port: u16::from_be_bytes([pkt[2], pkt[3]]),
        seq: u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]),
        ack: u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]),
        flags: pkt[13],
        window: u16::from_be_bytes([pkt[14], pkt[15]]),
        header_len: data_offset,
    };
    Ok((hdr, &pkt[data_offset..]))
}
