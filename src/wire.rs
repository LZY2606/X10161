//! Link layer / IPv4 / IPv6 / TCP header parsing.
//!
//! No checksum validation: fixtures may omit checksums, and the workbench is
//! reconstructing conversations from deterministic offline captures.

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TCP_SYN: u8 = 0x02;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_HOPOPTS: u8 = 0;
pub const IP_PROTO_ROUTING: u8 = 43;
pub const IP_PROTO_FRAGMENT: u8 = 44;
pub const IP_PROTO_DSTOPTS: u8 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Port(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Endpoint { ip, port }
    }
}

/// Canonical endpoint ordering: v4 before v6, then bytes, then port.
impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> Ordering {
        match (&self.ip, &other.ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => a
                .octets()
                .cmp(&b.octets())
                .then_with(|| self.port.cmp(&other.port)),
            (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Greater,
            (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Less,
            (IpAddr::V6(a), IpAddr::V6(b)) => a
                .octets()
                .cmp(&b.octets())
                .then_with(|| self.port.cmp(&other.port)),
        }
    }
}

impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip {
            IpAddr::V4(v4) => write!(f, "{v4}:{}", self.port),
            IpAddr::V6(v6) => write!(f, "[{v6}]:{}", self.port),
        }
    }
}

/// A complete (possibly reassembled) IP datagram handed to L4.
#[derive(Debug, Clone)]
pub struct Datagram {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub next_proto: u8,
    pub payload: Vec<u8>,
}

/// IPv4 fragment bookkeeping before L4 reassembly.
#[derive(Debug, Clone)]
pub struct IpFragment {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub id: u32,
    pub protocol: u8,
    pub offset: u16,
    pub more_fragments: bool,
    pub data: Vec<u8>,
    /// Frame index/order on which the fragment arrived.
    pub frame_seq: u64,
}

#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub src: Endpoint,
    pub dst: Endpoint,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: Vec<u8>,
    /// Frame ordering key (timestamp micros, original frame number).
    pub seen_at: (u64, u64),
    pub frame_seq: u64,
    /// Content hash of the original frame.
    pub frame_hash: String,
}

impl TcpSegment {
    pub fn syn(&self) -> bool {
        self.flags & TCP_SYN != 0
    }
    pub fn fin(&self) -> bool {
        self.flags & TCP_FIN != 0
    }
    pub fn rst(&self) -> bool {
        self.flags & TCP_RST != 0
    }
}

/// Result of parsing one link-layer frame.
#[derive(Debug)]
pub enum ParsedFrame {
    Datagram(Datagram),
    Fragment(IpFragment),
    Other(String),
}

fn parse_ipv4(packet: &[u8]) -> Result<ParsedFrame, String> {
    if packet.len() < 20 {
        return Err("ipv4: too short".into());
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return Err("ipv4: bad version".into());
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return Err("ipv4: bad ihl".into());
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl || total_len > packet.len() {
        return Err("ipv4: bad total length".into());
    }
    let id = u16::from_be_bytes([packet[4], packet[5]]) as u32;
    let flags_frag = u16::from_be_bytes([packet[6], packet[7]]);
    let more = flags_frag & 0x2000 != 0;
    let frag_offset = (flags_frag & 0x1fff) * 8;
    let protocol = packet[9];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let l4 = &packet[ihl..total_len];

    if frag_offset != 0 || more {
        Ok(ParsedFrame::Fragment(IpFragment {
            src: IpAddr::V4(src),
            dst: IpAddr::V4(dst),
            id,
            protocol,
            offset: frag_offset,
            more_fragments: more,
            data: l4.to_vec(),
            frame_seq: 0,
        }))
    } else {
        Ok(ParsedFrame::Datagram(Datagram {
            src: IpAddr::V4(src),
            dst: IpAddr::V4(dst),
            next_proto: protocol,
            payload: l4.to_vec(),
        }))
    }
}

/// Walk IPv6 extension headers; returns (next header, l4 payload).
fn parse_ipv6(packet: &[u8]) -> Result<ParsedFrame, String> {
    if packet.len() < 40 {
        return Err("ipv6: too short".into());
    }
    if packet[0] >> 4 != 6 {
        return Err("ipv6: bad version".into());
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let mut next = packet[6];
    let src_bytes: [u8; 16] = packet[8..24].try_into().unwrap();
    let dst_bytes: [u8; 16] = packet[24..40].try_into().unwrap();
    let src = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst = IpAddr::V6(Ipv6Addr::from(dst_bytes));
    let end = (40 + payload_len).min(packet.len());

    let mut cursor = 40;
    let mut frag: Option<(u16, bool, u32)> = None;
    loop {
        match next {
            IP_PROTO_HOPOPTS | IP_PROTO_ROUTING | IP_PROTO_DSTOPTS => {
                if cursor + 2 > end {
                    return Err("ipv6: truncated extension header".into());
                }
                let hdr_len = (packet[cursor + 1] as usize + 1) * 8;
                if hdr_len == 0 || cursor + hdr_len > end {
                    return Err("ipv6: bad extension length".into());
                }
                next = packet[cursor];
                cursor += hdr_len;
            }
            IP_PROTO_FRAGMENT => {
                if cursor + 8 > end {
                    return Err("ipv6: truncated fragment header".into());
                }
                next = packet[cursor];
                let off_flags = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
                let offset = off_flags & 0xfff8;
                let more = off_flags & 0x0001 != 0;
                let ident = u32::from_be_bytes([
                    packet[cursor + 4],
                    packet[cursor + 5],
                    packet[cursor + 6],
                    packet[cursor + 7],
                ]);
                frag = Some((offset, more, ident));
                cursor += 8;
            }
            _ => break,
        }
    }
    if cursor > end {
        return Err("ipv6: header past payload".into());
    }
    let l4 = &packet[cursor..end];

    if let Some((offset, more, ident)) = frag {
        Ok(ParsedFrame::Fragment(IpFragment {
            src,
            dst,
            id: ident,
            protocol: next,
            offset,
            more_fragments: more,
            data: l4.to_vec(),
            frame_seq: 0,
        }))
    } else {
        Ok(ParsedFrame::Datagram(Datagram {
            src,
            dst,
            next_proto: next,
            payload: l4.to_vec(),
        }))
    }
}

pub fn parse_ip(packet: &[u8]) -> Result<ParsedFrame, String> {
    match packet.first() {
        Some(&v) if v >> 4 == 4 => parse_ipv4(packet),
        Some(&v) if v >> 4 == 6 => parse_ipv6(packet),
        Some(&v) => Err(format!("unknown ip version {:#x}", v >> 4)),
        None => Err("empty ip packet".into()),
    }
}

/// Parse an Ethernet frame (or raw IP when `link == "raw"`).
pub fn parse_link(link: &str, frame: &[u8]) -> Result<ParsedFrame, String> {
    match link {
        "raw" => parse_ip(frame),
        "ethernet" | "" => {
            if frame.len() < 14 {
                return Err("ethernet: too short".into());
            }
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            let mut payload = &frame[14..];
            let mut et = ethertype;
            // 802.1Q VLAN tags.
            while matches!(et, 0x8100 | 0x88a8) {
                if payload.len() < 4 {
                    return Err("ethernet: truncated vlan".into());
                }
                et = u16::from_be_bytes([payload[2], payload[3]]);
                payload = &payload[4..];
            }
            match et {
                0x0800 | 0x86dd => parse_ip(payload),
                other => Ok(ParsedFrame::Other(format!("ethertype {other:#06x}"))),
            }
        }
        other => Err(format!("unsupported link type {other}")),
    }
}

pub fn parse_tcp(d: &Datagram) -> Result<TcpSegment, String> {
    let p = &d.payload;
    if p.len() < 20 {
        return Err("tcp: too short".into());
    }
    let src_port = u16::from_be_bytes([p[0], p[1]]);
    let dst_port = u16::from_be_bytes([p[2], p[3]]);
    let seq = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
    let ack = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
    let data_offset = (p[12] >> 4) as usize * 4;
    if data_offset < 20 || data_offset > p.len() {
        return Err("tcp: bad data offset".into());
    }
    let flags = p[13] & 0x3f;
    let window = u16::from_be_bytes([p[14], p[15]]);
    let payload = p[data_offset..].to_vec();
    Ok(TcpSegment {
        src: Endpoint::new(d.src, src_port),
        dst: Endpoint::new(d.dst, dst_port),
        seq,
        ack,
        flags,
        window,
        payload,
        seen_at: (0, 0),
        frame_seq: 0,
        frame_hash: String::new(),
    })
}
