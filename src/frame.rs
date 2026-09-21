//! Link / IP / TCP parsing.
//!
//! Only TCP datagrams matter to this tool; everything else is reported but
//! ignored for session reconstruction.

use crate::types::{Ip, LinkKind};
use serde::{Deserialize, Serialize};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_IPV6: u8 = 41;
const IPV6_HOPOPTS: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_DSTOPTS: u8 = 60;
const IPV6_MOBILITY: u8 = 135;
const IPV6_HIP: u8 = 139;
const IPV6_SHIM6: u8 = 140;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub data_offset: u8,
    pub payload: Vec<u8>,
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

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
    pub fn ack_flag(&self) -> bool {
        self.flags & TCP_ACK != 0
    }
    /// Total sequence space consumed, including SYN/FIN controls.
    pub fn seq_len(&self) -> u32 {
        (self.payload.len() as u32)
            + if self.syn() { 1 } else { 0 }
            + if self.fin() { 1 } else { 0 }
    }
}

/// Information extracted from a fully reassembled IP datagram.
#[derive(Clone, Debug)]
pub struct IpInfo {
    pub src: Ip,
    pub dst: Ip,
    pub protocol: u8,
    /// IP-level identification (v4) / IPv6 fragment id (0 when not fragmented).
    pub frag_id: u32,
    /// 8-bit fragment key per datagram (v6 uses 1 byte; v4 uses 16-bit id).
    pub payload: Vec<u8>,
}

/// A frame either carries a complete IP datagram or one IP fragment.
#[derive(Clone, Debug)]
pub enum IpFrame {
    Complete(IpInfo),
    Fragment {
        src: Ip,
        dst: Ip,
        protocol: u8,
        frag_id: u32,
        offset: usize,
        more: bool,
        data: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
pub enum ParsedKind {
    Ip(IpFrame),
    NonTcp(String),
    Ignored(String),
}

#[derive(Clone, Debug)]
pub struct ParsedFrame {
    pub kind: ParsedKind,
}

/// Parse a raw link-layer frame according to its declared link kind.
pub fn parse_frame(frame: &[u8], link: LinkKind) -> Result<ParsedFrame, String> {
    let (ethertype, ip_bytes) = match link {
        LinkKind::Ethernet => parse_ethernet(frame)?,
        LinkKind::Ipv4Raw => (0x0800, frame),
        LinkKind::Ipv6Raw => (0x86dd, frame),
        LinkKind::Null => parse_null(frame)?,
        LinkKind::LinuxSll => parse_linux_sll(frame)?,
        LinkKind::Raw => match frame.first().map(|b| b >> 4) {
            Some(6) => (0x86dd, frame),
            _ => (0x0800, frame),
        },
    };
    parse_ip(ethertype, ip_bytes)
}

fn parse_ethernet(frame: &[u8]) -> Result<(u16, &[u8]), String> {
    if frame.len() < 14 {
        return Err("ethernet frame too short".to_string());
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut rest = &frame[14..];
    // 802.1Q / QinQ / 802.1ad.
    while ethertype == 0x8100 || ethertype == 0x88a8 || ethertype == 0x9100 {
        if rest.len() < 4 {
            return Err("truncated VLAN tag".to_string());
        }
        ethertype = u16::from_be_bytes([rest[2], rest[3]]);
        rest = &rest[4..];
    }
    Ok((ethertype, rest))
}

fn parse_null(frame: &[u8]) -> Result<(u16, &[u8]), String> {
    if frame.len() < 4 {
        return Err("null loopback frame too short".to_string());
    }
    // BSD loopback: 4-byte AF_* family in host byte order. Both orders are
    // captured in the wild (OpenBSD writes host order little-endian on amd64).
    let le = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let be = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let family = match (le, be) {
        (2, _) | (_, 2) => 0x0800,
        (30, _) | (_, 30) | (28, _) | (_, 28) => 0x86dd,
        _ => return Err("unsupported null loopback address family".to_string()),
    };
    Ok((family, &frame[4..]))
}

fn parse_linux_sll(frame: &[u8]) -> Result<(u16, &[u8]), String> {
    if frame.len() < 16 {
        return Err("linux cooked frame too short".to_string());
    }
    let protocol = u16::from_be_bytes([frame[14], frame[15]]);
    Ok((protocol, &frame[16..]))
}

fn parse_ip(ethertype: u16, bytes: &[u8]) -> Result<ParsedFrame, String> {
    match ethertype {
        0x0800 => parse_ipv4(bytes),
        0x86dd => parse_ipv6(bytes),
        other => Ok(ParsedFrame {
            kind: ParsedKind::Ignored(format!("non-IP ethertype 0x{other:04x}")),
        }),
    }
}

fn parse_ipv4(bytes: &[u8]) -> Result<ParsedFrame, String> {
    if bytes.len() < 20 {
        return Err("IPv4 header too short".to_string());
    }
    let version = bytes[0] >> 4;
    if version != 4 {
        return Err(format!("IPv4 version field is {version}"));
    }
    let ihl = (bytes[0] & 0x0f) as usize;
    if ihl < 5 {
        return Err("IPv4 IHL too small".to_string());
    }
    let header_len = ihl * 4;
    if bytes.len() < header_len {
        return Err("IPv4 packet shorter than IHL".to_string());
    }
    let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let ident = u16::from_be_bytes([bytes[4], bytes[5]]);
    let flags_frag = u16::from_be_bytes([bytes[6], bytes[7]]);
    let more = flags_frag & 0x2000 != 0;
    let offset = ((flags_frag & 0x1fff) as usize) * 8;
    let protocol = bytes[9];
    let src = Ip::V4([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let dst = Ip::V4([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let packet = if total_len != 0 && total_len <= bytes.len() {
        &bytes[..total_len]
    } else {
        bytes
    };
    let l4 = &packet[header_len..];
    if offset == 0 && !more {
        Ok(ParsedFrame {
            kind: ParsedKind::Ip(IpFrame::Complete(IpInfo {
                src,
                dst,
                protocol,
                frag_id: 0,
                payload: l4.to_vec(),
            })),
        })
    } else {
        Ok(ParsedFrame {
            kind: ParsedKind::Ip(IpFrame::Fragment {
                src,
                dst,
                protocol,
                frag_id: ident as u32,
                offset,
                more,
                data: l4.to_vec(),
            }),
        })
    }
}

struct V6Extension {
    next_header: u8,
    frag: Option<V6Frag>,
    payload: Vec<u8>,
}

struct V6Frag {
    id: u32,
    offset: usize,
    more: bool,
}

fn parse_ipv6(bytes: &[u8]) -> Result<ParsedFrame, String> {
    if bytes.len() < 40 {
        return Err("IPv6 header too short".to_string());
    }
    let version = bytes[0] >> 4;
    if version != 6 {
        return Err(format!("IPv6 version field is {version}"));
    }
    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let mut next_header = bytes[6];
    let src = Ip::V6(bytes[8..24].try_into().unwrap());
    let dst = Ip::V6(bytes[24..40].try_into().unwrap());
    let end = (40 + payload_len).min(bytes.len());
    let mut cursor = 40usize;
    let mut frag: Option<V6Frag> = None;

    while is_v6_extension(next_header) {
        if next_header == IPV6_FRAGMENT {
            if cursor + 8 > end {
                return Err("truncated IPv6 fragment header".to_string());
            }
            let ext = &bytes[cursor..end];
            next_header = ext[0];
            let off_flags = u16::from_be_bytes([ext[2], ext[3]]);
            let offset = ((off_flags & 0xfff8) as usize) * 8;
            let more = off_flags & 0x0001 != 0;
            let id = u32::from_be_bytes([ext[4], ext[5], ext[6], ext[7]]);
            frag = Some(V6Frag { id, offset, more });
            cursor += 8;
            break;
        }
        if cursor + 2 > end {
            return Err("truncated IPv6 extension header".to_string());
        }
        let ext = &bytes[cursor..end];
        let hdr_len = (ext[1] as usize + 1) * 8;
        if hdr_len == 0 || cursor + hdr_len > end {
            return Err("invalid IPv6 extension header length".to_string());
        }
        next_header = ext[0];
        cursor += hdr_len;
    }

    let payload = bytes[cursor..end].to_vec();
    match frag {
        Some(f) => Ok(ParsedFrame {
            kind: ParsedKind::Ip(IpFrame::Fragment {
                src,
                dst,
                protocol: next_header,
                frag_id: f.id,
                offset: f.offset,
                more: f.more,
                data: payload,
            }),
        }),
        None => Ok(ParsedFrame {
            kind: ParsedKind::Ip(IpFrame::Complete(IpInfo {
                src,
                dst,
                protocol: next_header,
                frag_id: 0,
                payload,
            })),
        }),
    }
}

fn is_v6_extension(nh: u8) -> bool {
    matches!(
        nh,
        IPV6_HOPOPTS
            | IPV6_ROUTING
            | IPV6_FRAGMENT
            | IPV6_DSTOPTS
            | IPV6_MOBILITY
            | IPV6_HIP
            | IPV6_SHIM6
            | IPPROTO_IPV6
    )
}

pub fn parse_tcp(data: &[u8]) -> Result<TcpSegment, String> {
    if data.len() < 20 {
        return Err("TCP header too short".to_string());
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = (data[12] >> 4) * 4;
    if (data_offset as usize) < 20 || (data_offset as usize) > data.len() {
        return Err("invalid TCP data offset".to_string());
    }
    let flags = data[13] & 0x3f;
    let window = u16::from_be_bytes([data[14], data[15]]);
    let payload = data[data_offset as usize..].to_vec();
    Ok(TcpSegment {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        data_offset,
        payload,
    })
}
