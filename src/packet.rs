//! Link-layer / IPv4 / IPv6 / TCP metadata parsing (checksums not validated;
//! this tool analyzes offline captures, it does not verify live traffic).

use std::fmt;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_FRAGMENT: u8 = 44;

pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_PSH: u8 = 0x08;
pub const FLAG_ACK: u8 = 0x10;
pub const FLAG_URG: u8 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddr::V4(b) => write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
            IpAddr::V6(b) => {
                let mut groups = [0u16; 8];
                for i in 0..8 {
                    groups[i] = u16::from_be_bytes([b[2 * i], b[2 * i + 1]]);
                }
                write!(f, "{:x}", groups[0])?;
                for g in &groups[1..] {
                    write!(f, ":{:x}", g)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(_) => write!(f, "{}:{}", self.ip, self.port),
            IpAddr::V6(_) => write!(f, "[{}]:{}", self.ip, self.port),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub id: u32,
    pub proto: u8,
}

#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub src: Endpoint,
    pub dst: Endpoint,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum IpPacket {
    Tcp(TcpPacket),
    Fragment {
        key: FragKey,
        offset_bytes: u32,
        more: bool,
        payload: Vec<u8>,
    },
    Other {
        proto: u8,
    },
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Parse one L2 frame. Returns None for non-Ethernet / non-IP content.
pub fn parse_frame(data: &[u8]) -> Result<IpPacket, String> {
    if data.len() < 14 {
        return Err("frame shorter than Ethernet header".into());
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut off = 14usize;
    // Skip up to two VLAN tags.
    for _ in 0..2 {
        if ethertype == 0x8100 || ethertype == 0x88a8 {
            if data.len() < off + 4 {
                return Err("truncated VLAN tag".into());
            }
            ethertype = u16::from_be_bytes([data[off + 2], data[off + 3]]);
            off += 4;
        } else {
            break;
        }
    }
    match ethertype {
        0x0800 => parse_ipv4(&data[off..]),
        0x86dd => parse_ipv6(&data[off..]),
        _ => Ok(IpPacket::Other { proto: 0 }),
    }
}

fn parse_ipv4(pkt: &[u8]) -> Result<IpPacket, String> {
    if pkt.len() < 20 {
        return Err("truncated IPv4 header".into());
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return Err("bad IPv4 IHL".into());
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let total_len = total_len.min(pkt.len());
    if total_len < ihl {
        return Err("bad IPv4 total length".into());
    }
    let id = u16::from_be_bytes([pkt[4], pkt[5]]);
    let flags_off = u16::from_be_bytes([pkt[6], pkt[7]]);
    let more = flags_off & 0x2000 != 0;
    let frag_off = ((flags_off & 0x1fff) as u32) * 8;
    let proto = pkt[9];
    let src = IpAddr::V4([pkt[12], pkt[13], pkt[14], pkt[15]]);
    let dst = IpAddr::V4([pkt[16], pkt[17], pkt[18], pkt[19]]);
    let payload = &pkt[ihl..total_len];
    if more || frag_off > 0 {
        return Ok(IpPacket::Fragment {
            key: FragKey { src, dst, id: id as u32, proto },
            offset_bytes: frag_off,
            more,
            payload: payload.to_vec(),
        });
    }
    if proto == PROTO_TCP {
        return parse_tcp(payload, src, dst).map(IpPacket::Tcp);
    }
    Ok(IpPacket::Other { proto })
}

fn parse_ipv6(pkt: &[u8]) -> Result<IpPacket, String> {
    if pkt.len() < 40 {
        return Err("truncated IPv6 header".into());
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let mut next = pkt[6];
    let mut srcb = [0u8; 16];
    let mut dstb = [0u8; 16];
    srcb.copy_from_slice(&pkt[8..24]);
    dstb.copy_from_slice(&pkt[24..40]);
    let src = IpAddr::V6(srcb);
    let dst = IpAddr::V6(dstb);
    let end = (40 + payload_len).min(pkt.len());
    let mut off = 40usize;
    // Walk extension headers: hop-by-hop(0), routing(43), dest-opts(60), fragment(44).
    loop {
        match next {
            0 | 43 | 60 => {
                if off + 2 > end {
                    return Err("truncated IPv6 extension header".into());
                }
                let hdr_len = (pkt[off + 1] as usize + 1) * 8;
                next = pkt[off];
                off += hdr_len;
                if off > end {
                    return Err("truncated IPv6 extension body".into());
                }
            }
            PROTO_FRAGMENT => {
                if off + 8 > end {
                    return Err("truncated IPv6 fragment header".into());
                }
                let frag_next = pkt[off];
                let field = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
                let offset_bytes = ((field >> 3) as u32 & 0x1fff) * 8;
                let more = field & 1 != 0;
                let id = u32::from_be_bytes([pkt[off + 4], pkt[off + 5], pkt[off + 6], pkt[off + 7]]);
                return Ok(IpPacket::Fragment {
                    key: FragKey { src, dst, id, proto: frag_next },
                    offset_bytes,
                    more,
                    payload: pkt[off + 8..end].to_vec(),
                });
            }
            _ => break,
        }
    }
    if next == PROTO_TCP {
        return parse_tcp(&pkt[off..end], src, dst).map(IpPacket::Tcp);
    }
    Ok(IpPacket::Other { proto: next })
}

fn parse_tcp(seg: &[u8], src_ip: IpAddr, dst_ip: IpAddr) -> Result<TcpPacket, String> {
    if seg.len() < 20 {
        return Err("truncated TCP header".into());
    }
    let sport = u16::from_be_bytes([seg[0], seg[1]]);
    let dport = u16::from_be_bytes([seg[2], seg[3]]);
    let seq = u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]);
    let ack = u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]);
    let data_off = ((seg[12] >> 4) as usize) * 4;
    if data_off < 20 || data_off > seg.len() {
        return Err("bad TCP data offset".into());
    }
    let flags = seg[13];
    let window = u16::from_be_bytes([seg[14], seg[15]]);
    Ok(TcpPacket {
        src: Endpoint { ip: src_ip, port: sport },
        dst: Endpoint { ip: dst_ip, port: dport },
        seq,
        ack,
        flags,
        window,
        payload: seg[data_off..].to_vec(),
    })
}

/// Parse a TCP segment out of a reassembled IP datagram payload.
pub fn parse_tcp_datagram(payload: &[u8], src: IpAddr, dst: IpAddr) -> Result<TcpPacket, String> {
    parse_tcp(payload, src, dst)
}
