use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

#[derive(Debug, Clone)]
pub struct RawFrame {
    pub index: u64,
    pub ts_micros: i64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum NetPacket {
    Ipv4(Ipv4Packet),
    Ipv6(Ipv6Packet),
    Other { ethertype: u16 },
    Malformed { reason: String },
}

#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ident: u16,
    pub frag_offset_bytes: u16,
    pub more_fragments: bool,
    pub dont_fragment: bool,
    pub ttl: u8,
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.frag_offset_bytes > 0
    }
}

#[derive(Debug, Clone)]
pub struct Ipv6Packet {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_header: u8,
    pub payload: Vec<u8>,
    /// Set when an IPv6 fragment header was encountered; reassembly of IPv6
    /// fragments is intentionally not attempted, the datagram is isolated.
    pub fragmented: bool,
}

#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: Vec<u8>,
}

pub fn flags_to_string(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & TCP_SYN != 0 {
        parts.push("SYN");
    }
    if flags & TCP_FIN != 0 {
        parts.push("FIN");
    }
    if flags & TCP_RST != 0 {
        parts.push("RST");
    }
    if flags & TCP_PSH != 0 {
        parts.push("PSH");
    }
    if flags & TCP_ACK != 0 {
        parts.push("ACK");
    }
    if flags & TCP_URG != 0 {
        parts.push("URG");
    }
    if parts.is_empty() {
        "NONE".to_string()
    } else {
        parts.join("+")
    }
}

/// Parse a classic pcap byte stream into raw frames (linktype 1 = Ethernet,
/// linktype 101 = raw IP). Nanosecond magics are converted to microseconds.
pub fn parse_pcap(bytes: &[u8]) -> Result<Vec<RawFrame>, String> {
    if bytes.len() < 24 {
        return Err("pcap: file too short for global header".into());
    }
    let magic = &bytes[0..4];
    let (le, nano) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err("pcap: unknown magic".into()),
    };
    let u16_at = |off: usize| -> u16 {
        let b = [bytes[off], bytes[off + 1]];
        if le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) }
    };
    let u32_at = |off: usize| -> u32 {
        let b = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
    };
    let linktype = u16_at(22);
    if linktype != 1 && linktype != 101 {
        return Err(format!("pcap: unsupported linktype {}", linktype));
    }
    let mut frames = Vec::new();
    let mut off = 24usize;
    let mut index: u64 = 0;
    while off + 16 <= bytes.len() {
        let ts_sec = u32_at(off) as i64;
        let ts_frac = u32_at(off + 4) as i64;
        let incl_len = u32_at(off + 8) as usize;
        off += 16;
        if off + incl_len > bytes.len() {
            return Err(format!("pcap: truncated frame {}", index));
        }
        let mut data = bytes[off..off + incl_len].to_vec();
        off += incl_len;
        let ts_micros = if nano {
            ts_sec * 1_000_000 + ts_frac / 1_000
        } else {
            ts_sec * 1_000_000 + ts_frac
        };
        if linktype == 101 {
            // Wrap raw IP in a fake zeroed ethernet header is wrong; instead
            // tag by prepending nothing and letting the caller detect IP
            // version from the first nibble.
            data = wrap_raw_ip(data);
        }
        frames.push(RawFrame { index, ts_micros, data });
        index += 1;
    }
    Ok(frames)
}

pub const RAW_IP_ETHERTYPE_MARKER: u16 = 0xffff;

fn wrap_raw_ip(ip: Vec<u8>) -> Vec<u8> {
    let version = ip.first().map(|b| b >> 4).unwrap_or(0);
    let ethertype: u16 = match version {
        4 => 0x0800,
        6 => 0x86dd,
        _ => RAW_IP_ETHERTYPE_MARKER,
    };
    let mut out = Vec::with_capacity(14 + ip.len());
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(&ip);
    out
}

/// Parse one link-layer frame into a network packet.
pub fn parse_link(frame: &RawFrame) -> NetPacket {
    let data = &frame.data;
    if data.len() < 14 {
        return NetPacket::Malformed { reason: "frame shorter than ethernet header".into() };
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut off = 14usize;
    // Skip up to two VLAN tags (802.1Q / 802.1ad).
    for _ in 0..2 {
        if ethertype == 0x8100 || ethertype == 0x88a8 {
            if data.len() < off + 4 {
                return NetPacket::Malformed { reason: "truncated VLAN tag".into() };
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
        other => NetPacket::Other { ethertype: other },
    }
}

fn parse_ipv4(data: &[u8]) -> NetPacket {
    if data.len() < 20 {
        return NetPacket::Malformed { reason: "ipv4: header too short".into() };
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return NetPacket::Malformed { reason: "ipv4: bad IHL".into() };
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_len < ihl || data.len() < total_len {
        return NetPacket::Malformed { reason: "ipv4: bad total length".into() };
    }
    let ident = u16::from_be_bytes([data[4], data[5]]);
    let flags_frag = u16::from_be_bytes([data[6], data[7]]);
    let dont_fragment = flags_frag & 0x4000 != 0;
    let more_fragments = flags_frag & 0x2000 != 0;
    let frag_offset_bytes = (flags_frag & 0x1fff) * 8;
    let ttl = data[8];
    let protocol = data[9];
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    NetPacket::Ipv4(Ipv4Packet {
        src,
        dst,
        protocol,
        ident,
        frag_offset_bytes,
        more_fragments,
        dont_fragment,
        ttl,
        payload: data[ihl..total_len].to_vec(),
    })
}

fn parse_ipv6(data: &[u8]) -> NetPacket {
    if data.len() < 40 {
        return NetPacket::Malformed { reason: "ipv6: header too short".into() };
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    if data.len() < 40 + payload_len {
        return NetPacket::Malformed { reason: "ipv6: truncated payload".into() };
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);
    let mut next = data[6];
    let mut off = 40usize;
    let end = 40 + payload_len;
    let mut fragmented = false;
    // Walk extension headers: hop-by-hop(0), routing(43), destination(60),
    // fragment(44), AH(51). Stop at TCP(6) or anything else.
    loop {
        match next {
            0 | 43 | 60 => {
                if off + 2 > end {
                    return NetPacket::Malformed { reason: "ipv6: truncated ext header".into() };
                }
                let hdr_len = (data[off + 1] as usize + 1) * 8;
                next = data[off];
                off += hdr_len;
                if off > end {
                    return NetPacket::Malformed { reason: "ipv6: ext header overrun".into() };
                }
            }
            44 => {
                fragmented = true;
                if off + 8 > end {
                    return NetPacket::Malformed { reason: "ipv6: truncated fragment header".into() };
                }
                next = data[off];
                off += 8;
                break;
            }
            51 => {
                if off + 2 > end {
                    return NetPacket::Malformed { reason: "ipv6: truncated AH header".into() };
                }
                let hdr_len = (data[off + 1] as usize + 2) * 4;
                next = data[off];
                off += hdr_len;
                if off > end {
                    return NetPacket::Malformed { reason: "ipv6: AH overrun".into() };
                }
            }
            _ => break,
        }
    }
    NetPacket::Ipv6(Ipv6Packet {
        src: Ipv6Addr::from(src),
        dst: Ipv6Addr::from(dst),
        next_header: next,
        payload: data[off..end].to_vec(),
        fragmented,
    })
}

pub fn parse_tcp(data: &[u8]) -> Result<TcpSegment, String> {
    if data.len() < 20 {
        return Err("tcp: header too short".into());
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = ((data[12] >> 4) as usize) * 4;
    if data_offset < 20 || data.len() < data_offset {
        return Err("tcp: bad data offset".into());
    }
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    Ok(TcpSegment {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload: data[data_offset..].to_vec(),
    })
}

pub fn ip_addr_of_v4(a: Ipv4Addr) -> IpAddr {
    IpAddr::V4(a)
}

pub fn ip_addr_of_v6(a: Ipv6Addr) -> IpAddr {
    IpAddr::V6(a)
}
