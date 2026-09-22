//! Link-layer, IPv4/IPv6 and TCP metadata parsing.

use crate::fragment::{Frag, FragKey, FragResult, FragmentReassembler};
use crate::model::{Frame, LinkType};

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: Vec<u8>,
    pub frame: u64,
    pub ts: f64,
    /// True when the carrier IP datagram was reassembled from fragments.
    pub ip_fragmented: bool,
}

#[derive(Debug)]
pub enum FrameOutcome {
    Tcp(TcpPacket),
    /// IP fragment buffered, datagram incomplete.
    FragmentPending { desc: String },
    /// Datagram isolated (overlap / budget / timeout). Other sessions unaffected.
    DatagramIsolated { desc: String },
    NonTcp { desc: String },
    Malformed { reason: String },
}

pub fn parse_frame(frame: &Frame, frags: &mut FragmentReassembler) -> FrameOutcome {
    let ip = match frame.link {
        LinkType::Ethernet => match strip_ethernet(&frame.data) {
            Ok(x) => x,
            Err(e) => return FrameOutcome::Malformed { reason: e },
        },
        LinkType::RawIp => frame.data.clone(),
    };
    match ip.first().map(|b| b >> 4) {
        Some(4) => parse_ipv4(&ip, frame, frags),
        Some(6) => parse_ipv6(&ip, frame, frags),
        _ => FrameOutcome::Malformed { reason: "not IPv4/IPv6".to_string() },
    }
}

/// Returns the IP packet (handles one or more 802.1Q VLAN tags).
fn strip_ethernet(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 14 {
        return Err("ethernet: truncated header".to_string());
    }
    let mut off = 12usize;
    loop {
        if off + 2 > data.len() {
            return Err("ethernet: truncated ethertype".to_string());
        }
        let etype = u16::from_be_bytes([data[off], data[off + 1]]);
        match etype {
            0x0800 | 0x86DD => return Ok(data[off + 2..].to_vec()),
            0x8100 | 0x88A8 => off += 4, // VLAN tag
            other => return Err(format!("ethernet: unsupported ethertype 0x{:04x}", other)),
        }
    }
}

fn ipv4_addr(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn ipv6_addr(b: &[u8]) -> String {
    let mut groups = [0u16; 8];
    for i in 0..8 {
        groups[i] = u16::from_be_bytes([b[2 * i], b[2 * i + 1]]);
    }
    // RFC 5952-ish: compress the longest zero run.
    let mut best_start = 8usize;
    let mut best_len = 0usize;
    let mut i = 0;
    while i < 8 {
        if groups[i] == 0 {
            let start = i;
            while i < 8 && groups[i] == 0 {
                i += 1;
            }
            if i - start > best_len {
                best_len = i - start;
                best_start = start;
            }
        } else {
            i += 1;
        }
    }
    let mut s = String::new();
    let mut i = 0;
    while i < 8 {
        if best_len >= 2 && i == best_start {
            s.push_str("::");
            i += best_len;
            continue;
        }
        if !s.is_empty() && !s.ends_with(':') {
            s.push(':');
        }
        s.push_str(&format!("{:x}", groups[i]));
        i += 1;
    }
    if s.is_empty() {
        s = "::".to_string();
    }
    s
}

fn parse_ipv4(ip: &[u8], frame: &Frame, frags: &mut FragmentReassembler) -> FrameOutcome {
    if ip.len() < 20 {
        return FrameOutcome::Malformed { reason: "ipv4: truncated header".to_string() };
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return FrameOutcome::Malformed { reason: "ipv4: bad IHL".to_string() };
    }
    let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if total_len < ihl || ip.len() < total_len {
        return FrameOutcome::Malformed { reason: "ipv4: bad total length".to_string() };
    }
    let ident = u16::from_be_bytes([ip[4], ip[5]]) as u32;
    let flags_frag = u16::from_be_bytes([ip[6], ip[7]]);
    let more = flags_frag & 0x2000 != 0;
    let frag_off = ((flags_frag & 0x1fff) as usize) * 8;
    let protocol = ip[8];
    let src = ipv4_addr(&ip[12..16]);
    let dst = ipv4_addr(&ip[16..20]);
    let payload = &ip[ihl..total_len];

    if more || frag_off > 0 {
        let key = FragKey { src: src.clone(), dst: dst.clone(), ident, protocol };
        let frag = Frag {
            offset: frag_off,
            more,
            data: payload.to_vec(),
            frame: frame.index,
            ts: frame.ts,
        };
        return match frags.add(key, frag) {
            FragResult::Pending => FrameOutcome::FragmentPending {
                desc: format!("ipv4 fragment {} -> {} id={} off={}", src, dst, ident, frag_off),
            },
            FragResult::Isolated(reason) => FrameOutcome::DatagramIsolated {
                desc: format!("ipv4 datagram {} -> {} id={}: {}", src, dst, ident, reason),
            },
            FragResult::Complete(data) => dispatch_transport(&src, &dst, protocol, &data, frame, true),
        };
    }
    dispatch_transport(&src, &dst, protocol, payload, frame, false)
}

fn parse_ipv6(ip: &[u8], frame: &Frame, frags: &mut FragmentReassembler) -> FrameOutcome {
    if ip.len() < 40 {
        return FrameOutcome::Malformed { reason: "ipv6: truncated header".to_string() };
    }
    let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    if ip.len() < 40 + payload_len {
        return FrameOutcome::Malformed { reason: "ipv6: truncated payload".to_string() };
    }
    let mut next = ip[6];
    let src = ipv6_addr(&ip[8..24]);
    let dst = ipv6_addr(&ip[24..40]);
    let mut off = 40usize;
    let end = 40 + payload_len;

    // Walk extension headers.
    loop {
        match next {
            0 | 43 | 60 => {
                // hop-by-hop / routing / destination options
                if off + 2 > end {
                    return FrameOutcome::Malformed { reason: "ipv6: truncated ext header".to_string() };
                }
                let hdr_len = (ip[off + 1] as usize + 1) * 8;
                next = ip[off];
                off += hdr_len;
                if off > end {
                    return FrameOutcome::Malformed { reason: "ipv6: ext header overrun".to_string() };
                }
            }
            44 => {
                // fragment header
                if off + 8 > end {
                    return FrameOutcome::Malformed { reason: "ipv6: truncated fragment header".to_string() };
                }
                let inner_next = ip[off];
                let frag_field = u16::from_be_bytes([ip[off + 2], ip[off + 3]]);
                let frag_off = ((frag_field >> 3) as usize) * 8;
                let more = frag_field & 1 != 0;
                let ident = u32::from_be_bytes([ip[off + 4], ip[off + 5], ip[off + 6], ip[off + 7]]);
                let data = &ip[off + 8..end];
                let key = FragKey { src: src.clone(), dst: dst.clone(), ident, protocol: inner_next };
                let frag = Frag {
                    offset: frag_off,
                    more,
                    data: data.to_vec(),
                    frame: frame.index,
                    ts: frame.ts,
                };
                return match frags.add(key, frag) {
                    FragResult::Pending => FrameOutcome::FragmentPending {
                        desc: format!("ipv6 fragment {} -> {} id={} off={}", src, dst, ident, frag_off),
                    },
                    FragResult::Isolated(reason) => FrameOutcome::DatagramIsolated {
                        desc: format!("ipv6 datagram {} -> {} id={}: {}", src, dst, ident, reason),
                    },
                    FragResult::Complete(data) => {
                        dispatch_transport(&src, &dst, inner_next, &data, frame, true)
                    }
                };
            }
            _ => {
                let payload = &ip[off..end];
                return dispatch_transport(&src, &dst, next, payload, frame, false);
            }
        }
    }
}

fn dispatch_transport(
    src: &str,
    dst: &str,
    protocol: u8,
    payload: &[u8],
    frame: &Frame,
    ip_fragmented: bool,
) -> FrameOutcome {
    if protocol != 6 {
        return FrameOutcome::NonTcp {
            desc: format!("{} -> {} ip-proto={}", src, dst, protocol),
        };
    }
    match parse_tcp(src, dst, payload, frame, ip_fragmented) {
        Ok(p) => FrameOutcome::Tcp(p),
        Err(e) => FrameOutcome::Malformed { reason: e },
    }
}

fn parse_tcp(
    src: &str,
    dst: &str,
    data: &[u8],
    frame: &Frame,
    ip_fragmented: bool,
) -> Result<TcpPacket, String> {
    if data.len() < 20 {
        return Err("tcp: truncated header".to_string());
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_off = ((data[12] >> 4) as usize) * 4;
    if data_off < 20 || data.len() < data_off {
        return Err("tcp: bad data offset".to_string());
    }
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    Ok(TcpPacket {
        src_ip: src.to_string(),
        dst_ip: dst.to_string(),
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload: data[data_off..].to_vec(),
        frame: frame.index,
        ts: frame.ts,
        ip_fragmented,
    })
}
