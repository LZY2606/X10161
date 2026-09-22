use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub const PROTO_TCP: u8 = 6;

#[derive(Clone, Debug)]
pub struct FragRef<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub ident: u32,
    /// Fragment offset in bytes (already multiplied by 8).
    pub offset_bytes: usize,
    pub more_fragments: bool,
    pub payload: &'a [u8],
}

#[derive(Clone, Debug)]
pub enum NetPacket<'a> {
    /// A complete, unfragmented IP datagram payload.
    Direct {
        src: IpAddr,
        dst: IpAddr,
        proto: u8,
        payload: &'a [u8],
    },
    /// One fragment of a fragmented datagram; must go through defragmentation.
    Fragment(FragRef<'a>),
}

#[derive(Clone, Debug)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Parse an Ethernet frame (optionally VLAN tagged) into an IP-level packet view.
pub fn parse_frame(data: &[u8]) -> Option<NetPacket<'_>> {
    if data.len() < 14 {
        return None;
    }
    let mut ethertype = be16(data, 12);
    let mut off = 14usize;
    // Skip up to two VLAN/QinQ tags.
    for _ in 0..2 {
        if ethertype == 0x8100 || ethertype == 0x88a8 || ethertype == 0x9100 {
            if data.len() < off + 4 {
                return None;
            }
            ethertype = be16(data, off + 2);
            off += 4;
        } else {
            break;
        }
    }
    match ethertype {
        0x0800 => parse_ipv4(&data[off..]),
        0x86dd => parse_ipv6(&data[off..]),
        _ => None,
    }
}

fn parse_ipv4(b: &[u8]) -> Option<NetPacket<'_>> {
    if b.len() < 20 || b[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((b[0] & 0x0f) as usize) * 4;
    if ihl < 20 || b.len() < ihl {
        return None;
    }
    let total_len = be16(b, 2) as usize;
    if total_len < ihl || b.len() < total_len {
        return None;
    }
    let ident = be16(b, 4) as u32;
    let flags_frag = be16(b, 6);
    let more_fragments = flags_frag & 0x2000 != 0;
    let offset_bytes = ((flags_frag & 0x1fff) as usize) * 8;
    let proto = b[9];
    let src = IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19]));
    let payload = &b[ihl..total_len];
    if more_fragments || offset_bytes > 0 {
        Some(NetPacket::Fragment(FragRef {
            src,
            dst,
            proto,
            ident,
            offset_bytes,
            more_fragments,
            payload,
        }))
    } else {
        Some(NetPacket::Direct {
            src,
            dst,
            proto,
            payload,
        })
    }
}

fn parse_ipv6(b: &[u8]) -> Option<NetPacket<'_>> {
    if b.len() < 40 || b[0] >> 4 != 6 {
        return None;
    }
    let payload_len = be16(b, 4) as usize;
    if b.len() < 40 + payload_len {
        return None;
    }
    let mut next = b[6];
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).ok()?));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).ok()?));
    let mut off = 40usize;
    let end = 40 + payload_len;
    // Walk extension headers: hop-by-hop (0), routing (43), destination (60), fragment (44).
    loop {
        match next {
            0 | 43 | 60 => {
                if end < off + 2 {
                    return None;
                }
                let hdr_len = (b[off + 1] as usize + 1) * 8;
                if end < off + hdr_len {
                    return None;
                }
                next = b[off];
                off += hdr_len;
            }
            44 => {
                if end < off + 8 {
                    return None;
                }
                let frag_next = b[off];
                let frag_off_flags = be16(b, off + 2);
                let offset_bytes = ((frag_off_flags >> 3) as usize) * 8;
                let more_fragments = frag_off_flags & 1 != 0;
                let ident = be32(b, off + 4);
                return Some(NetPacket::Fragment(FragRef {
                    src,
                    dst,
                    proto: frag_next,
                    ident,
                    offset_bytes,
                    more_fragments,
                    payload: &b[off + 8..end],
                }));
            }
            _ => {
                if end < off {
                    return None;
                }
                return Some(NetPacket::Direct {
                    src,
                    dst,
                    proto: next,
                    payload: &b[off..end],
                });
            }
        }
    }
}

pub fn parse_tcp(b: &[u8]) -> Option<TcpSegment<'_>> {
    if b.len() < 20 {
        return None;
    }
    let data_off = ((b[12] >> 4) as usize) * 4;
    if data_off < 20 || b.len() < data_off {
        return None;
    }
    Some(TcpSegment {
        src_port: be16(b, 0),
        dst_port: be16(b, 2),
        seq: be32(b, 4),
        ack: be32(b, 8),
        flags: b[13],
        payload: &b[data_off..],
    })
}

/// 32-bit wrapping sequence comparison: is a "before" b (mod 2^32)?
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Signed distance from `base` to `seq` in the 32-bit wrapping sequence space.
pub fn seq_offset(seq: u32, base: u32) -> i64 {
    seq.wrapping_sub(base) as i32 as i64
}
