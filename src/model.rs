//! 帧模型与链路层 / IPv4 / IPv6 / TCP 元数据解析。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub const PROTO_TCP: u8 = 6;

/// 输入帧：index 为原始帧序号，时间戳相同的情况下以 index 决定处理顺序。
#[derive(Clone, Debug)]
pub struct Frame {
    pub index: u32,
    pub ts_ns: i64,
    pub data: Vec<u8>,
}

/// IP 分片元数据（IPv4 与 IPv6 分片头共用）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragInfo {
    pub id: u32,
    pub offset_bytes: u32,
    pub more: bool,
}

#[derive(Clone, Debug)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ParsedFrame {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ip_version: u8,
    pub protocol: u8,
    pub frag: Option<FragInfo>,
    /// 传输层字节（分片时仅为本分片携带的部分）。
    pub transport: Vec<u8>,
}

/// 解析以太网帧（含 802.1Q VLAN），非 IPv4/IPv6 返回 None。
pub fn parse_frame(data: &[u8]) -> Option<ParsedFrame> {
    if data.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut off = 14usize;
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        if data.len() < off + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([data[off + 2], data[off + 3]]);
        off += 4;
    }
    match ethertype {
        0x0800 => parse_ipv4(&data[off..]),
        0x86dd => parse_ipv6(&data[off..]),
        _ => None,
    }
}

fn parse_ipv4(b: &[u8]) -> Option<ParsedFrame> {
    if b.len() < 20 || b[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((b[0] & 0x0f) as usize) * 4;
    if ihl < 20 || b.len() < ihl {
        return None;
    }
    let total = u16::from_be_bytes([b[2], b[3]]) as usize;
    if total < ihl || b.len() < total {
        return None;
    }
    let id = u16::from_be_bytes([b[4], b[5]]);
    let fo = u16::from_be_bytes([b[6], b[7]]);
    let more = fo & 0x2000 != 0;
    let offset_bytes = ((fo & 0x1fff) as u32) * 8;
    let frag = if more || offset_bytes > 0 {
        Some(FragInfo {
            id: id as u32,
            offset_bytes,
            more,
        })
    } else {
        None
    };
    Some(ParsedFrame {
        src: IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])),
        dst: IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19])),
        ip_version: 4,
        protocol: b[9],
        frag,
        transport: b[ihl..total].to_vec(),
    })
}

fn parse_ipv6(b: &[u8]) -> Option<ParsedFrame> {
    if b.len() < 40 || b[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([b[4], b[5]]) as usize;
    if b.len() < 40 + payload_len {
        return None;
    }
    let mut nh = b[6];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&b[8..24]);
    dst.copy_from_slice(&b[24..40]);
    let end = 40 + payload_len;
    let mut off = 40usize;
    let mut frag = None;
    loop {
        match nh {
            // Hop-by-Hop / Routing / Destination Options
            0 | 43 | 60 => {
                if off + 2 > end {
                    return None;
                }
                let next = b[off];
                let len = (b[off + 1] as usize + 1) * 8;
                if off + len > end {
                    return None;
                }
                nh = next;
                off += len;
            }
            // Fragment header
            44 => {
                if off + 8 > end {
                    return None;
                }
                let next = b[off];
                let fo = u16::from_be_bytes([b[off + 2], b[off + 3]]);
                frag = Some(FragInfo {
                    id: u32::from_be_bytes([b[off + 4], b[off + 5], b[off + 6], b[off + 7]]),
                    offset_bytes: ((fo >> 3) as u32) * 8,
                    more: fo & 1 != 0,
                });
                nh = next;
                off += 8;
                break;
            }
            _ => break,
        }
    }
    Some(ParsedFrame {
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        ip_version: 6,
        protocol: nh,
        frag,
        transport: b[off..end].to_vec(),
    })
}

pub fn parse_tcp(b: &[u8]) -> Option<TcpSegment> {
    if b.len() < 20 {
        return None;
    }
    let data_offset = ((b[12] >> 4) as usize) * 4;
    if data_offset < 20 || b.len() < data_offset {
        return None;
    }
    Some(TcpSegment {
        src_port: u16::from_be_bytes([b[0], b[1]]),
        dst_port: u16::from_be_bytes([b[2], b[3]]),
        seq: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        ack: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        flags: b[13],
        window: u16::from_be_bytes([b[14], b[15]]),
        payload: b[data_offset..].to_vec(),
    })
}

/// 32 位环绕序号比较：a 是否位于 b 之前（序列号空间差小于 2^31）。
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub fn flags_str(flags: u8) -> String {
    let mut s = String::new();
    if flags & TCP_SYN != 0 {
        s.push('S');
    }
    if flags & TCP_FIN != 0 {
        s.push('F');
    }
    if flags & TCP_RST != 0 {
        s.push('R');
    }
    if flags & TCP_PSH != 0 {
        s.push('P');
    }
    if flags & TCP_ACK != 0 {
        s.push('A');
    }
    if s.is_empty() {
        s.push('.');
    }
    s
}
