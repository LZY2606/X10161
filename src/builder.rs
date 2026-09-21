//! 确定性线包构造器：把结构化描述编成真实链路层字节，
//! 供夹具加载与测试构造使用（不触碰任何抓包权限/网卡）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::{RawFrame, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};

pub fn mac_for(ip: IpAddr) -> [u8; 6] {
    let mut mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            mac[2..6].copy_from_slice(&o);
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            mac[2..6].copy_from_slice(&o[12..16]);
        }
    }
    mac
}

pub fn ethernet(payload: &[u8], ethertype: u16, src: IpAddr, dst: IpAddr) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&mac_for(dst));
    f.extend_from_slice(&mac_for(src));
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn csum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn tcp_flags_from_str(s: &str) -> Result<u8, String> {
    let s = s.trim();
    if let Ok(v) = s.parse::<u8>() {
        return Ok(v);
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u8::from_str_radix(hex, 16).map_err(|e| format!("tcp flags: {}", e));
    }
    let mut flags = 0u8;
    for c in s.bytes() {
        flags |= match c {
            b'F' => TCP_FIN,
            b'S' => TCP_SYN,
            b'R' => TCP_RST,
            b'P' => TCP_PSH,
            b'A' => TCP_ACK,
            b'.' | b' ' => 0,
            other => return Err(format!("tcp flags: 未知标志 '{}'", other as char)),
        };
    }
    Ok(flags)
}

pub fn tcp_segment(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(0x50); // data offset = 5
    seg.push(flags);
    seg.extend_from_slice(&64240u16.to_be_bytes()); // window
    seg.extend_from_slice(&0u16.to_be_bytes()); // checksum（不校验）
    seg.extend_from_slice(&0u16.to_be_bytes()); // urgent
    seg.extend_from_slice(payload);
    seg
}

pub fn ipv4_datagram(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    ipv4_fragment(src, dst, 0, 0, false, proto, payload)
}

pub fn ipv4_fragment(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    offset_bytes: usize,
    mf: bool,
    proto: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut ip = Vec::with_capacity(total_len);
    let ihl_ver = 0x45;
    ip.push(ihl_ver);
    ip.push(0); // DSCP/ECN
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&id.to_be_bytes());
    let field = ((offset_bytes / 8) as u16) | if mf { 0x2000 } else { 0 };
    ip.extend_from_slice(&field.to_be_bytes());
    ip.push(64); // TTL
    ip.push(proto);
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum 占位
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let c = csum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(payload);
    ip
}

pub fn ipv6_datagram(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut ip = Vec::with_capacity(40 + payload.len());
    ip.push(0x60);
    ip.push(0);
    ip.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    ip.push(next_header);
    ip.push(64);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip.extend_from_slice(payload);
    ip
}

/// 构造 IPv6 分片（片段头 next-header=44）。
pub fn ipv6_fragment(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    id: u32,
    offset_bytes: usize,
    mf: bool,
    next_header: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut frag = Vec::with_capacity(8 + payload.len());
    frag.push(next_header);
    frag.push(0); // 片段头长度（固定 8 字节 => 0）
    let off = ((offset_bytes / 8) as u16) | if mf { 0x0001 } else { 0 };
    frag.extend_from_slice(&off.to_be_bytes());
    frag.extend_from_slice(&id.to_be_bytes());
    frag.extend_from_slice(payload);
    ipv6_datagram(src, dst, 44, &frag)
}

/// 一个完整 TCP 以太网帧。
pub fn tcp_frame(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let seg = tcp_segment(sport, dport, seq, ack, flags, payload);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let ip = ipv4_datagram(s, d, 6, &seg);
            ethernet(&ip, 0x0800, src, dst)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let ip = ipv6_datagram(s, d, 6, &seg);
            ethernet(&ip, 0x86dd, src, dst)
        }
        _ => panic!("tcp_frame: IPv4/IPv6 版本不一致"),
    }
}

pub fn to_raw(bytes: Vec<u8>, ts_ns: i64) -> RawFrame {
    RawFrame { frame_no: 0, ts_ns, bytes }
}
