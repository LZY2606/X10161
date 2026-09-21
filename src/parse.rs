//! 逐帧解析：链路层 → IPv4/IPv6（含扩展头、分片元数据）→ TCP 元数据。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::{Datagram, L4, ParseNote, TcpSegment, Frame};

#[derive(Debug, Clone)]
pub struct IpFragment {
    pub version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub ident: u32,
    pub frag_offset: usize,
    pub mf: bool,
    pub l4_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum ParsedFrame {
    Single(Datagram),
    Fragment(IpFragment),
}

fn note(frame_no: u64, stage: &str, level: &str, message: impl Into<String>) -> ParseNote {
    ParseNote { frame_no, stage: stage.to_string(), level: level.to_string(), message: message.into() }
}

fn parse_tcp(data: &[u8]) -> Result<TcpSegment, String> {
    if data.len() < 20 {
        return Err(format!("tcp: 载荷 {} 字节短于最小头 20", data.len()));
    }
    let sport = u16::from_be_bytes([data[0], data[1]]);
    let dport = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset_words = (data[12] >> 4) as usize;
    if data_offset_words < 5 || data_offset_words * 4 > data.len() {
        return Err(format!("tcp: 非法 data offset {}", data_offset_words));
    }
    let flags = data[13] & 0x3f;
    let payload = data[data_offset_words * 4..].to_vec();
    Ok(TcpSegment { sport, dport, seq, ack, flags, payload, data_offset_words })
}

fn parse_ipv4(packet: &[u8]) -> Result<(IpAddr, IpAddr, u8, usize, bool, u32, Vec<u8>), String> {
    if packet.len() < 20 {
        return Err("ipv4: 短于 20 字节".into());
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return Err(format!("ipv4: IP 版本为 {}", version));
    }
    let ihl = (packet[0] & 0x0f) as usize;
    if ihl < 5 {
        return Err("ipv4: IHL 非法".into());
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len > packet.len() || total_len < ihl * 4 {
        return Err(format!("ipv4: total length {} 超出帧边界", total_len));
    }
    let ident = u16::from_be_bytes([packet[4], packet[5]]) as u32;
    let flags_frag = u16::from_be_bytes([packet[6], packet[7]]);
    let mf = flags_frag & 0x2000 != 0;
    let frag_offset = ((flags_frag & 0x1fff) * 8) as usize;
    let proto = packet[9];
    let src = IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
    let body = packet[ihl * 4..total_len].to_vec();
    Ok((src, dst, proto, frag_offset, mf, ident, body))
}

/// 解析 IPv6，跳过已知扩展头；遇到片段头返回分片信息。
fn parse_ipv6(packet: &[u8]) -> Result<(IpAddr, IpAddr, u8, usize, bool, u32, Vec<u8>), String> {
    if packet.len() < 40 {
        return Err("ipv6: 短于 40 字节".into());
    }
    if packet[0] >> 4 != 6 {
        return Err("ipv6: IP 版本不为 6".into());
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let mut next_header = packet[6];
    let src = IpAddr::V6(Ipv6Addr::from({
        let mut a = [0u8; 16];
        a.copy_from_slice(&packet[8..24]);
        a
    }));
    let dst = IpAddr::V6(Ipv6Addr::from({
        let mut a = [0u8; 16];
        a.copy_from_slice(&packet[24..40]);
        a
    }));
    let end = (40 + payload_len).min(packet.len());
    let mut cursor = 40usize;

    // 0 hop-by-hop, 43 routing, 60 dest opts：逐头跳过；44 fragment 特殊处理；51 AH。
    loop {
        match next_header {
            0 | 43 | 60 => {
                if cursor + 2 > end {
                    return Err("ipv6: 扩展头不完整".into());
                }
                let hdr_len = (packet[cursor + 1] as usize + 1) * 8;
                if cursor + hdr_len > end {
                    return Err("ipv6: 扩展头越界".into());
                }
                next_header = packet[cursor];
                cursor += hdr_len;
            }
            51 => {
                if cursor + 4 > end {
                    return Err("ipv6: AH 头不完整".into());
                }
                let payload_len_words = (packet[cursor + 1] as usize + 2) * 4;
                if cursor + payload_len_words > end {
                    return Err("ipv6: AH 头越界".into());
                }
                next_header = packet[cursor];
                cursor += payload_len_words;
            }
            44 => {
                if cursor + 8 > end {
                    return Err("ipv6: 片段头不完整".into());
                }
                let frag_next = packet[cursor];
                let off_flags = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
                let mf = off_flags & 0x0001 != 0;
                let frag_offset = ((off_flags & 0xfff8) as usize) * 8;
                let ident = u32::from_be_bytes([packet[cursor + 4], packet[cursor + 5], packet[cursor + 6], packet[cursor + 7]]);
                let body = packet[cursor + 8..end].to_vec();
                return Ok((src, dst, frag_next, frag_offset, mf, ident, body));
            }
            _ => {
                let body = packet[cursor..end].to_vec();
                return Ok((src, dst, next_header, 0, false, 0, body));
            }
        }
    }
}

fn parse_ip_packet(packet: &[u8]) -> Result<(u8, IpAddr, IpAddr, u8, usize, bool, u32, Vec<u8>), String> {
    if packet.is_empty() {
        return Err("ip: 空包".into());
    }
    match packet[0] >> 4 {
        4 => {
            let (s, d, p, off, mf, id, body) = parse_ipv4(packet)?;
            Ok((4, s, d, p, off, mf, id, body))
        }
        6 => {
            let (s, d, p, off, mf, id, body) = parse_ipv6(packet)?;
            Ok((6, s, d, p, off, mf, id, body))
        }
        v => Err(format!("ip: 不支持的版本 {}", v)),
    }
}

/// 剥链路层并尝试解析 IP。
pub fn parse_frame(frame: &Frame, linktype: u32, notes: &mut Vec<ParseNote>) -> Option<ParsedFrame> {
    let raw = &frame.bytes;
    let packet = match linktype {
        1 => {
            // Ethernet，支持单层/双层 802.1Q。
            let mut p = raw.as_slice();
            loop {
                if p.len() < 14 {
                    notes.push(note(frame.frame_no, "ethernet", "warn", "短于 14 字节"));
                    return None;
                }
                let ethertype = u16::from_be_bytes([p[12], p[13]]);
                match ethertype {
                    0x8100 | 0x88a8 => {
                        p = &p[18..];
                        continue;
                    }
                    0x0800 | 0x86dd => &p[14..],
                    other => {
                        notes.push(note(frame.frame_no, "ethernet", "info", format!("ethertype 0x{:04x} 非 IP，跳过", other)));
                        return None;
                    }
                }
            }
        }
        0 | 12 => {
            // BSD loopback：4 字节地址族，2 = AF_INET，28/30 = AF_INET6。
            if raw.len() < 4 {
                notes.push(note(frame.frame_no, "loopback", "warn", "loopback 头不完整"));
                return None;
            }
            let family = u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
            if family != 2 && family != 28 && family != 30 {
                notes.push(note(frame.frame_no, "loopback", "info", format!("地址族 {} 非 IP，跳过", family)));
                return None;
            }
            &raw[4..]
        }
        101 | 228 => raw, // RAW / LINKTYPE_IPV4（IPv6 也按首字节版本分派）
        other => {
            notes.push(note(frame.frame_no, "linktype", "warn", format!("不支持的 linktype {}", other)));
            return None;
        }
    };

    let parsed = match parse_ip_packet(packet) {
        Ok(v) => v,
        Err(e) => {
            notes.push(note(frame.frame_no, "ip", "error", e));
            return None;
        }
    };
    let (version, src, dst, proto, frag_offset, mf, ident, body) = parsed;

    if mf || frag_offset > 0 {
        return Some(ParsedFrame::Fragment(IpFragment {
            version,
            src,
            dst,
            proto,
            ident,
            frag_offset,
            mf,
            l4_bytes: body,
        }));
    }

    let l4 = match proto {
        6 => match parse_tcp(&body) {
            Ok(seg) => L4::Tcp(seg),
            Err(e) => {
                notes.push(note(frame.frame_no, "tcp", "error", e));
                return None;
            }
        },
        other => {
            notes.push(note(frame.frame_no, "ip", "info", format!("协议号 {} 非 TCP，跳过", other)));
            L4::Other(other)
        }
    };
    Some(ParsedFrame::Single(Datagram {
        first_frame_no: frame.frame_no,
        frame_nos: vec![frame.frame_no],
        ts_ns: frame.ts_ns,
        version,
        src,
        dst,
        proto,
        l4,
        fragmented: false,
    }))
}
