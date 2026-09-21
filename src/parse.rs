//! 链路层（Ethernet / 裸 IP）、IPv4、IPv6（含分片扩展头）与 TCP 解析。

use crate::model::{v4_mapped, Frame, Packet};

#[derive(Clone, Debug)]
pub struct FragPiece {
    pub ip_version: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub ident: u32,
    pub proto: u8,
    pub offset_bytes: u32,
    pub more: bool,
    pub data: Vec<u8>,
    pub frame_index: u32,
    pub ts_ns: u64,
}

#[derive(Debug)]
pub enum L3 {
    Tcp(Packet),
    Frag(FragPiece),
    Ignored,
    Malformed(String),
}

pub fn parse_frame(frame: &Frame) -> L3 {
    let b = &frame.raw;
    if b.is_empty() {
        return L3::Malformed("empty frame".into());
    }
    match b[0] >> 4 {
        4 => parse_ipv4(b, 0, frame),
        6 => parse_ipv6(b, 0, frame),
        _ => {
            if b.len() < 14 {
                return L3::Malformed("frame shorter than ethernet header".into());
            }
            let mut ethertype = u16::from_be_bytes([b[12], b[13]]);
            let mut l3 = 14usize;
            // 802.1Q / QinQ
            while ethertype == 0x8100 || ethertype == 0x88a8 {
                if b.len() < l3 + 4 {
                    return L3::Malformed("truncated vlan tag".into());
                }
                ethertype = u16::from_be_bytes([b[l3 + 2], b[l3 + 3]]);
                l3 += 4;
            }
            match ethertype {
                0x0800 => parse_ipv4(b, l3, frame),
                0x86DD => parse_ipv6(b, l3, frame),
                _ => L3::Ignored,
            }
        }
    }
}

fn parse_ipv4(b: &[u8], off: usize, frame: &Frame) -> L3 {
    if b.len() < off + 20 {
        return L3::Malformed("truncated ipv4 header".into());
    }
    let version = b[off] >> 4;
    let ihl = (b[off] & 0x0f) as usize * 4;
    if version != 4 || ihl < 20 || b.len() < off + ihl {
        return L3::Malformed("bad ipv4 header".into());
    }
    let total_len = u16::from_be_bytes([b[off + 2], b[off + 3]]) as usize;
    let ident = u16::from_be_bytes([b[off + 4], b[off + 5]]) as u32;
    let flags_frag = u16::from_be_bytes([b[off + 6], b[off + 7]]);
    let more = (flags_frag & 0x2000) != 0;
    let frag_offset = ((flags_frag & 0x1fff) as u32) * 8;
    let proto = b[off + 9];
    let mut src4 = [0u8; 4];
    src4.copy_from_slice(&b[off + 12..off + 16]);
    let mut dst4 = [0u8; 4];
    dst4.copy_from_slice(&b[off + 16..off + 20]);
    let src = v4_mapped(src4);
    let dst = v4_mapped(dst4);

    let end = if total_len > 0 {
        (off + total_len).min(b.len())
    } else {
        b.len()
    };
    let payload = &b[off + ihl..end];

    if more || frag_offset > 0 {
        return L3::Frag(FragPiece {
            ip_version: 4,
            src,
            dst,
            ident,
            proto,
            offset_bytes: frag_offset,
            more,
            data: payload.to_vec(),
            frame_index: frame.index,
            ts_ns: frame.ts_ns,
        });
    }
    if proto != 6 {
        return L3::Ignored;
    }
    parse_tcp(payload, 4, src, dst, frame)
}

fn parse_ipv6(b: &[u8], off: usize, frame: &Frame) -> L3 {
    if b.len() < off + 40 {
        return L3::Malformed("truncated ipv6 header".into());
    }
    if b[off] >> 4 != 6 {
        return L3::Malformed("bad ipv6 version".into());
    }
    let payload_len = u16::from_be_bytes([b[off + 4], b[off + 5]]) as usize;
    let next = b[off + 6];
    let mut src = [0u8; 16];
    src.copy_from_slice(&b[off + 8..off + 24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&b[off + 24..off + 40]);
    let cur = off + 40;
    let end = (off + 40 + payload_len).min(b.len());

    // 仅深入处理分片扩展头（44）；其余扩展头不展开。
    if next == 44 {
        if end < cur + 8 {
            return L3::Malformed("truncated fragment header".into());
        }
        let inner_proto = b[cur];
        let off_flags = u16::from_be_bytes([b[cur + 2], b[cur + 3]]);
        let frag_offset = ((off_flags >> 3) as u32) * 8;
        let more = (off_flags & 1) != 0;
        let ident = u32::from_be_bytes([b[cur + 4], b[cur + 5], b[cur + 6], b[cur + 7]]);
        let data = &b[cur + 8..end];
        return L3::Frag(FragPiece {
            ip_version: 6,
            src,
            dst,
            ident,
            proto: inner_proto,
            offset_bytes: frag_offset,
            more,
            data: data.to_vec(),
            frame_index: frame.index,
            ts_ns: frame.ts_ns,
        });
    }
    if next != 6 {
        return L3::Ignored;
    }
    parse_tcp(&b[cur..end], 6, src, dst, frame)
}

fn parse_tcp(
    data: &[u8],
    ip_version: u8,
    src: [u8; 16],
    dst: [u8; 16],
    frame: &Frame,
) -> L3 {
    if data.len() < 20 {
        return L3::Malformed("truncated tcp header".into());
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_off = ((data[12] >> 4) as usize) * 4;
    if data_off < 20 || data.len() < data_off {
        return L3::Malformed("bad tcp data offset".into());
    }
    let flags = data[13] & 0x3f;
    let window = u16::from_be_bytes([data[14], data[15]]);
    let payload = data[data_off..].to_vec();
    L3::Tcp(Packet {
        frame_index: frame.index,
        ts_ns: frame.ts_ns,
        ip_version,
        src,
        dst,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload,
    })
}

/// 对 IP 分片重组得到的数据报再次解析 TCP。
pub fn parse_reassembled_tcp(
    piece: &FragPiece,
    datagram: &[u8],
) -> L3 {
    if piece.proto != 6 {
        return L3::Ignored;
    }
    let fake = Frame {
        index: piece.frame_index,
        ts_ns: piece.ts_ns,
        raw: Vec::new(),
    };
    parse_tcp(datagram, piece.ip_version, piece.src, piece.dst, &fake)
}
