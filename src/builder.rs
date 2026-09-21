//! 确定性帧构造器：生成以太网 + IPv4/IPv6 + TCP 帧，供测试与示例夹具使用。

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct FrameBuilder {
    pub frames: Vec<BuiltFrame>,
    pub v6: bool,
}

#[derive(Debug, Clone)]
pub struct BuiltFrame {
    pub ts_us: i64,
    pub bytes: Vec<u8>,
}

impl FrameBuilder {
    pub fn new() -> Self {
        FrameBuilder {
            frames: Vec::new(),
            v6: false,
        }
    }

    pub fn ipv6() -> Self {
        FrameBuilder {
            frames: Vec::new(),
            v6: true,
        }
    }

    pub fn push(&mut self, ts_us: i64, bytes: Vec<u8>) -> usize {
        self.frames.push(BuiltFrame { ts_us, bytes });
        self.frames.len() - 1
    }

    pub fn tcp(
        &mut self,
        ts_us: i64,
        src: &str,
        sport: u16,
        dst: &str,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> usize {
        let bytes = if self.v6 {
            build_v6_tcp(src, dst, sport, dport, seq, ack, flags, payload)
        } else {
            build_v4_tcp(src, dst, sport, dport, seq, ack, flags, payload)
        };
        self.push(ts_us, bytes)
    }

    /// IPv4 手动分片推送。`payload` 为 TCP 报文段整体（含 TCP 首部）。
    pub fn tcp_v4_fragmented(
        &mut self,
        ts_us: i64,
        src: &str,
        dst: &str,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
        fragment_size: usize,
        identification: u16,
    ) -> Vec<usize> {
        let srcip: Ipv4Addr = src.parse().unwrap();
        let dstip: Ipv4Addr = dst.parse().unwrap();
        let mut segment = tcp_segment(sport, dport, seq, ack, flags, payload);
        tcp_checksum_v4(&mut segment, &srcip, &dstip);
        let total = segment.len();
        let mut indices = Vec::new();
        let mut off = 0usize;
        let mut first = true;
        while off < total {
            let take = fragment_size.min(total - off);
            // 强制 8 字节对齐（最后一片除外）。
            let mut take = take;
            if off + take < total {
                take -= take % 8;
            }
            let chunk = &segment[off..off + take];
            let more = off + take < total;
            let ip = build_ipv4_header(
                &srcip,
                &dstip,
                chunk.len(),
                identification,
                more,
                (off / 8) as u16,
            );
            let mut frame = eth_frame(false);
            frame.extend_from_slice(&ip);
            frame.extend_from_slice(chunk);
            indices.push(self.push(ts_us + if first { 0 } else { 1 }, frame));
            off += take;
            first = false;
        }
        indices
    }

    pub fn into_raw(self) -> Vec<crate::pcap::RawFrame> {
        self.frames
            .into_iter()
            .map(|f| {
                let len = f.bytes.len() as u32;
                crate::pcap::RawFrame {
                    ts_us: f.ts_us,
                    data: f.bytes,
                    orig_len: len,
                }
            })
            .collect()
    }
}

pub const F_FIN: u8 = 0x01;
pub const F_SYN: u8 = 0x02;
pub const F_RST: u8 = 0x04;
pub const F_PSH: u8 = 0x08;
pub const F_ACK: u8 = 0x10;

fn build_v4_tcp(
    src: &str,
    dst: &str,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let srcip: Ipv4Addr = src.parse().unwrap();
    let dstip: Ipv4Addr = dst.parse().unwrap();
    let mut segment = tcp_segment(sport, dport, seq, ack, flags, payload);
    tcp_checksum_v4(&mut segment, &srcip, &dstip);
    let ip = build_ipv4_header(&srcip, &dstip, segment.len(), 0x1234, false, 0);
    let mut out = eth_frame(false);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&segment);
    out
}

fn build_v6_tcp(
    src: &str,
    dst: &str,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let srcip: Ipv6Addr = src.parse().unwrap();
    let dstip: Ipv6Addr = dst.parse().unwrap();
    let mut segment = tcp_segment(sport, dport, seq, ack, flags, payload);
    tcp_checksum_v6(&mut segment, &srcip, &dstip);
    let mut ip = Vec::with_capacity(40 + segment.len());
    ip.push(0x60);
    ip.push(0);
    ip.push(0);
    ip.push(0);
    ip.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    ip.push(6);
    ip.push(64);
    ip.extend_from_slice(&srcip.octets());
    ip.extend_from_slice(&dstip.octets());
    ip.extend_from_slice(&segment);
    let mut out = eth_frame(true);
    out.extend_from_slice(&ip);
    out
}

fn eth_frame(v6: bool) -> Vec<u8> {
    let mut eth = vec![0u8; 14];
    eth[12..14].copy_from_slice(if v6 { &[0x86, 0xdd] } else { &[0x08, 0x00] });
    eth
}

fn tcp_segment(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut seg = vec![0u8; 20 + payload.len()];
    seg[0..2].copy_from_slice(&sport.to_be_bytes());
    seg[2..4].copy_from_slice(&dport.to_be_bytes());
    seg[4..8].copy_from_slice(&seq.to_be_bytes());
    seg[8..12].copy_from_slice(&ack.to_be_bytes());
    seg[12] = 5 << 4;
    seg[13] = flags;
    seg[14..16].copy_from_slice(&65535u16.to_be_bytes());
    seg[20..].copy_from_slice(payload);
    seg
}

fn tcp_checksum_v4(seg: &mut [u8], src: &Ipv4Addr, dst: &Ipv4Addr) {
    let mut sum = 0u32;
    let mut push = |b: &[u8]| {
        for w in b.chunks(2) {
            let word = if w.len() == 2 {
                u16::from_be_bytes([w[0], w[1]])
            } else {
                (w[0] as u16) << 8
            };
            sum += word as u32;
        }
    };
    push(&src.octets());
    push(&dst.octets());
    push(&[0, 6]);
    push(&(seg.len() as u16).to_be_bytes());
    push(seg);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let c = !(sum as u16);
    seg[16..18].copy_from_slice(&c.to_be_bytes());
}

fn tcp_checksum_v6(seg: &mut [u8], src: &Ipv6Addr, dst: &Ipv6Addr) {
    let mut sum = 0u32;
    let mut push = |b: &[u8]| {
        for w in b.chunks(2) {
            let word = if w.len() == 2 {
                u16::from_be_bytes([w[0], w[1]])
            } else {
                (w[0] as u16) << 8
            };
            sum += word as u32;
        }
    };
    push(&src.octets());
    push(&dst.octets());
    push(&(seg.len() as u32).to_be_bytes());
    push(&[0, 0, 0, 6]);
    push(seg);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let c = !(sum as u16);
    seg[16..18].copy_from_slice(&c.to_be_bytes());
}

fn build_ipv4_header(
    src: &Ipv4Addr,
    dst: &Ipv4Addr,
    l4_len: usize,
    id: u16,
    more: bool,
    frag_offset_words: u16,
) -> Vec<u8> {
    let total = 20 + l4_len;
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[1] = 0;
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    let mut ff = frag_offset_words;
    if more {
        ff |= 0x2000;
    }
    ip[6..8].copy_from_slice(&ff.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let sum = csum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    ip
}

fn csum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
