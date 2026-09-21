//! Deterministic fixture constructors.
//!
//! These builders emit real Ethernet/IP/TCP frames with correct checksums, so
//! the very same parsing pipeline consumes both captured pcap data and generated
//! fixtures. Custom JSON fixtures may instead provide prebuilt `bytes_hex`.

use crate::frame::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};
use crate::types::{Ip, LinkKind, RawFrame};

#[derive(Clone)]
pub struct TcpFrameSpec {
    pub timestamp: f64,
    pub src: Ip,
    pub dst: Ip,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub syn: bool,
    pub ack_flag: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub payload: Vec<u8>,
    pub link: LinkKind,
    pub comment: Option<String>,
}

impl TcpFrameSpec {
    pub fn new(timestamp: f64, src: Ip, dst: Ip, src_port: u16, dst_port: u16) -> Self {
        TcpFrameSpec {
            timestamp,
            src,
            dst,
            src_port,
            dst_port,
            seq: 0,
            ack: 0,
            syn: false,
            ack_flag: false,
            fin: false,
            rst: false,
            psh: false,
            payload: Vec::new(),
            link: LinkKind::Ethernet,
            comment: None,
        }
    }

    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }
    pub fn ack(mut self, ack: u32) -> Self {
        self.ack = ack;
        self.ack_flag = true;
        self
    }
    pub fn flags(mut self, syn: bool, ackf: bool, fin: bool, rst: bool) -> Self {
        self.syn = syn;
        self.ack_flag = ackf;
        self.fin = fin;
        self.rst = rst;
        self
    }
    pub fn payload(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.payload = data.into();
        if !self.payload.is_empty() {
            self.psh = true;
        }
        self
    }
    pub fn link(mut self, link: LinkKind) -> Self {
        self.link = link;
        self
    }
    pub fn comment(mut self, c: impl Into<String>) -> Self {
        self.comment = Some(c.into());
        self
    }
}

pub fn tcp_frame(spec: &TcpFrameSpec) -> RawFrame {
    let ip_bytes = build_ip(&spec.src, &spec.dst, &build_tcp_segment(spec));
    let bytes = match spec.link {
        LinkKind::Ethernet => wrap_ethernet(&spec.src, &spec.dst, &ip_bytes),
        LinkKind::Ipv4Raw | LinkKind::Ipv6Raw | LinkKind::Raw => ip_bytes,
        LinkKind::Null => {
            let family: u32 = match spec.src {
                Ip::V4(_) => 2,
                Ip::V6(_) => 28,
            };
            let mut b = family.to_le_bytes().to_vec();
            b.extend_from_slice(&ip_bytes);
            b
        }
        LinkKind::LinuxSll => {
            let ethertype: u16 = match spec.src {
                Ip::V4(_) => 0x0800,
                Ip::V6(_) => 0x86dd,
            };
            let mut b = vec![0u8; 14];
            b.extend_from_slice(&ethertype.to_be_bytes());
            b.extend_from_slice(&ip_bytes);
            b
        }
    };
    RawFrame {
        index: None,
        timestamp: spec.timestamp,
        link: spec.link,
        bytes_hex: crate::hash::hex(&bytes),
        comment: spec.comment.clone(),
    }
}

fn wrap_ethernet(src: &Ip, dst: &Ip, ip: &[u8]) -> Vec<u8> {
    let ethertype: u16 = match src {
        Ip::V4(_) => 0x0800,
        Ip::V6(_) => 0x86dd,
    };
    let mut frame = Vec::with_capacity(14 + ip.len());
    frame.extend_from_slice(&deterministic_mac(dst, true));
    frame.extend_from_slice(&deterministic_mac(src, false));
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(ip);
    frame
}

fn deterministic_mac(ip: &Ip, destination: bool) -> [u8; 6] {
    // Locally administered, stable per address.
    let digest = crate::hash::sha256(ip.to_string().as_bytes());
    [
        if destination { 0x02 } else { 0x06 },
        0x42,
        digest[0],
        digest[1],
        digest[2],
        digest[3],
    ]
}

fn build_ip(src: &Ip, dst: &Ip, tcp: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (Ip::V4(s), Ip::V4(d)) => build_ipv4(s, d, tcp, false, 0, 0),
        (Ip::V6(s), Ip::V6(d)) => build_ipv6(s, d, tcp),
        _ => panic!("mixed IPv4/IPv6 endpoints are unsupported"),
    }
}

/// Build an IPv4 packet carrying `l4`, optionally as one fragment.
/// `frag_offset` is in bytes (must be a multiple of 8); `more` sets MF.
pub fn build_ipv4_fragment(
    src: &[u8; 4],
    dst: &[u8; 4],
    l4: &[u8],
    ident: u16,
    frag_offset: usize,
    more: bool,
) -> Vec<u8> {
    build_ipv4(src, dst, l4, more, ident, frag_offset)
}

fn build_ipv4(src: &[u8; 4], dst: &[u8; 4], l4: &[u8], more: bool, ident: u16, frag_offset: usize) -> Vec<u8> {
    let total_len = 20 + l4.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45); // version + IHL 5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&ident.to_be_bytes());
    let mut flags_frag = (frag_offset / 8) as u16;
    if more {
        flags_frag |= 0x2000;
    }
    pkt.extend_from_slice(&flags_frag.to_be_bytes());
    pkt.push(64); // TTL
    pkt.push(6); // TCP
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    pkt.extend_from_slice(src);
    pkt.extend_from_slice(dst);
    pkt.extend_from_slice(l4);
    let cksum = ipv4_header_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&cksum.to_be_bytes());
    pkt
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_ipv6(src: &[u8; 16], dst: &[u8; 16], tcp: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(40 + tcp.len());
    pkt.push(0x60);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pkt.push(6); // next header TCP
    pkt.push(64); // hop limit
    pkt.extend_from_slice(src);
    pkt.extend_from_slice(dst);
    pkt.extend_from_slice(tcp);
    pkt
}

/// IPv6 fragment frame (non-first fragments carry raw l4 bytes).
pub fn build_ipv6_fragment(
    src: &[u8; 16],
    dst: &[u8; 16],
    fragment_header_payload: &[u8],
    ident: u32,
    frag_offset: usize,
    more: bool,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(40 + 8 + fragment_header_payload.len());
    pkt.push(0x60);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.extend_from_slice(&((8 + fragment_header_payload.len()) as u16).to_be_bytes());
    pkt.push(44); // next header: fragment
    pkt.push(64);
    pkt.extend_from_slice(src);
    pkt.extend_from_slice(dst);
    // Fragment extension header.
    pkt.push(6); // next header after fragment = TCP
    pkt.push(0); // reserved
    let mut off_flags = ((frag_offset / 8) as u16) << 3;
    if more {
        off_flags |= 1;
    }
    pkt.extend_from_slice(&off_flags.to_be_bytes());
    pkt.extend_from_slice(&ident.to_be_bytes());
    pkt.extend_from_slice(fragment_header_payload);
    pkt
}

fn tcp_flags(spec: &TcpFrameSpec) -> u8 {
    let mut flags = 0u8;
    if spec.syn { flags |= TCP_SYN; }
    if spec.ack_flag { flags |= TCP_ACK; }
    if spec.fin { flags |= TCP_FIN; }
    if spec.rst { flags |= TCP_RST; }
    if spec.psh { flags |= TCP_PSH; }
    flags
}

pub fn tcp_segment_bytes(spec: &TcpFrameSpec) -> Vec<u8> {
    build_tcp_segment(spec)
}

fn build_tcp_segment(spec: &TcpFrameSpec) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + spec.payload.len());
    seg.extend_from_slice(&spec.src_port.to_be_bytes());
    seg.extend_from_slice(&spec.dst_port.to_be_bytes());
    seg.extend_from_slice(&spec.seq.to_be_bytes());
    seg.extend_from_slice(&spec.ack.to_be_bytes());
    seg.push(0x50); // data offset 5 (20 bytes), reserved zero
    seg.push(tcp_flags(spec));
    seg.extend_from_slice(&65535u16.to_be_bytes()); // window
    seg.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    seg.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    seg.extend_from_slice(&spec.payload);
    let cksum = tcp_checksum(&spec.src, &spec.dst, &seg);
    seg[16..18].copy_from_slice(&cksum.to_be_bytes());
    seg
}

fn tcp_checksum(src: &Ip, dst: &Ip, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::new();
    match (src, dst) {
        (Ip::V4(s), Ip::V4(d)) => {
            pseudo.extend_from_slice(s);
            pseudo.extend_from_slice(d);
            pseudo.push(0);
            pseudo.push(6);
            pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes()[2..]);
        }
        (Ip::V6(s), Ip::V6(d)) => {
            pseudo.extend_from_slice(s);
            pseudo.extend_from_slice(d);
            pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 6]);
        }
        _ => panic!("mixed address families"),
    }
    let mut sum = 0u32;
    sum = add_bytes(sum, &pseudo);
    sum = add_bytes(sum, segment);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn add_bytes(mut sum: u32, data: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

/// Wrap an already-built IP packet in a link-layer frame for a fixture.
pub fn raw_ip_frame(timestamp: f64, src: &Ip, ip_packet: &[u8], comment: Option<String>) -> RawFrame {
    let link = match src {
        Ip::V4(_) => LinkKind::Ipv4Raw,
        Ip::V6(_) => LinkKind::Ipv6Raw,
    };
    RawFrame {
        index: None,
        timestamp,
        link,
        bytes_hex: crate::hash::hex(ip_packet),
        comment,
    }
}

/// Convenience: build an IPv4 packet for a TCP segment spec, then split it into
/// IP fragments. The first fragment keeps the full TCP header; later fragments
/// contain arbitrary 8-byte-aligned tails of the TCP stream.
pub fn tcp_ipv4_fragments(
    spec: &TcpFrameSpec,
    ident: u16,
    fragment_payload_sizes: &[usize],
) -> Vec<RawFrame> {
    let tcp = build_tcp_segment(spec);
    let (s, d) = match (&spec.src, &spec.dst) {
        (Ip::V4(s), Ip::V4(d)) => (s, d),
        _ => panic!("tcp_ipv4_fragments requires IPv4"),
    };
    split_into_ipv4_frames(spec.timestamp, s, d, &tcp, ident, fragment_payload_sizes)
}

fn split_into_ipv4_frames(
    timestamp: f64,
    src: &[u8; 4],
    dst: &[u8; 4],
    tcp: &[u8],
    ident: u16,
    sizes: &[usize],
) -> Vec<RawFrame> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    let total = sizes.iter().sum::<usize>();
    assert_eq!(total, tcp.len(), "fragment sizes must cover the TCP datagram");
    for (i, &size) in sizes.iter().enumerate() {
        let chunk = &tcp[offset..offset + size];
        let more = i + 1 < sizes.len();
        let pkt = build_ipv4_fragment(src, dst, chunk, ident, offset, more);
        frames.push(raw_ip_frame(
            timestamp,
            &Ip::V4(*src),
            &pkt,
            Some(format!("ipv4 fragment offset {offset}")),
        ));
        offset += size;
    }
    frames
}
