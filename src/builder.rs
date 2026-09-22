//! Deterministic frame fixture builder used by tests and the demo generator.

use crate::json::{self, Json};
use crate::model::{ACK, PSH, SYN};

pub struct FrameSpec {
    pub ts_us: i128,
    pub bytes: Vec<u8>,
}

pub struct Builder {
    linktype: u32,
    frames: Vec<FrameSpec>,
}

impl Builder {
    pub fn new(linktype: u32) -> Builder {
        Builder {
            linktype,
            frames: Vec::new(),
        }
    }

    pub fn add(&mut self, ts_us: i128, bytes: Vec<u8>) -> usize {
        let i = self.frames.len();
        self.frames.push(FrameSpec { ts_us, bytes });
        i
    }

    pub fn to_json(&self) -> Json {
        let mut arr = Vec::new();
        for f in &self.frames {
            let mut o = Json::obj();
            o.set("ts_us", Json::Num(f.ts_us));
            o.set("data", Json::Str(json::bytes_to_hex(&f.bytes)));
            arr.push(o);
        }
        let mut root = Json::obj();
        root.set("linktype", Json::Num(self.linktype as i128));
        root.set("frames", Json::Arr(arr));
        root
    }

    pub fn to_json_string(&self) -> String {
        json::to_string(&self.to_json())
    }

    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }
}

pub fn ipv4(a: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

pub fn parse_ipv4(s: &str) -> [u8; 4] {
    let p: Vec<u8> = s.split('.').map(|x| x.parse().unwrap()).collect();
    [p[0], p[1], p[2], p[3]]
}

fn ip_checksum(b: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < b.len() {
        sum += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
        i += 2;
    }
    if i < b.len() {
        sum += (b[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src: &[u8], dst: &[u8], tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(dst);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    ip_checksum(&pseudo)
}

pub fn tcp_packet(
    src: &str,
    sport: u16,
    dst: &str,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    ip_id: u16,
) -> Vec<u8> {
    tcp_packet_frag(
        src, sport, dst, dport, seq, ack, flags, payload, ip_id, None,
    )
}

/// Build an Ethernet + IPv6 (no extension headers) + TCP frame.
pub fn tcp_packet_v6(
    src: &str,
    sport: u16,
    dst: &str,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let s = parse_ipv6(src);
    let d = parse_ipv6(dst);
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push((20 / 4) << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&64240u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(payload);
    let csum = tcp_checksum_v6(&s, &d, &tcp);
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());

    let plen = tcp.len() as u16;
    let mut ip = Vec::new();
    // 4 bytes: version(4)=6, traffic class(8), flow label(20)
    ip.extend_from_slice(&0x60000000u32.to_be_bytes());
    ip.extend_from_slice(&plen.to_be_bytes());
    ip.push(6); // next header (byte 6)
    ip.push(64); // hop limit (byte 7)
    ip.extend_from_slice(&s);
    ip.extend_from_slice(&d);
    ip.extend_from_slice(&tcp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    eth.extend_from_slice(&0x86ddu16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

fn parse_ipv6(s: &str) -> [u8; 16] {
    let mut groups = [0u16; 8];
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => (h, t),
        None => (s, ""),
    };
    let h: Vec<u16> = if head.is_empty() {
        Vec::new()
    } else {
        head.split(':')
            .map(|x| u16::from_str_radix(x, 16).unwrap())
            .collect()
    };
    let t: Vec<u16> = if tail.is_empty() {
        Vec::new()
    } else {
        tail.split(':')
            .map(|x| u16::from_str_radix(x, 16).unwrap())
            .collect()
    };
    let zero_count = 8 - h.len() - t.len();
    for (i, v) in h.iter().enumerate() {
        groups[i] = *v;
    }
    for (i, v) in t.iter().enumerate() {
        groups[h.len() + zero_count + i] = *v;
    }
    let mut out = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        out[i * 2..i * 2 + 2].copy_from_slice(&g.to_be_bytes());
    }
    out
}

fn tcp_checksum_v6(src: &[u8; 16], dst: &[u8; 16], tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(dst);
    pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 6]);
    pseudo.extend_from_slice(tcp);
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    ip_checksum(&pseudo)
}

/// Build an Ethernet + IPv6-fragment frame. `frag` = (offset bytes % 8, MF, id).
/// The first fragment carries the full TCP header plus initial payload bytes;
/// later fragments carry raw payload.
pub fn tcp_packet_v6_frag(
    src: &str,
    sport: u16,
    dst: &str,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    frag_off: u16,
    mf: bool,
    ident: u32,
) -> Vec<u8> {
    let s = parse_ipv6(src);
    let d = parse_ipv6(dst);

    // Inner L4 content for this fragment: header only on offset-0 fragment.
    let mut l4: Vec<u8> = Vec::new();
    if frag_off == 0 {
        l4.extend_from_slice(&sport.to_be_bytes());
        l4.extend_from_slice(&dport.to_be_bytes());
        l4.extend_from_slice(&seq.to_be_bytes());
        l4.extend_from_slice(&ack.to_be_bytes());
        l4.push((20 / 4) << 4);
        l4.push(flags);
        l4.extend_from_slice(&64240u16.to_be_bytes());
        l4.extend_from_slice(&0u16.to_be_bytes());
        l4.extend_from_slice(&0u16.to_be_bytes());
    }
    l4.extend_from_slice(payload);

    // Fragment extension header (8 bytes).
    let mut ext = Vec::new();
    ext.push(6); // next header
    ext.push(0); // reserved
    let fo_word = (frag_off / 8) << 3 | if mf { 1 } else { 0 };
    ext.extend_from_slice(&fo_word.to_be_bytes());
    ext.extend_from_slice(&ident.to_be_bytes());

    let upper_len = ext.len() + l4.len();
    let mut ip = Vec::new();
    ip.extend_from_slice(&0x60000000u32.to_be_bytes());
    ip.extend_from_slice(&(upper_len as u16).to_be_bytes());
    ip.push(44); // next header = fragment
    ip.push(64);
    ip.extend_from_slice(&s);
    ip.extend_from_slice(&d);
    ip.extend_from_slice(&ext);

    // Correct TCP checksum (over the original, un-fragmented TCP segment) must
    // be computed by the caller scenario; zero checksums are accepted by parser.
    if frag_off == 0 {
        let csum = tcp_checksum_v6(&s, &d, &l4);
        l4[16..18].copy_from_slice(&csum.to_be_bytes());
    }

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    ip.extend_from_slice(&l4);
    eth.extend_from_slice(&0x86ddu16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

pub fn tcp_packet_frag(
    src: &str,
    sport: u16,
    dst: &str,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    ip_id: u16,
    frag: Option<(u16, bool)>, // (offset_in_bytes % 8 == 0, more_fragments)
) -> Vec<u8> {
    let s = parse_ipv4(src);
    let d = parse_ipv4(dst);
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push((20 / 4) << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&64240u16.to_be_bytes()); // window
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urg
    tcp.extend_from_slice(payload);
    let csum = tcp_checksum(&s, &d, &tcp);
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());

    let (frag_off, mf) = frag.map(|(o, m)| (o / 8, m)).unwrap_or((0, false));
    let frag_word = (frag_off as u16) | if mf { 0x2000 } else { 0 };

    let total = 20 + tcp.len();
    let mut ip = Vec::new();
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&ip_id.to_be_bytes());
    ip.extend_from_slice(&frag_word.to_be_bytes());
    ip.push(64);
    ip.push(6);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&s);
    ip.extend_from_slice(&d);
    let hcsum = ip_checksum(&ip);
    ip[10..12].copy_from_slice(&hcsum.to_be_bytes());
    ip.extend_from_slice(&tcp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

/// Emit a three-way handshake plus optional bidirectional payload/close.
pub fn handshake(
    b: &mut Builder,
    ts: i128,
    c: &str,
    cp: u16,
    s: &str,
    sp: u16,
    isn_c: u32,
    isn_s: u32,
) -> i128 {
    let mut t = ts;
    b.add(t, tcp_packet(c, cp, s, sp, isn_c, 0, SYN, &[], 100));
    t += 100;
    b.add(
        t,
        tcp_packet(
            s,
            sp,
            c,
            cp,
            isn_s,
            isn_c.wrapping_add(1),
            SYN | ACK,
            &[],
            101,
        ),
    );
    t += 100;
    b.add(
        t,
        tcp_packet(
            c,
            cp,
            s,
            sp,
            isn_c.wrapping_add(1),
            isn_s.wrapping_add(1),
            ACK,
            &[],
            102,
        ),
    );
    t += 100;
    t
}

pub fn data(
    b: &mut Builder,
    ts: i128,
    src: &str,
    sp: u16,
    dst: &str,
    dp: u16,
    seq: u32,
    ack: u32,
    payload: &[u8],
    id: u16,
) -> i128 {
    b.add(
        ts,
        tcp_packet(src, sp, dst, dp, seq, ack, PSH | ACK, payload, id),
    );
    ts + 100
}

pub fn flags(
    b: &mut Builder,
    ts: i128,
    src: &str,
    sp: u16,
    dst: &str,
    dp: u16,
    seq: u32,
    ack: u32,
    fl: u8,
    id: u16,
) -> i128 {
    b.add(ts, tcp_packet(src, sp, dst, dp, seq, ack, fl, &[], id));
    ts + 100
}

pub use crate::model::{ACK as F_ACK, FIN as F_FIN, RST as F_RST, SYN as F_SYN};
