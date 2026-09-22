use crate::pcap::Frame;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

pub const A_IP: [u8; 4] = [10, 0, 0, 1];
pub const B_IP: [u8; 4] = [10, 0, 0, 2];
pub const A_PORT: u16 = 40000;
pub const B_PORT: u16 = 80;

fn tcp_header(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut h = Vec::with_capacity(20);
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    h.extend_from_slice(&seq.to_be_bytes());
    h.extend_from_slice(&ack.to_be_bytes());
    h.push(5 << 4); // data offset
    h.push(flags);
    h.extend_from_slice(&65535u16.to_be_bytes()); // window
    h.extend_from_slice(&0u16.to_be_bytes()); // checksum (not validated)
    h.extend_from_slice(&0u16.to_be_bytes()); // urg
    h
}

fn ipv4_header(src: [u8; 4], dst: [u8; 4], proto: u8, payload_len: usize) -> Vec<u8> {
    let total = 20 + payload_len;
    let mut h = Vec::with_capacity(20);
    h.push(0x45);
    h.push(0);
    h.extend_from_slice(&(total as u16).to_be_bytes());
    h.extend_from_slice(&0u16.to_be_bytes()); // id
    h.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    h.push(64);
    h.push(proto);
    h.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let sum = ipv4_checksum(&h);
    h[10..12].copy_from_slice(&sum.to_be_bytes());
    h
}

fn ipv4_checksum(h: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in h.chunks(2) {
        let w = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            (chunk[0] as u16) << 8
        };
        sum += w as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn eth(payload: &[u8], ethertype: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Ethernet / IPv4 / TCP frame.
pub fn tcp4(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = tcp_header(sport, dport, seq, ack, flags);
    seg.extend_from_slice(payload);
    let mut ip = ipv4_header(src, dst, 6, seg.len());
    ip.append(&mut seg);
    eth(&ip, 0x0800)
}

/// Ethernet / IPv6 / TCP frame.
pub fn tcp6(
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = tcp_header(sport, dport, seq, ack, flags);
    seg.extend_from_slice(payload);
    let mut ip = Vec::with_capacity(40);
    ip.push(0x60);
    ip.extend_from_slice(&[0, 0, 0]);
    ip.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    ip.push(6); // next header: TCP
    ip.push(64); // hop limit
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.append(&mut seg);
    eth(&ip, 0x86dd)
}

/// One IPv4 fragment carrying a raw chunk of the transport payload.
pub fn ipv4_fragment(
    src: [u8; 4],
    dst: [u8; 4],
    ident: u16,
    offset_bytes: u16,
    more: bool,
    proto: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut h = Vec::with_capacity(20);
    h.push(0x45);
    h.push(0);
    h.extend_from_slice(&(total as u16).to_be_bytes());
    h.extend_from_slice(&ident.to_be_bytes());
    let mut frag = offset_bytes / 8;
    if more {
        frag |= 0x2000;
    }
    h.extend_from_slice(&frag.to_be_bytes());
    h.push(64);
    h.push(proto);
    h.extend_from_slice(&0u16.to_be_bytes());
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let sum = ipv4_checksum(&h);
    h[10..12].copy_from_slice(&sum.to_be_bytes());
    h.extend_from_slice(payload);
    eth(&h, 0x0800)
}

/// Deterministic capture builder: frames keep insertion order as frame index.
#[derive(Default)]
pub struct Capture {
    pub frames: Vec<Frame>,
}

impl Capture {
    pub fn new() -> Self {
        Capture { frames: Vec::new() }
    }
    pub fn push(&mut self, ts_ns: u64, data: Vec<u8>) -> &mut Self {
        let index = self.frames.len() as u64;
        self.frames.push(Frame { index, ts_ns, data });
        self
    }
    /// Convenience: TCP/IPv4 between the standard test endpoints.
    pub fn tcp_ab(&mut self, ts_ns: u64, seq: u32, flags: u8, payload: &[u8]) -> &mut Self {
        let f = tcp4(A_IP, B_IP, A_PORT, B_PORT, seq, 0, flags, payload);
        self.push(ts_ns, f)
    }
    pub fn tcp_ba(&mut self, ts_ns: u64, seq: u32, flags: u8, payload: &[u8]) -> &mut Self {
        let f = tcp4(B_IP, A_IP, B_PORT, A_PORT, seq, 0, flags, payload);
        self.push(ts_ns, f)
    }
}
