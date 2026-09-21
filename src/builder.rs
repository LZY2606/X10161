//! Deterministic frame/fixture constructors used by tests and the built-in
//! demo fixture. All checksums are computed properly so the output could be
//! replayed by real tooling.

use crate::fixture::{Frame, FIXTURE_MAGIC};
use crate::packet::{FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN};
use crate::sha256::to_hex;

pub const MAC_A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
pub const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        sum += (rem[0] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn tcp_segment(src_ip: &[u8], dst_ip: &[u8], sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(5 << 4); // data offset = 20 bytes
    seg.push(flags);
    seg.extend_from_slice(&65535u16.to_be_bytes()); // window
    seg.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    seg.extend_from_slice(&0u16.to_be_bytes()); // urgent
    seg.extend_from_slice(payload);
    // TCP checksum over pseudo-header.
    let mut pseudo = Vec::new();
    if src_ip.len() == 4 {
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dst_ip);
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    } else {
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dst_ip);
        pseudo.extend_from_slice(&(seg.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 6]);
    }
    pseudo.extend_from_slice(&seg);
    let csum = checksum(&pseudo);
    seg[16..18].copy_from_slice(&csum.to_be_bytes());
    seg
}

fn eth_wrap(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&MAC_B);
    f.extend_from_slice(&MAC_A);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn ipv4_wrap(src: [u8; 4], dst: [u8; 4], id: u16, frag_off_flags: u16, proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut ip = Vec::with_capacity(total as usize);
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&id.to_be_bytes());
    ip.extend_from_slice(&frag_off_flags.to_be_bytes());
    ip.push(64); // ttl
    ip.push(proto);
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let csum = checksum(&ip);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    eth_wrap(0x0800, &ip)
}

pub fn tcp_v4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let seg = tcp_segment(&src, &dst, sport, dport, seq, ack, flags, payload);
    ipv4_wrap(src, dst, 0, 0, 6, &seg)
}

pub fn tcp_v6(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let seg = tcp_segment(&src, &dst, sport, dport, seq, ack, flags, payload);
    let mut ip = Vec::with_capacity(40 + seg.len());
    ip.push(0x60);
    ip.extend_from_slice(&[0, 0, 0]);
    ip.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    ip.push(6); // next header TCP
    ip.push(64); // hop limit
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(&seg);
    eth_wrap(0x86dd, &ip)
}

/// One IPv4 fragment carrying `payload` (a slice of the inner datagram).
pub fn ipv4_fragment(src: [u8; 4], dst: [u8; 4], id: u16, offset_bytes: u32, more: bool, proto: u8, payload: &[u8]) -> Vec<u8> {
    assert_eq!(offset_bytes % 8, 0, "fragment offsets are 8-byte units");
    let mut flags_off = ((offset_bytes / 8) as u16) & 0x1fff;
    if more {
        flags_off |= 0x2000;
    }
    ipv4_wrap(src, dst, id, flags_off, proto, payload)
}

pub fn fixture_text(frames: &[(i64, Vec<u8>)]) -> String {
    let mut out = String::new();
    out.push_str(FIXTURE_MAGIC);
    out.push('\n');
    for (i, (ts, data)) in frames.iter().enumerate() {
        out.push_str(&format!("frame {} {} {}\n", i, ts, to_hex(data)));
    }
    out
}

pub fn pcap_bytes(frames: &[(i64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // LE magic
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
    for (ts, data) in frames {
        let sec = (ts / 1_000_000) as u32;
        let usec = (ts % 1_000_000) as u32;
        out.extend_from_slice(&sec.to_le_bytes());
        out.extend_from_slice(&usec.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

pub fn frames_of(fixture: &[(i64, Vec<u8>)]) -> Vec<Frame> {
    fixture
        .iter()
        .enumerate()
        .map(|(i, (ts, data))| Frame { index: i as u32, ts_micros: *ts, data: data.clone() })
        .collect()
}

// Convenience flag combos for tests/demo.
pub const SYN: u8 = FLAG_SYN;
pub const SYN_ACK: u8 = FLAG_SYN | FLAG_ACK;
pub const ACK: u8 = FLAG_ACK;
pub const PSH_ACK: u8 = FLAG_PSH | FLAG_ACK;
pub const FIN_ACK: u8 = FLAG_FIN | FLAG_ACK;
pub const RST: u8 = FLAG_RST;
pub const RST_ACK: u8 = FLAG_RST | FLAG_ACK;

/// Demo fixture combining several interesting scenarios for the UI.
pub fn demo_fixture() -> String {
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    let c = [10, 0, 0, 3];
    let t = 1_700_000_000_000_000i64;
    let mut f: Vec<(i64, Vec<u8>)> = Vec::new();
    // Session 1: full handshake, out-of-order + retransmission + overlap.
    f.push((t, tcp_v4(a, b, 40000, 80, 1000, 0, SYN, &[])));
    f.push((t + 10_000, tcp_v4(b, a, 80, 40000, 5000, 1001, SYN_ACK, &[])));
    f.push((t + 20_000, tcp_v4(a, b, 40000, 80, 1001, 5001, ACK, &[])));
    f.push((t + 30_000, tcp_v4(a, b, 40000, 80, 1001, 5001, PSH_ACK, b"hello ")));
    f.push((t + 40_000, tcp_v4(a, b, 40000, 80, 1013, 5001, PSH_ACK, b"world!"))); // ooo (gap first)
    f.push((t + 50_000, tcp_v4(a, b, 40000, 80, 1007, 5001, PSH_ACK, b"brave "))); // fills gap, overlaps "o " -> kept per policy
    f.push((t + 60_000, tcp_v4(a, b, 40000, 80, 1001, 5001, PSH_ACK, b"hello "))); // retransmission
    f.push((t + 70_000, tcp_v4(b, a, 80, 40000, 5001, 1019, PSH_ACK, b"200 OK")));
    f.push((t + 80_000, tcp_v4(a, b, 40000, 80, 1019, 5007, FIN_ACK, &[])));
    f.push((t + 90_000, tcp_v4(b, a, 80, 40000, 5007, 1020, FIN_ACK, &[])));
    // Session 2: same 4-tuple reused after close -> new generation.
    f.push((t + 200_000, tcp_v4(a, b, 40000, 80, 9000, 0, SYN, &[])));
    f.push((t + 210_000, tcp_v4(b, a, 80, 40000, 3000, 9001, SYN_ACK, &[])));
    f.push((t + 220_000, tcp_v4(a, b, 40000, 80, 9001, 3001, PSH_ACK, b"second incarnation")));
    f.push((t + 230_000, tcp_v4(a, b, 40000, 80, 9020, 3001, RST_ACK, &[])));
    // Session 3: capture starts mid-stream (partial, no handshake).
    f.push((t + 300_000, tcp_v4(a, c, 51000, 22, 777000, 0, PSH_ACK, b"mid-stream-data")));
    f.push((t + 310_000, tcp_v4(c, a, 22, 51000, 444000, 777015, PSH_ACK, b"reply")));
    // Session 4: fragmented IPv4 datagram carrying a TCP segment.
    let seg = tcp_segment(&a, &b, 45000, 8080, 100, 0, SYN, &[]);
    let (p1, p2) = seg.split_at(8);
    f.push((t + 400_000, ipv4_fragment(a, b, 0x1234, 0, true, 6, p1)));
    f.push((t + 410_000, ipv4_fragment(a, b, 0x1234, 8, false, 6, p2)));
    fixture_text(&f)
}
