//! 确定性帧构造器：生成 Ethernet/IPv4/IPv6/TCP 报文与 IPv4 分片，
//! 供测试构造环绕、重传、乱序、FIN/RST 竞态等场景。

use crate::model::{Frame, ACK, FIN, PSH, RST, SYN};

fn ipv4_checksum(data: &[u8]) -> u16 {
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

#[derive(Clone, Copy)]
pub struct TcpArgs<'a> {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

pub fn tcp_v4(args: TcpArgs<'_>) -> Vec<u8> {
    tcp_v4_ts(args, 0)
}

pub fn tcp_v4_ts(args: TcpArgs<'_>, _ts: u64) -> Vec<u8> {
    let TcpArgs {
        src,
        dst,
        sport,
        dport,
        seq,
        ack,
        flags,
        payload,
    } = args;

    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push((20 / 4) << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&64240u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum（解析器不校验）
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent
    tcp.extend_from_slice(payload);

    let total_len = 20 + tcp.len();
    let mut ip = Vec::with_capacity(20 + tcp.len());
    ip.push(0x45);
    ip.push(0x00);
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&0x1234u16.to_be_bytes()); // ident
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
    ip.push(64);
    ip.push(6);
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let cksum = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&cksum.to_be_bytes());
    ip.extend_from_slice(&tcp);

    let mut eth = Vec::with_capacity(14 + ip.len());
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

pub fn frame(ts_ns: u64, raw: Vec<u8>) -> Frame {
    Frame {
        index: 0,
        ts_ns,
        raw,
    }
}

pub fn frames(ts_raw: &[(u64, Vec<u8>)]) -> Vec<Frame> {
    ts_raw
        .iter()
        .enumerate()
        .map(|(i, (ts, raw))| Frame {
            index: i as u32,
            ts_ns: *ts,
            raw: raw.clone(),
        })
        .collect()
}

/// 生成一个 IPv4 分片（Ethernet + IP + 分片数据）。
/// 数据报内容必须是完整的 TCP 报文；按 offset/more 切分。
pub fn ipv4_fragment(
    src: [u8; 4],
    dst: [u8; 4],
    ident: u16,
    offset_bytes: u16,
    more: bool,
    datagram_fragment: &[u8],
) -> Vec<u8> {
    let mut ip = Vec::with_capacity(20 + datagram_fragment.len());
    ip.push(0x45);
    ip.push(0x00);
    ip.extend_from_slice(&((20 + datagram_fragment.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&ident.to_be_bytes());
    let frag = (offset_bytes / 8) | if more { 0x2000 } else { 0x0000 };
    ip.extend_from_slice(&frag.to_be_bytes());
    ip.push(64);
    ip.push(6);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let cksum = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&cksum.to_be_bytes());
    ip.extend_from_slice(datagram_fragment);

    let mut eth = Vec::with_capacity(14 + ip.len());
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

/// 直接构造一个无 IP 封装的 TCP 数据报字节（用作分片的净荷输入）。
pub fn tcp_datagram(
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&64240u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(payload);
    tcp
}

pub fn syn(src: [u8;4], dst: [u8;4], sport: u16, dport: u16, seq: u32) -> Vec<u8> {
    tcp_v4(TcpArgs { src, dst, sport, dport, seq, ack: 0, flags: SYN, payload: &[] })
}
pub fn synack(src: [u8;4], dst: [u8;4], sport: u16, dport: u16, seq: u32, ack: u32) -> Vec<u8> {
    tcp_v4(TcpArgs { src, dst, sport, dport, seq, ack, flags: SYN | ACK, payload: &[] })
}
pub fn ack_bytes(src: [u8;4], dst: [u8;4], sport: u16, dport: u16, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    tcp_v4(TcpArgs { src, dst, sport, dport, seq, ack, flags: ACK | PSH, payload })
}
pub fn pure_ack(src: [u8;4], dst: [u8;4], sport: u16, dport: u16, seq: u32, ack: u32) -> Vec<u8> {
    tcp_v4(TcpArgs { src, dst, sport, dport, seq, ack, flags: ACK, payload: &[] })
}
pub fn fin_ack(src: [u8;4], dst: [u8;4], sport: u16, dport: u16, seq: u32, ack: u32) -> Vec<u8> {
    tcp_v4(TcpArgs { src, dst, sport, dport, seq, ack, flags: FIN | ACK, payload: &[] })
}
pub fn rst(src: [u8;4], dst: [u8;4], sport: u16, dport: u16, seq: u32, ack: u32) -> Vec<u8> {
    tcp_v4(TcpArgs { src, dst, sport, dport, seq, ack, flags: RST, payload: &[] })
}
