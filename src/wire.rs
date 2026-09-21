//! 链路层 / IPv4 / IPv6 / TCP 元数据解析（只读、无状态）。
//!
//! IP 分片的组盒逻辑在 [`crate::frag`]；本模块负责把单个链路帧拆成
//! “分片件”或“完整数据报”，并在校验通过后解析 TCP。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_IPV6: u8 = 41;
pub const IP_PROTO_FRAGMENT: u8 = 44;

/// pcap 链路类型：以太网。
pub const LINK_ETHERNET: u32 = 1;
/// pcap 链路类型：原生 IPv4/IPv6（无链路头）。
pub const LINK_RAW: u32 = 101;
/// pcap 链路类型：Linux cooked v1。
pub const LINK_LINUX_SLL: u32 = 113;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone)]
pub struct IpMeta {
    pub version: IpVersion,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub id: u32,
    pub fragment: FragInfo,
    /// IPv4 首部校验是否通过（IPv6 无首部校验和）。
    pub header_checksum_ok: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FragInfo {
    pub more_fragments: bool,
    /// 分片偏移，单位字节。
    pub offset: u16,
}

impl FragInfo {
    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.offset != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

impl TcpFlags {
    pub fn from_byte(b: u8) -> TcpFlags {
        TcpFlags {
            syn: b & 0x02 != 0,
            ack: b & 0x10 != 0,
            fin: b & 0x01 != 0,
            rst: b & 0x04 != 0,
            psh: b & 0x08 != 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpMeta {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum_ok: bool,
}

#[derive(Debug, Clone)]
pub struct CompleteDatagram {
    pub ip: IpMeta,
    pub tcp: Option<TcpMeta>,
    /// TCP 报文段数据（非 TCP 时为整个负载）。
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FragmentPiece {
    pub ip: IpMeta,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum FrameOutcome {
    /// 非 IPv4/IPv6，或非上层关注协议（UDP/ICMP 等）。
    Ignored,
    /// 单个帧即携带完整（未分片）数据报。
    Complete(CompleteDatagram),
    /// IP 分片的一片，交给分片重组器。
    Fragment(FragmentPiece),
}

#[derive(Debug, Clone)]
pub struct ParseNote {
    pub frame_index: usize,
    pub kind: String,
    pub detail: String,
}

/// 解析一帧。`frame_index` 为原始帧序号（从 0 开始）。
pub fn parse_frame(frame: &[u8], link: u32, frame_index: usize) -> Result<FrameOutcome, String> {
    let (packet, link_type) = strip_link(frame, link)?;
    match link_type {
        IpVersion::V4 => parse_ipv4(packet, frame_index),
        IpVersion::V6 => parse_ipv6(packet, frame_index),
    }
}

fn strip_link(frame: &[u8], link: u32) -> Result<(&[u8], IpVersion), String> {
    match link {
        LINK_ETHERNET => {
            if frame.len() < 14 {
                return Err("ethernet: 帧短于 14 字节".into());
            }
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            let mut rest = &frame[14..];
            let et = match ethertype {
                0x8100 => {
                    // 802.1Q（兼容 QinQ，最多两层）
                    if rest.len() < 4 {
                        return Err("vlan: 帧被截断".into());
                    }
                    let mut et = u16::from_be_bytes([rest[2], rest[3]]);
                    rest = &rest[4..];
                    if et == 0x8100 {
                        if rest.len() < 4 {
                            return Err("vlan: QinQ 帧被截断".into());
                        }
                        et = u16::from_be_bytes([rest[2], rest[3]]);
                        rest = &rest[4..];
                    }
                    et
                }
                other => other,
            };
            match et {
                0x0800 => Ok((rest, IpVersion::V4)),
                0x86dd => Ok((rest, IpVersion::V6)),
                _ => Err(format!("ethernet: 非 IP 以太类型 0x{:04x}", et)),
            }
        }
        LINK_RAW => {
            let v = *frame.first().ok_or("raw: 空帧")? >> 4;
            match v {
                4 => Ok((frame, IpVersion::V4)),
                6 => Ok((frame, IpVersion::V6)),
                _ => Err(format!("raw: 未知 IP 版本 {}", v)),
            }
        }
        LINK_LINUX_SLL => {
            if frame.len() < 16 {
                return Err("sll: 帧短于 16 字节".into());
            }
            let et = u16::from_be_bytes([frame[14], frame[15]]);
            match et {
                0x0800 => Ok((&frame[16..], IpVersion::V4)),
                0x86dd => Ok((&frame[16..], IpVersion::V6)),
                _ => Err(format!("sll: 非 IP 以太类型 0x{:04x}", et)),
            }
        }
        other => Err(format!("link: 不支持的 pcap 链路类型 {}", other)),
    }
}

fn ones_complement(data: &[u8]) -> u16 {
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

fn parse_ipv4(packet: &[u8], _frame_index: usize) -> Result<FrameOutcome, String> {
    if packet.len() < 20 {
        return Err("ipv4: 首部短于 20 字节".into());
    }
    if packet[0] >> 4 != 4 {
        return Err("ipv4: 版本字段不是 4".into());
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || ihl > packet.len() {
        return Err("ipv4: 非法首部长度".into());
    }
    let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_length < ihl || total_length > packet.len() {
        return Err("ipv4: 总长度越界（可能被 snaplen 截断）".into());
    }
    let datagram = &packet[..total_length];
    let identification = u16::from_be_bytes([packet[4], packet[5]]);
    let flags_frag = u16::from_be_bytes([packet[6], packet[7]]);
    let more = flags_frag & 0x2000 != 0;
    let offset = ((flags_frag & 0x1fff) * 8) as u16;
    let protocol = packet[9];
    let header_sum = ones_complement(&datagram[..ihl]);
    let header_ok = header_sum == 0;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let ip = IpMeta {
        version: IpVersion::V4,
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        protocol,
        id: identification as u32,
        fragment: FragInfo {
            more_fragments: more,
            offset,
        },
        header_checksum_ok: header_ok,
    };
    let l4 = &datagram[ihl..];
    finish_ip(ip, l4)
}

fn parse_ipv6(packet: &[u8], frame_index: usize) -> Result<FrameOutcome, String> {
    if packet.len() < 40 {
        return Err("ipv6: 首部短于 40 字节".into());
    }
    if packet[0] >> 4 != 6 {
        return Err("ipv6: 版本字段不是 6".into());
    }
    let payload_length = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if 40 + payload_length > packet.len() {
        return Err("ipv6: 负载长度越界（可能被 snaplen 截断）".into());
    }
    let mut next_header = packet[6];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
    let mut cursor = 40usize;
    let end = 40 + payload_length;

    // 逐个跳过扩展首部；遇到分片扩展则重组，遇到 TCP 则解析。
    loop {
        match next_header {
            IPPROTO_TCP => {
                let ip = IpMeta {
                    version: IpVersion::V6,
                    src: IpAddr::V6(src),
                    dst: IpAddr::V6(dst),
                    protocol: IPPROTO_TCP,
                    id: 0,
                    fragment: FragInfo::default(),
                    header_checksum_ok: true,
                };
                return finish_ip(ip, &packet[cursor..end]);
            }
            IP_PROTO_FRAGMENT => {
                if cursor + 8 > end {
                    return Err("ipv6-frag: 扩展首部被截断".into());
                }
                let ext = &packet[cursor..cursor + 8];
                let frag_next = ext[0];
                let off_flags = u16::from_be_bytes([ext[2], ext[3]]);
                let more = off_flags & 0x0001 != 0;
                let offset = ((off_flags >> 3) * 8) as u16;
                let ident = u32::from_be_bytes([ext[4], ext[5], ext[6], ext[7]]);
                let ip = IpMeta {
                    version: IpVersion::V6,
                    src: IpAddr::V6(src),
                    dst: IpAddr::V6(dst),
                    protocol: frag_next,
                    id: ident,
                    fragment: FragInfo {
                        more_fragments: more,
                        offset,
                    },
                    header_checksum_ok: true,
                };
                return finish_ip(ip, &packet[cursor + 8..end]);
            }
            // Hop-by-Hop(0), Routing(43), Destination Options(60), AH(51)
            0 | 43 | 60 | 51 => {
                if cursor >= end {
                    return Err("ipv6-ext: 扩展首部越界".into());
                }
                let hdr_len = if next_header == 51 {
                    // AH：载荷长度字段单位 4 字节，整体 = (len+2)*4
                    ((packet[cursor + 1] as usize) + 2) * 4
                } else {
                    (packet[cursor + 1] as usize + 1) * 8
                };
                if hdr_len == 0 || cursor + hdr_len > end {
                    return Err("ipv6-ext: 扩展首部长度非法".into());
                }
                next_header = packet[cursor];
                cursor += hdr_len;
            }
            _ => {
                let _ = frame_index;
                return Ok(FrameOutcome::Ignored);
            }
        }
    }
}

fn finish_ip(ip: IpMeta, l4: &[u8]) -> Result<FrameOutcome, String> {
    if ip.fragment.is_fragment() {
        return Ok(FrameOutcome::Fragment(FragmentPiece {
            ip,
            data: l4.to_vec(),
        }));
    }
    if ip.protocol != IPPROTO_TCP {
        return Ok(FrameOutcome::Ignored);
    }
    let tcp = parse_tcp(l4, &ip)?;
    let data_offset = (tcp.data_offset as usize) * 4;
    let payload = l4.get(data_offset..).unwrap_or(&[]).to_vec();
    Ok(FrameOutcome::Complete(CompleteDatagram {
        ip,
        tcp: Some(tcp),
        payload,
    }))
}

fn parse_tcp(l4: &[u8], ip: &IpMeta) -> Result<TcpMeta, String> {
    if l4.len() < 20 {
        return Err("tcp: 首部短于 20 字节".into());
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
    let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
    let data_offset = (l4[12] >> 4) as u8;
    if (data_offset as usize) * 4 > l4.len() || data_offset < 5 {
        return Err("tcp: 非法数据偏移".into());
    }
    let flags = TcpFlags::from_byte(l4[13]);
    let window = u16::from_be_bytes([l4[14], l4[15]]);
    let checksum_ok = verify_tcp_checksum(ip, l4);
    Ok(TcpMeta {
        src_port,
        dst_port,
        seq,
        ack,
        data_offset,
        flags,
        window,
        checksum_ok,
    })
}

fn raw_sum16(data: &[u8]) -> u32 {
    let mut sum = 0u32;
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

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn pseudo_header_sum(ip: &IpMeta, l4_len: usize) -> u32 {
    let mut sum = 0u32;
    let mut push_word = |hi: u8, lo: u8| sum += u16::from_be_bytes([hi, lo]) as u32;
    match (&ip.src, &ip.dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let so = s.octets();
            let do_ = d.octets();
            for i in (0..4).step_by(2) {
                push_word(so[i], so[i + 1]);
                push_word(do_[i], do_[i + 1]);
            }
            push_word(0, IPPROTO_TCP);
            push_word((l4_len >> 8) as u8, (l4_len & 0xff) as u8);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let so = s.octets();
            let do_ = d.octets();
            for i in (0..16).step_by(2) {
                push_word(so[i], so[i + 1]);
                push_word(do_[i], do_[i + 1]);
            }
            push_word((l4_len >> 24) as u8, (l4_len >> 16) as u8);
            push_word((l4_len >> 8) as u8, (l4_len & 0xff) as u8);
            push_word(0, IPPROTO_TCP);
        }
        _ => {}
    }
    sum
}

/// 对完整 TCP 报文段（含伪首部）做校验：正确数据折叠结果为 0xffff。
pub fn verify_tcp_checksum(ip: &IpMeta, segment: &[u8]) -> bool {
    if segment.len() < 20 {
        return false;
    }
    let mut sum = pseudo_header_sum(ip, segment.len());
    sum += raw_sum16(segment);
    fold(sum) == 0xffff
}
