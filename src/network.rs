use crate::model::{parse_ipv4, parse_ipv6};
use std::net::IpAddr;

pub const TCP: u8 = 6;

#[derive(Debug, Clone)]
pub struct IpDatagram {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub payload: Vec<u8>,
    pub fragment: Option<FragmentInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentInfo {
    pub identification: u32,
    pub offset: usize,
    pub more_fragments: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub data_offset: usize,
    pub flags: u8,
    pub window: u16,
    pub payload: &'a [u8],
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

pub fn parse_link(frame: &[u8], link_type: u16) -> Result<IpDatagram, String> {
    match link_type {
        1 => parse_ethernet(frame),
        101 => parse_ip(frame),
        113 => parse_linux_cooked(frame),
        0 => parse_null(frame),
        _ => Err(format!("unsupported link type {link_type}")),
    }
}

fn parse_ethernet(mut frame: &[u8]) -> Result<IpDatagram, String> {
    if frame.len() < 14 {
        return Err("Ethernet frame is shorter than 14 bytes".into());
    }
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    frame = &frame[14..];
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        if frame.len() < 4 {
            return Err("truncated VLAN tag".into());
        }
        ether_type = u16::from_be_bytes([frame[2], frame[3]]);
        frame = &frame[4..];
    }
    match ether_type {
        0x0800 | 0x86dd => parse_ip_payload(frame, ether_type),
        _ => Err(format!("ignored Ethernet ether_type {ether_type:#06x}")),
    }
}

fn parse_linux_cooked(frame: &[u8]) -> Result<IpDatagram, String> {
    if frame.len() < 16 {
        return Err("Linux cooked capture header is truncated".into());
    }
    let ether_type = u16::from_be_bytes([frame[14], frame[15]]);
    parse_ip_payload(&frame[16..], ether_type)
}

fn parse_null(frame: &[u8]) -> Result<IpDatagram, String> {
    if frame.len() < 4 {
        return Err("null/Loopback frame is truncated".into());
    }
    let family_le = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let family_be = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if family_le == 2 || family_be == 2 {
        parse_ip_payload(&frame[4..], 0x0800)
    } else if family_le == 30 || family_be == 30 || family_le == 10 || family_be == 10 {
        parse_ip_payload(&frame[4..], 0x86dd)
    } else {
        Err("unsupported null/Loopback address family".into())
    }
}

fn parse_ip(frame: &[u8]) -> Result<IpDatagram, String> {
    match frame.first() {
        Some(0x40..=0x4f) => parse_ip_payload(frame, 0x0800),
        Some(0x60..=0x6f) => parse_ip_payload(frame, 0x86dd),
        _ => Err("raw IP frame has an unknown IP version".into()),
    }
}

fn parse_ip_payload(frame: &[u8], ether_type: u16) -> Result<IpDatagram, String> {
    match ether_type {
        0x0800 => parse_ipv4_datagram(frame),
        0x86dd => parse_ipv6_datagram(frame),
        _ => Err("non-IP datagram was ignored".into()),
    }
}

fn parse_ipv4_datagram(frame: &[u8]) -> Result<IpDatagram, String> {
    if frame.len() < 20 {
        return Err("IPv4 header is shorter than 20 bytes".into());
    }
    let version = frame[0] >> 4;
    let header_length = ((frame[0] & 0x0f) as usize) * 4;
    if version != 4 || header_length < 20 || frame.len() < header_length {
        return Err("IPv4 header length is invalid".into());
    }
    let total_length = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    if total_length < header_length || total_length > frame.len() {
        return Err("IPv4 total length is invalid".into());
    }
    let datagram = &frame[..total_length];
    let identification = u16::from_be_bytes([frame[4], frame[5]]) as u32;
    let flags_fragment = u16::from_be_bytes([frame[6], frame[7]]);
    let more_fragments = flags_fragment & 0x2000 != 0;
    let fragment_offset = ((flags_fragment & 0x1fff) as usize) * 8;
    let protocol = frame[9];
    let source = IpAddr::V4(parse_ipv4(&frame[12..16]));
    let destination = IpAddr::V4(parse_ipv4(&frame[16..20]));
    let payload = datagram[header_length..].to_vec();
    let fragment = if more_fragments || fragment_offset > 0 {
        Some(FragmentInfo {
            identification,
            offset: fragment_offset,
            more_fragments,
        })
    } else {
        None
    };
    Ok(IpDatagram {
        source,
        destination,
        protocol,
        payload,
        fragment,
    })
}

fn parse_ipv6_datagram(frame: &[u8]) -> Result<IpDatagram, String> {
    if frame.len() < 40 {
        return Err("IPv6 header is shorter than 40 bytes".into());
    }
    if frame[0] >> 4 != 6 {
        return Err("IPv6 version is invalid".into());
    }
    let payload_length = u16::from_be_bytes([frame[4], frame[5]]) as usize;
    if 40 + payload_length > frame.len() {
        return Err("IPv6 payload length exceeds frame".into());
    }
    let source = IpAddr::V6(parse_ipv6(&frame[8..24]));
    let destination = IpAddr::V6(parse_ipv6(&frame[24..40]));
    let mut next_header = frame[6];
    let mut cursor = 40;
    let end = 40 + payload_length;
    let mut fragment = None;
    while matches!(next_header, 0 | 43 | 44 | 60 | 51) {
        if cursor >= end {
            return Err("truncated IPv6 extension header".into());
        }
        let header_type = next_header;
        if header_type == 44 {
            if cursor + 8 > end {
                return Err("truncated IPv6 Fragment header".into());
            }
            next_header = frame[cursor];
            let offset_flags = u16::from_be_bytes([frame[cursor + 2], frame[cursor + 3]]);
            let offset = ((offset_flags >> 3) as usize) * 8;
            let more_fragments = offset_flags & 1 != 0;
            let identification = u32::from_be_bytes([
                frame[cursor + 4],
                frame[cursor + 5],
                frame[cursor + 6],
                frame[cursor + 7],
            ]);
            if more_fragments || offset > 0 {
                fragment = Some(FragmentInfo {
                    identification,
                    offset,
                    more_fragments,
                });
            }
            cursor += 8;
            break;
        }
        next_header = frame[cursor];
        let length = if header_type == 51 {
            if cursor + 2 > end {
                return Err("truncated IPv6 AH header".into());
            }
            ((frame[cursor + 1] as usize) * 4) + 2
        } else {
            if cursor + 2 > end {
                return Err("truncated IPv6 extension header".into());
            }
            ((frame[cursor + 1] as usize) + 1) * 8
        };
        if length == 0 || cursor + length > end {
            return Err("IPv6 extension header length is invalid".into());
        }
        cursor += length;
    }
    Ok(IpDatagram {
        source,
        destination,
        protocol: next_header,
        payload: frame[cursor..end].to_vec(),
        fragment,
    })
}

pub fn parse_tcp(datagram: &IpDatagram) -> Result<TcpSegment<'_>, String> {
    let payload = &datagram.payload;
    if payload.len() < 20 {
        return Err("TCP header is shorter than 20 bytes".into());
    }
    let source_port = u16::from_be_bytes([payload[0], payload[1]]);
    let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
    let sequence = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let acknowledgment = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let data_offset = ((payload[12] >> 4) as usize) * 4;
    if data_offset < 20 || data_offset > payload.len() {
        return Err("TCP data offset is invalid".into());
    }
    let flags = payload[13];
    let window = u16::from_be_bytes([payload[14], payload[15]]);
    Ok(TcpSegment {
        source: datagram.source,
        destination: datagram.destination,
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        data_offset,
        flags,
        window,
        payload: &payload[data_offset..],
    })
}
