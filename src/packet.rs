//! 链路层 / IPv4 / IPv6 / TCP 元数据解析。只解析，不校验校验和（离线分析场景）。

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_IPV6_FRAG: u8 = 44;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum NetAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl fmt::Display for NetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetAddr::V4(o) => write!(f, "{}.{}.{}.{}", o[0], o[1], o[2], o[3]),
            NetAddr::V6(o) => write!(f, "{}", std::net::Ipv6Addr::from(*o)),
        }
    }
}

impl Serialize for NetAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NetAddr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
            return Ok(NetAddr::V4(v4.octets()));
        }
        if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
            return Ok(NetAddr::V6(v6.octets()));
        }
        Err(serde::de::Error::custom(format!("bad ip addr: {s}")))
    }
}

/// 帧的链路层类型。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkType {
    Ethernet,
    Raw,
}

/// IP 分片信息（IPv4 分片或 IPv6 分片头）。
#[derive(Clone, Copy, Debug)]
pub struct FragInfo {
    pub id: u32,
    pub offset_bytes: usize,
    pub more: bool,
}

/// 解析后的 IP 数据报（或分片）。
#[derive(Debug)]
pub struct IpPacket<'a> {
    pub src: NetAddr,
    pub dst: NetAddr,
    /// 上层协议号（分片时为分片载荷的协议）。
    pub proto: u8,
    pub frag: Option<FragInfo>,
    pub payload: &'a [u8],
}

/// 解析后的 TCP 段元数据。
#[derive(Debug)]
pub struct TcpSegmentMeta<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parse error: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

fn err<T>(msg: &str) -> Result<T, ParseError> {
    Err(ParseError(msg.to_string()))
}

/// 从链路层帧解析出 IP 数据报。
pub fn parse_link(link: LinkType, data: &[u8]) -> Result<Option<IpPacket<'_>>, ParseError> {
    match link {
        LinkType::Ethernet => {
            if data.len() < 14 {
                return err("short ethernet frame");
            }
            let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
            let mut off = 14;
            // 跳过一层 VLAN 标签。
            if ethertype == 0x8100 && data.len() >= 18 {
                ethertype = u16::from_be_bytes([data[16], data[17]]);
                off = 18;
            }
            match ethertype {
                0x0800 => parse_ipv4(&data[off..]).map(Some),
                0x86DD => parse_ipv6(&data[off..]).map(Some),
                _ => Ok(None), // 非 IP 流量，忽略
            }
        }
        LinkType::Raw => {
            if data.is_empty() {
                return err("empty raw frame");
            }
            match data[0] >> 4 {
                4 => parse_ipv4(data).map(Some),
                6 => parse_ipv6(data).map(Some),
                _ => err("raw frame is not ip"),
            }
        }
    }
}

pub fn parse_ipv4(data: &[u8]) -> Result<IpPacket<'_>, ParseError> {
    if data.len() < 20 {
        return err("short ipv4 header");
    }
    let ihl = ((data[0] & 0x0F) as usize) * 4;
    if ihl < 20 || data.len() < ihl {
        return err("bad ipv4 ihl");
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_len < ihl || data.len() < total_len {
        return err("bad ipv4 total length");
    }
    let id = u16::from_be_bytes([data[4], data[5]]);
    let frag_field = u16::from_be_bytes([data[6], data[7]]);
    let more = frag_field & 0x2000 != 0;
    let frag_off_units = frag_field & 0x1FFF;
    let proto = data[9];
    let src = NetAddr::V4([data[12], data[13], data[14], data[15]]);
    let dst = NetAddr::V4([data[16], data[17], data[18], data[19]]);
    let frag = if more || frag_off_units != 0 {
        Some(FragInfo {
            id: id as u32,
            offset_bytes: frag_off_units as usize * 8,
            more,
        })
    } else {
        None
    };
    Ok(IpPacket {
        src,
        dst,
        proto,
        frag,
        payload: &data[ihl..total_len],
    })
}

pub fn parse_ipv6(data: &[u8]) -> Result<IpPacket<'_>, ParseError> {
    if data.len() < 40 {
        return err("short ipv6 header");
    }
    if data[0] >> 4 != 6 {
        return err("not ipv6");
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    if data.len() < 40 + payload_len {
        return err("bad ipv6 payload length");
    }
    let next_header = data[6];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);
    let body = &data[40..40 + payload_len];
    if next_header == IP_PROTO_IPV6_FRAG {
        if body.len() < 8 {
            return err("short ipv6 fragment header");
        }
        let upper_proto = body[0];
        let offlg = u16::from_be_bytes([body[2], body[3]]);
        let offset_bytes = ((offlg >> 3) as usize) * 8;
        let more = offlg & 1 != 0;
        let id = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        return Ok(IpPacket {
            src: NetAddr::V6(src),
            dst: NetAddr::V6(dst),
            proto: upper_proto,
            frag: Some(FragInfo {
                id,
                offset_bytes,
                more,
            }),
            payload: &body[8..],
        });
    }
    Ok(IpPacket {
        src: NetAddr::V6(src),
        dst: NetAddr::V6(dst),
        proto: next_header,
        frag: None,
        payload: body,
    })
}

/// 解析 TCP 段（输入为 IP 载荷）。
pub fn parse_tcp(data: &[u8]) -> Result<TcpSegmentMeta<'_>, ParseError> {
    if data.len() < 20 {
        return err("short tcp header");
    }
    let data_offset = ((data[12] >> 4) as usize) * 4;
    if data_offset < 20 || data.len() < data_offset {
        return err("bad tcp data offset");
    }
    Ok(TcpSegmentMeta {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        seq: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        ack: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        flags: data[13] & 0x3F,
        payload: &data[data_offset..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netaddr_roundtrip() {
        let a = NetAddr::V4([10, 0, 0, 1]);
        let s = serde_json::to_string(&a).unwrap();
        assert_eq!(s, "\"10.0.0.1\"");
        let b: NetAddr = serde_json::from_str(&s).unwrap();
        assert_eq!(a, b);
        let v6 = NetAddr::V6([0u8; 16]);
        let s6 = serde_json::to_string(&v6).unwrap();
        let b6: NetAddr = serde_json::from_str(&s6).unwrap();
        assert_eq!(v6, b6);
    }
}
