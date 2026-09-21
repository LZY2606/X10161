use crate::json::Value;
use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OverlapPolicy {
    FirstSeen,
    LastSeen,
}

impl OverlapPolicy {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "first-seen" | "first_seen" => Ok(Self::FirstSeen),
            "last-seen" | "last_seen" => Ok(Self::LastSeen),
            _ => Err("overlap_policy must be first-seen or last-seen".into()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FirstSeen => "first-seen",
            Self::LastSeen => "last-seen",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisConfig {
    pub overlap_policy: OverlapPolicy,
    pub tcp_timeout_ns: i64,
    pub max_ipv4_datagram: usize,
    pub max_ipv6_datagram: usize,
    pub fin_rst_race_ns: i64,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            overlap_policy: OverlapPolicy::FirstSeen,
            tcp_timeout_ns: 120_000_000_000,
            max_ipv4_datagram: 65_535,
            max_ipv6_datagram: 65_535,
            fin_rst_race_ns: 1_000_000,
        }
    }
}

impl AnalysisConfig {
    pub fn to_json(self) -> Value {
        let mut value = Value::object();
        value.put("fin_rst_race_ns", Value::from_i64(self.fin_rst_race_ns));
        value.put("max_ipv4_datagram", Value::from_usize(self.max_ipv4_datagram));
        value.put("max_ipv6_datagram", Value::from_usize(self.max_ipv6_datagram));
        value.put("overlap_policy", Value::from_string(self.overlap_policy.as_str()));
        value.put("tcp_timeout_ns", Value::from_i64(self.tcp_timeout_ns));
        value
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    pub fn to_json(&self) -> Value {
        let mut value = Value::object();
        value.put("ip", Value::from_string(self.ip.to_string()));
        value.put("port", Value::from_u64(self.port as u64));
        value
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub low: Endpoint,
    pub high: Endpoint,
}

impl FlowKey {
    pub fn new(a: Endpoint, b: Endpoint) -> Self {
        if endpoint_cmp(&a, &b) == Ordering::Less {
            Self { low: a, high: b }
        } else {
            Self { low: b, high: a }
        }
    }
}

pub fn endpoint_cmp(left: &Endpoint, right: &Endpoint) -> Ordering {
    ip_rank(left.ip)
        .cmp(&ip_rank(right.ip))
        .then_with(|| left.ip.to_string().cmp(&right.ip.to_string()))
        .then(left.port.cmp(&right.port))
}

fn ip_rank(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRecord {
    pub original_index: usize,
    pub timestamp_ns: i64,
    pub link_type: u16,
    pub frame_hash: String,
    pub length: usize,
}

#[derive(Debug, Clone)]
pub struct ReadyDatagram {
    pub event_index: usize,
    pub timestamp_ns: i64,
    pub original_index: usize,
    pub datagram_id: usize,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub protocol: u8,
    pub payload: Vec<u8>,
    pub fragmented: bool,
    pub evidence_id: usize,
}

pub fn tcp_seq_lt(left: u32, right: u32) -> bool {
    left.wrapping_sub(right) >= 0x8000_0000
}

pub fn tcp_seq_lte(left: u32, right: u32) -> bool {
    left == right || tcp_seq_lt(left, right)
}

pub fn tcp_seq_between(value: u32, left: u32, right: u32) -> bool {
    tcp_seq_lte(left, value) && tcp_seq_lt(value, right)
}

pub fn tcp_seq_forward(base: u32, absolute: u64) -> u32 {
    base.wrapping_add((absolute & 0xffff_ffff) as u32)
}

pub fn tcp_seq_distance(base: u32, value: u32) -> u64 {
    value.wrapping_sub(base) as u32 as u64
}

pub fn tcp_seq_range(start: u32, length: usize) -> Value {
    let mut value = Value::object();
    value.put("begin", Value::from_u64(start as u64));
    value.put("end", Value::from_u64(tcp_seq_forward(start, length as u64) as u64));
    value.put("length", Value::from_usize(length));
    value
}

pub fn parse_ipv4(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

pub fn parse_ipv6(bytes: &[u8]) -> Ipv6Addr {
    let mut address = [0u8; 16];
    address.copy_from_slice(bytes);
    Ipv6Addr::from(address)
}

pub fn interval_json(begin: u64, end: u64) -> Value {
    let mut value = Value::object();
    value.put("begin", Value::from_u64(begin));
    value.put("end", Value::from_u64(end));
}
