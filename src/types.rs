//! Shared value types and input frames.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// IPv4 or IPv6 address, stored canonically and sorted deterministically.
#[derive(Clone, Eq, PartialEq, Hash)]
pub enum Ip {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl PartialOrd for Ip {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ip {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Ip::V4(a), Ip::V4(b)) => a.cmp(b),
            (Ip::V6(a), Ip::V6(b)) => a.cmp(b),
            // IPv4 sorts before IPv6 so the ordering is total and stable.
            (Ip::V4(_), Ip::V6(_)) => Ordering::Less,
            (Ip::V6(_), Ip::V4(_)) => Ordering::Greater,
        }
    }
}

impl fmt::Display for Ip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ip::V4(a) => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Ip::V6(a) => {
                // RFC 5952 canonical textual form.
                let words: Vec<u16> = (0..8).map(|i| u16::from_be_bytes([a[i * 2], a[i * 2 + 1]])).collect();
                // Longest run of zeros (length >= 2) is compressed, first on tie.
                let mut best_start = None;
                let mut best_len = 1usize;
                let mut i = 0;
                while i < 8 {
                    if words[i] == 0 {
                        let start = i;
                        while i < 8 && words[i] == 0 {
                            i += 1;
                        }
                        let len = i - start;
                        if len > best_len {
                            best_len = len;
                            best_start = Some(start);
                        }
                    } else {
                        i += 1;
                    }
                }
                match best_start {
                    None => {
                        let parts: Vec<String> = words.iter().map(|w| format!("{w:x}")).collect();
                        write!(f, "{}", parts.join(":"))
                    }
                    Some(start) => {
                        let end = start + best_len;
                        let left: Vec<String> = words[..start].iter().map(|w| format!("{w:x}")).collect();
                        let right: Vec<String> = words[end..].iter().map(|w| format!("{w:x}")).collect();
                        write!(f, "{}::{}", left.join(":"), right.join(":"))
                    }
                }
            }
        }
    }
}

impl fmt::Debug for Ip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Serialize for Ip {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Ip {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl FromStr for Ip {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(':') {
            parse_v6(s)
        } else {
            parse_v4(s)
        }
    }
}

fn parse_v4(s: &str) -> Result<Ip, String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("invalid IPv4 address: {s}"));
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse::<u8>().map_err(|_| format!("invalid IPv4 octet: {p}"))?;
    }
    Ok(Ip::V4(out))
}

fn parse_v6(s: &str) -> Result<Ip, String> {
    let double = s.find("::");
    let mut groups: Vec<u16> = Vec::new();
    if let Some(pos) = double {
        if s[pos + 2..].contains("::") {
            return Err(format!("multiple :: in IPv6 address: {s}"));
        }
        let head = &s[..pos];
        let tail = &s[pos + 2..];
        let head_groups = if head.is_empty() {
            Vec::new()
        } else {
            parse_v6_groups(head)?
        };
        let tail_groups = if tail.is_empty() {
            Vec::new()
        } else {
            parse_v6_groups(tail)?
        };
        if head_groups.len() + tail_groups.len() > 6 {
            return Err(format!("too many IPv6 groups: {s}"));
        }
        let zeros = 8 - head_groups.len() - tail_groups.len();
        groups.extend(head_groups);
        groups.extend(std::iter::repeat(0).take(zeros));
        groups.extend(tail_groups);
    } else {
        groups = parse_v6_groups(s)?;
        if groups.len() != 8 {
            return Err(format!("invalid IPv6 address: {s}"));
        }
    }
    if groups.len() != 8 {
        return Err(format!("invalid IPv6 address: {s}"));
    }
    let mut out = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        out[i * 2..i * 2 + 2].copy_from_slice(&g.to_be_bytes());
    }
    Ok(Ip::V6(out))
}

fn parse_v6_groups(s: &str) -> Result<Vec<u16>, String> {
    s.split(':')
        .map(|g| {
            if g.is_empty() {
                return Err("empty IPv6 group".to_string());
            }
            u16::from_str_radix(g, 16).map_err(|_| format!("invalid IPv6 group: {g}"))
        })
        .collect()
}

/// One endpoint: IP plus port.
#[derive(Clone, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: Ip,
    pub port: u16,
}

impl Endpoint {
    pub fn new(ip: Ip, port: u16) -> Self {
        Endpoint { ip, port }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.ip {
            Ip::V4(_) => write!(f, "{}:{}", self.ip, self.port),
            Ip::V6(_) => write!(f, "[{}]:{}", self.ip, self.port),
        }
    }
}

/// Link layer hint used by custom fixtures and pcap linktypes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Ethernet,
    Ipv4Raw,
    Ipv6Raw,
    Null,
    LinuxSll,
    /// pcap linktype 101: payload begins directly with an IPv4/IPv6 header.
    Raw,
}

impl Default for LinkKind {
    fn default() -> Self {
        LinkKind::Ethernet
    }
}

/// One captured frame as ingested. `index` is optional in fixtures and assigned
/// when absent; it is the tie-breaker whenever timestamps are identical.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawFrame {
    #[serde(default)]
    pub index: Option<usize>,
    pub timestamp: f64,
    pub link: LinkKind,
    /// Hex-encoded raw link-layer frame.
    pub bytes_hex: String,
    #[serde(default)]
    pub comment: Option<String>,
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err("hex input has odd length".to_string());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| "invalid hex digit".to_string()))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    crate::hash::hex(bytes)
}
