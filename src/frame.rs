use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One captured frame. `index` is the original frame number in the capture
/// and is the tie-breaker for identical timestamps.
#[derive(Clone, Debug)]
pub struct Frame {
    pub index: u64,
    pub ts_ns: i64,
    pub raw: Vec<u8>,
    pub hash: String,
}

impl Frame {
    pub fn new(index: u64, ts_ns: i64, raw: Vec<u8>) -> Self {
        let hash = sha256_hex(&raw);
        Frame { index, ts_ns, raw, hash }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkType {
    Ethernet,
    LinuxSll,
    Raw,
}

impl LinkType {
    pub fn as_str(&self) -> &'static str {
        match self {
            LinkType::Ethernet => "ethernet",
            LinkType::LinuxSll => "linux_sll",
            LinkType::Raw => "raw",
        }
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
