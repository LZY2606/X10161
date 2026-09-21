//! 解析中间层的数据模型。

/// 原始帧：夹具数组中的位置即原始帧序号，时间戳统一为纳秒。
#[derive(Clone, Debug)]
pub struct Frame {
    pub index: u32,
    pub ts_ns: u64,
    pub raw: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub ip: [u8; 16],
    pub port: u16,
}

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

#[derive(Clone, Debug)]
pub struct Packet {
    pub frame_index: u32,
    pub ts_ns: u64,
    pub ip_version: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: Vec<u8>,
}

pub fn v4_mapped(addr: [u8; 4]) -> [u8; 16] {
    let mut ip = [0u8; 16];
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12..16].copy_from_slice(&addr);
    ip
}

pub fn is_v4_mapped(ip: &[u8; 16]) -> bool {
    ip[0..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff
}

pub fn fmt_ip(ip: &[u8; 16]) -> String {
    if is_v4_mapped(ip) {
        format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15])
    } else {
        let mut parts = Vec::with_capacity(8);
        for i in 0..8 {
            let group = u16::from_be_bytes([ip[i * 2], ip[i * 2 + 1]]);
            parts.push(format!("{:x}", group));
        }
        parts.join(":")
    }
}

impl Endpoint {
    pub fn to_string_v(&self) -> String {
        format!("{}:{}", fmt_ip(&self.ip), self.port)
    }
}
