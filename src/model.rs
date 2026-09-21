//! 全流水线共享的数据模型与配置。

use std::net::IpAddr;

/// 重叠片段合并策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapPolicy {
    /// 先到片段保留，后到重叠字节被记录为覆盖证据但不参与重组
    FirstSeen,
    /// 后到片段覆盖先到内容，被覆盖字节仍保留在证据中
    LastSeen,
}

impl OverlapPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            OverlapPolicy::FirstSeen => "first-seen",
            OverlapPolicy::LastSeen => "last-seen",
        }
    }

    pub fn parse(s: &str) -> Result<OverlapPolicy, String> {
        match s {
            "first-seen" => Ok(OverlapPolicy::FirstSeen),
            "last-seen" => Ok(OverlapPolicy::LastSeen),
            other => Err(format!("未知重叠策略: {}（可选 first-seen / last-seen）", other)),
        }
    }
}

/// 分析配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzeConfig {
    pub overlap: OverlapPolicy,
    /// 任意方向超过该纳秒数没有新数据即判定代次结束
    pub timeout_ns: i64,
    /// 单个 IP 数据报允许的最大重组字节数
    pub datagram_budget: usize,
}

impl Default for AnalyzeConfig {
    fn default() -> Self {
        AnalyzeConfig {
            overlap: OverlapPolicy::FirstSeen,
            timeout_ns: 2_000_000_000,
            datagram_budget: 65_535,
        }
    }
}

/// 抓包中的原始帧（链路层起始）。
#[derive(Debug, Clone)]
pub struct RawFrame {
    /// 原始帧序号：抓包文件中的顺序，从 1 开始
    pub frame_no: u64,
    /// 纳秒时间戳
    pub ts_ns: i64,
    /// 原始字节（内容寻址后落盘）
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_no: u64,
    pub ts_ns: i64,
    pub bytes: Vec<u8>,
    pub sha: String,
}

/// 解析阶段的提示或错误（不致命，不影响其他帧/会话）。
#[derive(Debug, Clone)]
pub struct ParseNote {
    pub frame_no: u64,
    pub stage: String,
    pub level: String,
    pub message: String,
}

/// 从（可能已分片重组的）IP 数据报中取出的 TCP 段。
#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
    pub data_offset_words: usize,
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

#[derive(Debug, Clone)]
pub enum L4 {
    Tcp(TcpSegment),
    Other(u8),
}

/// 已重组的 IP 数据报（未分片时直接来自单帧）。
#[derive(Debug, Clone)]
pub struct Datagram {
    pub first_frame_no: u64,
    pub frame_nos: Vec<u64>,
    pub ts_ns: i64,
    pub version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub l4: L4,
    pub fragmented: bool,
}

/// 因分片重叠或超预算而被整体隔离的 IP 数据报。
#[derive(Debug, Clone)]
pub struct Quarantine {
    pub key: String,
    pub reason: String,
    pub frame_nos: Vec<u64>,
    pub ts_ns: i64,
    pub observed_len: usize,
    pub budget: usize,
}

pub fn flags_string(flags: u8) -> String {
    let mut s = String::new();
    if flags & TCP_FIN != 0 {
        s.push('F');
    }
    if flags & TCP_SYN != 0 {
        s.push('S');
    }
    if flags & TCP_RST != 0 {
        s.push('R');
    }
    if flags & TCP_PSH != 0 {
        s.push('P');
    }
    if flags & TCP_ACK != 0 {
        s.push('A');
    }
    if s.is_empty() {
        s.push('.');
    }
    s
}
