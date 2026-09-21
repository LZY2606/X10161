//! 项目自定义的确定性帧夹具：JSON 描述链路层帧，时间戳以微秒整数表示。
//!
//! 格式见 README。支持两种载荷写法：
//! - `hex`：十六进制原始帧（以太网/raw）
//! - `eth`：结构化字段，由 [`crate::builder`] 等价手工组帧（见 web 示例）

use crate::json::{parse, Value};
use crate::pcap::RawFrame;
use crate::reasm::InputFrame;
use crate::wire::{LINK_ETHERNET, LINK_RAW};

#[derive(Debug, Clone)]
pub struct Fixture {
    pub link_type: u32,
    pub frames: Vec<RawFrame>,
}

/// 识别上传内容是 pcap 还是夹具 JSON。
pub fn sniff(bytes: &[u8]) -> InputKind {
    if bytes.len() >= 4 {
        match &bytes[..4] {
            [0xa1, 0xb2, 0xc3, 0xd4]
            | [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d]
            | [0x4d, 0x3c, 0xb2, 0xa1] => return InputKind::Pcap,
            [0x0a, 0x0d, 0x0d, 0x0a] => return InputKind::PcapNg,
            _ => {}
        }
    }
    let head: String = bytes
        .iter()
        .take(256)
        .map(|b| *b as char)
        .filter(|c| !c.is_whitespace())
        .collect();
    if head.starts_with('{') {
        InputKind::FixtureJson
    } else {
        InputKind::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Pcap,
    PcapNg,
    FixtureJson,
    Unknown,
}

impl Fixture {
    /// 解析夹具 JSON。帧顺序数组顺序即为“原始帧序号”。
    pub fn parse(input: &str) -> Result<Fixture, String> {
        let v = parse(input)?;
        let link = match v.get("link_type").and_then(|x| x.as_str()) {
            Some("ethernet") | None => LINK_ETHERNET,
            Some("raw") | Some("rawip") => LINK_RAW,
            Some(other) => return Err(format!("fixture: 未知 link_type {}", other)),
        };
        let arr = v
            .get("frames")
            .and_then(|x| x.as_array())
            .ok_or("fixture: 缺少 frames 数组")?;

        let mut frames = Vec::with_capacity(arr.len());
        for (i, f) in arr.iter().enumerate() {
            let ts_us = timestamp_us(f).ok_or_else(|| format!("fixture: 帧 {} 缺少时间戳", i))?;
            let data = frame_bytes(f, link).map_err(|e| format!("fixture: 帧 {}: {}", i, e))?;
            frames.push(RawFrame {
                ts_us,
                orig_len: data.len() as u32,
                data,
            });
        }
        Ok(Fixture {
            link_type: link,
            frames,
        })
    }

    pub fn to_input(&self) -> Vec<InputFrame> {
        self.frames
            .iter()
            .enumerate()
            .map(|(i, f)| InputFrame {
                order: i,
                ts_us: f.ts_us,
                data: f.data.clone(),
            })
            .collect()
    }
}

fn timestamp_us(f: &Value) -> Option<i64> {
    if let Some(us) = f.get("us").and_then(|x| x.as_i64()) {
        return Some(us);
    }
    if let Some(t) = f.get("t").and_then(|x| x.as_i64()) {
        return Some(t * 1_000_000);
    }
    None
}

fn frame_bytes(f: &Value, link: u32) -> Result<Vec<u8>, String> {
    if let Some(hex_str) = f.get("hex").and_then(|x| x.as_str()) {
        return decode_hex(hex_str);
    }
    if f.get("eth").is_some() {
        return build_eth_frame(f.get("eth").unwrap(), link);
    }
    Err("需要 hex 或 eth 字段".into())
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if clean.len() % 2 != 0 {
        return Err("hex 长度为奇数".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| "非法 hex".to_string()))
        .collect()
}

/// 结构化以太网帧：{"src":"..","dst":"..","ethertype":"ipv4","payload_hex":".."}
fn build_eth_frame(eth: &Value, link: u32) -> Result<Vec<u8>, String> {
    let payload = decode_hex(
        eth.get("payload_hex")
            .and_then(|x| x.as_str())
            .unwrap_or(""),
    )?;
    if link == LINK_RAW {
        return Ok(payload);
    }
    let dst = mac(eth
        .get("dst")
        .and_then(|x| x.as_str())
        .unwrap_or("00:00:00:00:00:00"))?;
    let src = mac(eth
        .get("src")
        .and_then(|x| x.as_str())
        .unwrap_or("00:00:00:00:00:00"))?;
    let et = match eth
        .get("ethertype")
        .and_then(|x| x.as_str())
        .unwrap_or("ipv4")
    {
        "ipv4" => 0x0800u16,
        "ipv6" => 0x86ddu16,
        other => return Err(format!("未知 ethertype {}", other)),
    };
    let mut out = Vec::with_capacity(14 + payload.len());
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    out.extend_from_slice(&et.to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

fn mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("非法 MAC {}", s));
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).map_err(|_| format!("非法 MAC {}", s))?;
    }
    Ok(out)
}
