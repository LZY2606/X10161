//! 项目自定义的确定性帧夹具（JSON）。
//!
//! ```json
//! { "format": "pwgsb-fixture/1",
//!   "frames": [ {"ts_ns": 1000, "raw": "hex..."}, ... ] }
//! ```
//! 帧在数组中的位置就是原始帧序号；相同时间戳排序依赖它。

use crate::json::Value;
use crate::model::Frame;
use crate::util::{hex_decode, hex_encode};

pub const FORMAT: &str = "pwgsb-fixture/1";

#[derive(Debug)]
pub struct FixtureError(pub String);

impl std::fmt::Display for FixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fixture error: {}", self.0)
    }
}

pub fn parse_fixture(input: &str) -> Result<Vec<Frame>, FixtureError> {
    let value = Value::parse(input).map_err(FixtureError)?;
    let format = value
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or(FORMAT);
    if format != FORMAT {
        return Err(FixtureError(format!("unsupported format: {}", format)));
    }
    let arr = value
        .get("frames")
        .and_then(|v| v.as_array())
        .ok_or_else(|| FixtureError("missing frames array".into()))?;

    let mut frames = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let ts_ns = item
            .get("ts_ns")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| FixtureError(format!("frame {} missing ts_ns", i)))?;
        let raw_hex = item
            .get("raw")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FixtureError(format!("frame {} missing raw hex", i)))?;
        let raw =
            hex_decode(raw_hex).map_err(|e| FixtureError(format!("frame {} bad hex: {}", i, e)))?;
        frames.push(Frame {
            index: i as u32,
            ts_ns,
            raw,
        });
    }
    Ok(frames)
}

pub fn build_fixture(frames: &[Frame]) -> String {
    let mut out = Value::obj();
    out.set("format", Value::Str(FORMAT.into()));
    let arr = frames
        .iter()
        .map(|f| {
            let mut o = Value::obj();
            o.set("ts_ns", Value::Int(f.ts_ns as i128));
            o.set("raw", Value::Str(hex_encode(&f.raw)));
            o
        })
        .collect();
    out.set("frames", Value::Arr(arr));
    let mut text = out.serialize();
    text.push('\n');
    text
}

/// 输入可能是经典 pcap（魔数开头），否则按 JSON 夹具处理。
pub fn parse_any(data: &[u8]) -> Result<Vec<Frame>, String> {
    if crate::pcap::looks_like_pcap(data) {
        crate::pcap::parse_pcap(data)
    } else {
        let text = std::str::from_utf8(data).map_err(|e| format!("invalid utf8: {}", e))?;
        parse_fixture(text).map_err(|e| e.0)
    }
}
