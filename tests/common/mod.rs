#![allow(dead_code)]
use reasm::builder::FrameBuilder;
use reasm::json::Value;
use reasm::pcap::RawFrame;
use reasm::reasm::{AnalyzeConfig, Analyzer, InputFrame};
use reasm::seq::OverlapPolicy;
use reasm::wire::LINK_ETHERNET;

pub const C: &str = "192.168.1.10";
pub const S: &str = "192.168.1.1";
pub const CP: u16 = 50000;
pub const SP: u16 = 443;

pub fn inputs(frames: Vec<RawFrame>) -> Vec<InputFrame> {
    frames
        .iter()
        .enumerate()
        .map(|(i, f)| InputFrame {
            order: i,
            ts_us: f.ts_us,
            data: f.data.clone(),
        })
        .collect()
}

pub fn analyze(b: FrameBuilder, overlap: OverlapPolicy, timeout_ms: i64) -> Value {
    let frames = b.into_raw();
    let inputs = inputs(frames);
    let cfg = AnalyzeConfig {
        overlap,
        idle_timeout_us: timeout_ms * 1000,
        ..AnalyzeConfig::default()
    };
    Analyzer::new(cfg).run(&inputs, LINK_ETHERNET).result
}

pub fn sessions(v: &Value) -> &Vec<Value> {
    v.get("sessions").unwrap().as_array().unwrap()
}

pub fn generations<'a>(sess: &'a Value) -> &'a Vec<Value> {
    sess.get("generations").unwrap().as_array().unwrap()
}

pub fn dir<'a>(gen: &'a Value, d: &str) -> &'a Value {
    gen.get("directions").unwrap().get(d).unwrap()
}

pub fn handshake(gen: &Value) -> &str {
    gen.get("handshake").unwrap().as_str().unwrap()
}

pub fn close_reason(gen: &Value) -> Option<&str> {
    gen.get("close")
        .and_then(|c| c.get("reason"))
        .and_then(|r| r.as_str())
}

pub fn segs<'a>(gen: &'a Value, d: &str) -> &'a Vec<Value> {
    dir(gen, d).get("segments").unwrap().as_array().unwrap()
}

pub fn seg_flag_count(gen: &Value, d: &str) -> Vec<String> {
    segs(gen, d)
        .iter()
        .map(|s| s.get("flags").unwrap().as_str().unwrap().to_string())
        .collect()
}

pub fn bools(gen: &Value, d: &str, key: &str) -> Vec<bool> {
    segs(gen, d)
        .iter()
        .map(|s| s.get(key).unwrap() == &Value::Bool(true))
        .collect()
}

pub fn gaps(gen: &Value, d: &str) -> Vec<(i64, i64)> {
    dir(gen, d)
        .get("gaps")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|g| {
            (
                g.get("start").unwrap().as_i64().unwrap(),
                g.get("end").unwrap().as_i64().unwrap(),
            )
        })
        .collect()
}

pub fn delivered(gen: &Value, d: &str) -> i64 {
    dir(gen, d)
        .get("delivered_length")
        .unwrap()
        .as_i64()
        .unwrap()
}

/// 完整三次握手 + 双方少量数据（从 ISN 100 / 200 开始）。
pub fn established_stream(
    b: &mut FrameBuilder,
    t0: i64,
    isn_c: u32,
    isn_s: u32,
    payloads_c: &[&[u8]],
) {
    use reasm::builder::{F_ACK, F_PSH, F_SYN};
    b.tcp(t0, C, CP, S, SP, isn_c, 0, F_SYN, b"");
    b.tcp(
        t0 + 1000,
        S,
        SP,
        C,
        CP,
        isn_s,
        isn_c.wrapping_add(1),
        F_SYN | F_ACK,
        b"",
    );
    b.tcp(
        t0 + 2000,
        C,
        CP,
        S,
        SP,
        isn_c.wrapping_add(1),
        isn_s.wrapping_add(1),
        F_ACK,
        b"",
    );
    let mut seq = isn_c.wrapping_add(1);
    let mut t = t0 + 10_000;
    for p in payloads_c {
        b.tcp(
            t,
            C,
            CP,
            S,
            SP,
            seq,
            isn_s.wrapping_add(1),
            F_PSH | F_ACK,
            p,
        );
        seq = seq.wrapping_add(p.len() as u32);
        t += 10_000;
    }
}
