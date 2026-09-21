#![allow(dead_code)]
use reasm_bench::analyze::{analyze, AnalysisConfig};
use reasm_bench::builder::{tcp_frame, TcpFrameSpec};
use reasm_bench::reasm::OverlapPolicy;
use reasm_bench::types::{Ip, RawFrame};

pub const CLIENT: (u8, u8, u8, u8) = (10, 0, 0, 1);
pub const SERVER: (u8, u8, u8, u8) = (10, 0, 0, 2);
pub const CP: u16 = 40000;
pub const SP: u16 = 80;

pub fn ip(quad: (u8, u8, u8, u8)) -> Ip {
    Ip::V4([quad.0, quad.1, quad.2, quad.3])
}

type Flags = (bool, bool, bool, bool);
pub const S: Flags = (true, false, false, false);
pub const SA: Flags = (true, true, false, false);
pub const A: Flags = (false, true, false, false);
pub const FA: Flags = (false, true, true, false);
pub const RA: Flags = (false, true, false, true);
pub const PA: Flags = (false, true, false, false);

pub fn spec(
    t: f64,
    seq: u32,
    ack: Option<u32>,
    flags: Flags,
    payload: &[u8],
) -> TcpFrameSpec {
    let mut s = TcpFrameSpec::new(t, ip(CLIENT), ip(SERVER), CP, SP)
        .seq(seq)
        .flags(flags.0, flags.1, flags.2, flags.3);
    if let Some(ackv) = ack {
        s = s.ack(ackv);
    }
    if !payload.is_empty() {
        s = s.payload(payload.to_vec());
    }
    s
}

pub fn from_server(t: f64, seq: u32, ack: Option<u32>, flags: Flags, payload: &[u8]) -> TcpFrameSpec {
    let mut s = TcpFrameSpec::new(t, ip(SERVER), ip(CLIENT), SP, CP)
        .seq(seq)
        .flags(flags.0, flags.1, flags.2, flags.3);
    if let Some(ackv) = ack {
        s = s.ack(ackv);
    }
    if !payload.is_empty() {
        s = s.payload(payload.to_vec());
    }
    s
}

pub fn build_frames(specs: Vec<TcpFrameSpec>) -> Vec<RawFrame> {
    specs.into_iter().map(|s| tcp_frame(&s)).collect()
}

pub fn run(frames: Vec<RawFrame>) -> reasm_bench::analyze::AnalysisResult {
    analyze(frames, AnalysisConfig::default())
}

pub fn run_policy(frames: Vec<RawFrame>, policy: OverlapPolicy) -> reasm_bench::analyze::AnalysisResult {
    analyze(
        frames,
        AnalysisConfig {
            overlap_policy: policy,
            timeout_seconds: 120.0,
        },
    )
}

pub fn handshake(t0: f64, isn_c: u32, isn_s: u32) -> Vec<TcpFrameSpec> {
    vec![
        spec(t0, isn_c, None, S, &[]),
        from_server(t0 + 0.01, isn_s, Some(isn_c.wrapping_add(1)), SA, &[]),
        spec(t0 + 0.02, isn_c, Some(isn_s.wrapping_add(1)), A, &[]),
    ]
}

pub fn graceful_fin(t0: f64, data_c: u32, data_s: u32) -> Vec<TcpFrameSpec> {
    // Client FIN, server FIN+ACK, both acknowledged.
    vec![
        spec(t0, data_c, Some(data_s), FA, &[]),
        from_server(t0 + 0.01, data_s, Some(data_c.wrapping_add(1)), FA, &[]),
        spec(t0 + 0.02, data_c.wrapping_add(1), Some(data_s.wrapping_add(1)), A, &[]),
    ]
}
