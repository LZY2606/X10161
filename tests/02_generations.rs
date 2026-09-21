mod common;
use common::*;
use reasm::builder::{FrameBuilder, F_ACK, F_FIN, F_PSH, F_RST, F_SYN};
use reasm::seq::OverlapPolicy;

fn handshake3(b: &mut FrameBuilder, t0: i64, isn_c: u32, isn_s: u32) {
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
}

#[test]
fn four_tuple_reuse_after_fin_starts_new_generation() {
    let mut b = FrameBuilder::new();
    // 第一代：完整握手 + 双向 FIN 优雅关闭。
    handshake3(&mut b, 0, 100, 200);
    b.tcp(10_000, C, CP, S, SP, 101, 201, F_PSH | F_ACK, b"one");
    b.tcp(20_000, C, CP, S, SP, 104, 201, F_FIN | F_ACK, b"");
    b.tcp(21_000, S, SP, C, CP, 201, 105, F_FIN | F_ACK, b"");
    b.tcp(22_000, C, CP, S, SP, 105, 202, F_ACK, b"");
    // 第二代：同四元组、新 ISN，重新握手。
    handshake3(&mut b, 1_000_000, 5000, 6000);
    // handshake3 后客户端已 ACK 6001；再发数据。
    b.tcp(1_010_000, C, CP, S, SP, 5001, 6001, F_PSH | F_ACK, b"two");

    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let s = &sessions(&v)[0];
    let gens = generations(s);
    assert_eq!(gens.len(), 2, "优雅关闭后的复用应产生两代");
    assert_eq!(close_reason(&gens[0]), Some("fin"));
    assert_eq!(handshake(&gens[0]), "full");
    assert_eq!(handshake(&gens[1]), "full");
}

#[test]
fn reused_while_active_marks_reused() {
    let mut b = FrameBuilder::new();
    handshake3(&mut b, 0, 100, 200);
    b.tcp(10_000, C, CP, S, SP, 101, 201, F_PSH | F_ACK, b"old");
    // 旧连接没有 FIN/RST，直接出现新 SYN。
    b.tcp(20_000, C, CP, S, SP, 9999, 0, F_SYN, b"");
    b.tcp(21_000, S, SP, C, CP, 8888, 10000, F_SYN | F_ACK, b"");
    b.tcp(22_000, C, CP, S, SP, 10000, 8889, F_ACK, b"");

    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let gens = generations(&sessions(&v)[0]);
    assert_eq!(gens.len(), 2);
    assert_eq!(close_reason(&gens[0]), Some("reused"));
}

#[test]
fn idle_timeout_splits_generation() {
    let mut b = FrameBuilder::new();
    handshake3(&mut b, 0, 100, 200);
    b.tcp(10_000, C, CP, S, SP, 101, 201, F_ACK, b"first");
    // 超过超时（120s）后的无 SYN 数据，视为新代次 partial。
    b.tcp(
        200_000_000,
        C,
        CP,
        S,
        SP,
        5555,
        201,
        F_PSH | F_ACK,
        b"second",
    );

    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let gens = generations(&sessions(&v)[0]);
    assert_eq!(gens.len(), 2);
    assert_eq!(close_reason(&gens[0]), Some("timeout"));
    assert_eq!(handshake(&gens[1]), "partial", "无新 SYN 必须是 partial");
}

#[test]
fn mid_capture_partial_does_not_fabricate_handshake() {
    let mut b = FrameBuilder::new();
    // 直接就是带数据的 ACK/PSH，没有任何 SYN。
    b.tcp(
        0,
        C,
        CP,
        S,
        SP,
        4242,
        9001,
        F_PSH | F_ACK,
        b"mid-stream data",
    );
    b.tcp(1000, S, SP, C, CP, 9001, 4256, F_ACK, b"");
    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let gens = generations(&sessions(&v)[0]);
    assert_eq!(gens.len(), 1);
    assert_eq!(handshake(&gens[0]), "partial");
    let client_dir = "B";
    assert_eq!(delivered(&gens[0], client_dir), 15);
    // base_frame 为 0，base_seq 直接取数据段 seq。
    assert_eq!(
        dir(&gens[0], client_dir)
            .get("base_seq")
            .unwrap()
            .as_i64()
            .unwrap(),
        4242
    );
}

#[test]
fn rst_closes_generation_and_fin_rst_race_ordered() {
    let mut b = FrameBuilder::new();
    handshake3(&mut b, 0, 100, 200);
    b.tcp(10_000, C, CP, S, SP, 101, 201, F_PSH | F_ACK, b"data");
    // FIN 与 RST 相同时间戳：靠原始帧序号，FIN 先 RST 后；RST 决定结束。
    b.tcp(20_000, C, CP, S, SP, 105, 201, F_FIN | F_ACK, b"");
    b.tcp(20_000, S, SP, C, CP, 201, 106, F_RST, b"");

    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let g = &generations(&sessions(&v)[0])[0];
    assert_eq!(close_reason(g), Some("rst"));
    let events = g.get("close_events").unwrap().as_array().unwrap();
    assert_eq!(events.len(), 2, "FIN 和 RST 都应留在关单事件中");
    assert_eq!(events[0].get("frame").unwrap().as_i64(), Some(4));
    assert_eq!(events[1].get("frame").unwrap().as_i64(), Some(5));
}

#[test]
fn syn_retransmit_does_not_start_generation() {
    let mut b = FrameBuilder::new();
    b.tcp(0, C, CP, S, SP, 100, 0, F_SYN, b"");
    // 同序号 SYN 重传（相同时间戳也可，用帧序号区分）。
    b.tcp(0, C, CP, S, SP, 100, 0, F_SYN, b"");
    b.tcp(1000, S, SP, C, CP, 200, 101, F_SYN | F_ACK, b"");
    b.tcp(2000, C, CP, S, SP, 101, 201, F_ACK, b"");
    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let gens = generations(&sessions(&v)[0]);
    assert_eq!(gens.len(), 1, "SYN 重传不应产生新代次");
    assert_eq!(handshake(&gens[0]), "full");
}

#[test]
fn traffic_after_fin_without_new_syn_stays_closed_and_grouped() {
    // 严格规范：FIN 优雅关闭后出现的非 SYN 段属于异常尾巴，
    // 本实现将其放入新的 partial 代次（避免把字节写回已关闭连接）。
    let mut b = FrameBuilder::new();
    handshake3(&mut b, 0, 100, 200);
    b.tcp(10_000, C, CP, S, SP, 104, 201, F_FIN | F_ACK, b"");
    b.tcp(11_000, S, SP, C, CP, 201, 105, F_FIN | F_ACK, b"");
    b.tcp(12_000, C, CP, S, SP, 105, 202, F_ACK, b"");
    b.tcp(30_000, C, CP, S, SP, 7777, 202, F_PSH | F_ACK, b"late");
    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let gens = generations(&sessions(&v)[0]);
    assert!(gens.len() >= 2);
    assert_eq!(close_reason(&gens[0]), Some("fin"));
}
