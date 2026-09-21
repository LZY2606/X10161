mod common;
use common::*;
use reasm::builder::{FrameBuilder, F_ACK, F_PSH, F_SYN};
use reasm::json::canonical;
use reasm::seq::OverlapPolicy;

#[test]
fn in_order_full_handshake_reassembles() {
    let mut b = FrameBuilder::new();
    established_stream(&mut b, 0, 100, 200, &[b"hello ", b"world"]);
    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let s = &sessions(&v)[0];
    let gens = generations(s);
    assert_eq!(gens.len(), 1);
    let g = &gens[0];
    assert_eq!(handshake(g), "full");
    // 规范化端点 A=服务端(192.168.1.1:443)，B=客户端(192.168.1.10:50000)。
    let client_dir = "B";
    assert_eq!(delivered(g, client_dir), 11);
}

#[test]
fn sequence_wrap_reassembles() {
    // ISN=0xffff_fff8：SYN 占 1，数据从 fff9 起，8 字节跨 0，next 环回为 1。
    let mut b = FrameBuilder::new();
    let isn = 0xffff_fff8u32;
    established_stream(&mut b, 0, isn, 900, &[b"ABCDEFGH"]);
    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let g = &generations(&sessions(&v)[0])[0];
    let client_dir = "B";
    assert_eq!(delivered(g, client_dir), 8);
    let observed = dir(g, client_dir).get("observed").unwrap();
    assert_eq!(observed.get("next_max").unwrap().as_i64().unwrap(), 1);
    assert_eq!(
        observed.get("seq_min").unwrap().as_i64(),
        Some(0xffff_fff8i64)
    );
}

#[test]
fn out_of_order_and_gap_then_fill() {
    let mut b = FrameBuilder::new();
    let isn = 1000u32;
    b.tcp(0, C, CP, S, SP, isn, 0, F_SYN, b"");
    b.tcp(
        1000,
        S,
        SP,
        C,
        CP,
        5000,
        isn.wrapping_add(1),
        F_SYN | F_ACK,
        b"",
    );
    b.tcp(2000, C, CP, S, SP, isn.wrapping_add(1), 5001, F_ACK, b"");
    // 先到高序号段，制造缺口。
    b.tcp(
        10_000,
        C,
        CP,
        S,
        SP,
        isn.wrapping_add(11),
        5001,
        F_ACK,
        b"KK",
    );
    // 确认缺口期间 delivered 仍为 0 的情形在乱序瞬时无法观察（批处理），
    // 但最终补缺后应完全重组。
    b.tcp(
        11_000,
        C,
        CP,
        S,
        SP,
        isn.wrapping_add(1),
        5001,
        F_PSH | F_ACK,
        b"0123456789",
    );
    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let g = &generations(&sessions(&v)[0])[0];
    let client_dir = "B"; // 客户端 IP 192.168.1.10 > 服务端 192.168.1.1，规范化为 B
    assert_eq!(delivered(g, client_dir), 12);
    assert!(gaps(g, client_dir).is_empty());
    // 乱序段必须被标记。
    let oo = bools(g, client_dir, "out_of_order");
    assert!(oo.iter().any(|x| *x), "应至少有一个乱序标记: {:?}", oo);
}

#[test]
fn persistent_gap_remains_and_prefix_stops() {
    let mut b = FrameBuilder::new();
    let isn = 1000u32;
    b.tcp(0, C, CP, S, SP, isn, 0, F_SYN, b"");
    b.tcp(
        1000,
        S,
        SP,
        C,
        CP,
        5000,
        isn.wrapping_add(1),
        F_SYN | F_ACK,
        b"",
    );
    b.tcp(2000, C, CP, S, SP, isn.wrapping_add(1), 5001, F_ACK, b"");
    b.tcp(
        10_000,
        C,
        CP,
        S,
        SP,
        isn.wrapping_add(1),
        5001,
        F_ACK,
        b"ab",
    );
    // 缺失 [2,6)
    b.tcp(
        11_000,
        C,
        CP,
        S,
        SP,
        isn.wrapping_add(7),
        5001,
        F_ACK,
        b"yz",
    );
    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let g = &generations(&sessions(&v)[0])[0];
    let client_dir = "B"; // 客户端 IP 192.168.1.10 > 服务端 192.168.1.1，规范化为 B
    assert_eq!(delivered(g, client_dir), 2);
    assert_eq!(gaps(g, client_dir), vec![(2, 6)]);
    // 缺口之后的字节仍留在覆盖证据中（total_seen_bytes = 4）。
    assert_eq!(
        dir(g, client_dir)
            .get("total_seen_bytes")
            .unwrap()
            .as_i64()
            .unwrap(),
        4
    );
}

#[test]
fn overlap_policies_first_vs_last() {
    fn run(policy: OverlapPolicy) -> String {
        let mut b = FrameBuilder::new();
        let isn = 1000u32;
        b.tcp(0, C, CP, S, SP, isn, 0, F_SYN, b"");
        b.tcp(
            1000,
            S,
            SP,
            C,
            CP,
            5000,
            isn.wrapping_add(1),
            F_SYN | F_ACK,
            b"",
        );
        b.tcp(2000, C, CP, S, SP, isn.wrapping_add(1), 5001, F_ACK, b"");
        b.tcp(
            10_000,
            C,
            CP,
            S,
            SP,
            isn.wrapping_add(1),
            5001,
            F_ACK,
            b"AAAA",
        );
        // 覆盖后两个字节为 XX。
        b.tcp(
            11_000,
            C,
            CP,
            S,
            SP,
            isn.wrapping_add(3),
            5001,
            F_ACK,
            b"XX",
        );
        let v = analyze(b, policy, 120_000);
        canonical(&v)
    }
    let f = run(OverlapPolicy::FirstSeen);
    let l = run(OverlapPolicy::LastSeen);
    assert_ne!(f, l, "两种策略指纹必须不同");
    assert!(f.contains("false"), "first-seen 中 replaced 应为 false");
    assert!(l.contains("true"), "last-seen 中 replaced 应为 true");
}
