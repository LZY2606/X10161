mod common;
use common::*;
use reasm::builder::{FrameBuilder, F_ACK, F_PSH, F_RST, F_SYN};
use reasm::seq::OverlapPolicy;

fn analyze_v6(b: FrameBuilder) -> reasm::json::Value {
    let frames = b.into_raw();
    let inputs: Vec<_> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| reasm::reasm::InputFrame {
            order: i,
            ts_us: f.ts_us,
            data: f.data.clone(),
        })
        .collect();
    let cfg = reasm::reasm::AnalyzeConfig {
        overlap: OverlapPolicy::FirstSeen,
        idle_timeout_us: 120_000_000,
        ..Default::default()
    };
    reasm::reasm::Analyzer::new(cfg)
        .run(&inputs, reasm::wire::LINK_ETHERNET)
        .result
}

#[test]
fn ipv6_session_reassembles() {
    let mut b = FrameBuilder::ipv6();
    let c6 = "2001:db8::1";
    let s6 = "2001:db8::2";
    let isn = 300u32;
    b.tcp(0, c6, CP, s6, SP, isn, 0, F_SYN, b"");
    b.tcp(
        1000,
        s6,
        SP,
        c6,
        CP,
        700,
        isn.wrapping_add(1),
        F_SYN | F_ACK,
        b"",
    );
    b.tcp(2000, c6, CP, s6, SP, isn.wrapping_add(1), 701, F_ACK, b"");
    b.tcp(
        3000,
        c6,
        CP,
        s6,
        SP,
        isn.wrapping_add(1),
        701,
        F_PSH | F_ACK,
        b"ipv6-data",
    );
    let v = analyze_v6(b);
    let g = &generations(&sessions(&v)[0])[0];
    assert_eq!(handshake(g), "full");
    // 2001:db8::1 < 2001:db8::2，客户端方向 A。
    assert_eq!(delivered(g, "A"), 9);
}

#[test]
fn sample_fixture_has_all_featured_artifacts() {
    let json = reasm::sample::fixture_json();
    let txt = reasm::json::pretty(&json);
    let tmp = format!("target/test-sample-{}", std::process::id());
    std::fs::create_dir_all(&tmp).unwrap();
    let store = reasm::store::Store::open(&tmp).unwrap();
    let cap = store.import_bytes(txt.as_bytes()).unwrap();
    let a = store
        .analyze(&cap.capture_id, OverlapPolicy::FirstSeen, 120_000_000)
        .unwrap();
    let ev = parse_ev(&store, &a.analysis_id);
    let sess = &ev.get("sessions").unwrap().as_array().unwrap()[0];
    let gen = &sess.get("generations").unwrap().as_array().unwrap()[0];
    assert_eq!(handshake(gen), "full");
    // 客户端 10.0.0.1 < 服务端 10.0.0.2，方向 A：15 字节。
    assert_eq!(delivered(gen, "A"), 15);
    let flags: Vec<String> = segs(gen, "A")
        .iter()
        .map(|s| s.get("flags").unwrap().as_str().unwrap().to_string())
        .collect();
    assert!(flags.iter().any(|f| f.contains("FIN")));
    // 至少一处碰撞证据（重叠段 XX vs AA）。
    let has_collision = segs(gen, "A").iter().any(|s| {
        s.get("collisions")
            .and_then(|c| c.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    });
    assert!(has_collision, "示例应包含字节碰撞证据");
    // 重传标记存在。
    assert!(bools(gen, "A", "retransmit").iter().any(|x| *x));
}

fn parse_ev(store: &reasm::store::Store, id: &str) -> reasm::json::Value {
    reasm::json::parse(&store.read_evidence(id).unwrap()).unwrap()
}

#[test]
fn rst_then_reuse_two_generations() {
    let mut b = FrameBuilder::new();
    // g1 被 RST 中断。
    b.tcp(0, C, CP, S, SP, 100, 0, F_SYN, b"");
    b.tcp(1000, S, SP, C, CP, 200, 101, F_SYN | F_ACK, b"");
    b.tcp(2000, C, CP, S, SP, 101, 201, F_ACK, b"");
    b.tcp(3000, C, CP, S, SP, 101, 201, F_PSH | F_ACK, b"abc");
    b.tcp(4000, S, SP, C, CP, 201, 104, F_RST, b"");
    // g2 同四元组重新握手。
    b.tcp(500_000, C, CP, S, SP, 400, 0, F_SYN, b"");
    b.tcp(501_000, S, SP, C, CP, 800, 401, F_SYN | F_ACK, b"");
    b.tcp(502_000, C, CP, S, SP, 401, 801, F_ACK, b"");
    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let gens = generations(&sessions(&v)[0]);
    assert_eq!(gens.len(), 2);
    assert_eq!(close_reason(&gens[0]), Some("rst"));
    assert_eq!(handshake(&gens[1]), "full");
}

#[test]
fn http_health_and_index_served() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    let dir = format!("target/test-http-{}", std::process::id());
    std::fs::create_dir_all(&dir).unwrap();
    let addr = "127.0.0.1:52351".to_string();
    let a2 = addr.clone();
    let d2 = dir.clone();
    let _ = thread::spawn(move || {
        let _ = reasm::server::serve(&a2, &d2);
    });
    thread::sleep(Duration::from_millis(250));

    let get = |path: &str| -> (u16, String) {
        let mut s = TcpStream::connect(("127.0.0.1", 52351)).unwrap();
        s.write_all(format!("GET {} HTTP/1.0\r\nHost: x\r\n\r\n", path).as_bytes())
            .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf).to_string();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|x| x.parse().ok())
            .unwrap_or(0);
        (status, text)
    };

    let (sc, index) = get("/");
    assert_eq!(sc, 200);
    assert!(index.contains("网络会话重组台"), "首页必须包含标题");
    let (hc, health) = get("/api/health");
    assert_eq!(hc, 200);
    assert!(health.contains("网络会话重组台"));
    let (sc2, sample) = get("/api/sample");
    assert_eq!(sc2, 200);
    assert!(sample.contains("reasm-fixture"));
}

#[test]
fn unknown_input_is_rejected_not_crash() {
    let dir = format!("target/test-bad-{}", std::process::id());
    std::fs::create_dir_all(&dir).unwrap();
    let store = reasm::store::Store::open(&dir).unwrap();
    let r = store.import_bytes(b"this is not pcap or json at all <<<");
    assert!(r.is_err());
}
