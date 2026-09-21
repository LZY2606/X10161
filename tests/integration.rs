//! 构造器场景测试：序号环绕、重传、乱序、缺口、四元组复用、中途抓取、
//! FIN/RST 竞态、IPv4 分片重叠隔离、相同时间戳，以及导入导出指纹一致性。

use pwgsb::analyze::analyze;
use pwgsb::builder::*;
use pwgsb::fixture;
use pwgsb::model::Frame;
use pwgsb::session::{Params, Policy};
use pwgsb::store::Store;

const C: [u8; 4] = [10, 0, 0, 1];
const S: [u8; 4] = [10, 0, 0, 2];
const CP: u16 = 1000;
const SP: u16 = 80;

fn f(ts: u64, raw: Vec<u8>) -> Frame {
    frame(ts, raw)
}

fn run(frames: Vec<Frame>, policy: Policy) -> pwgsb::analyze::BuiltAnalysis {
    run_to(frames, Params {
        policy,
        timeout_ns: 120_000_000_000,
        frag: Default::default(),
    })
}

fn run_to(frames: Vec<Frame>, params: Params) -> pwgsb::analyze::BuiltAnalysis {
    analyze("test-corpus", &frames, params)
}

fn dir0_stream(a: &pwgsb::analyze::BuiltAnalysis, sid: usize) -> &Vec<u8> {
    a.streams
        .iter()
        .find(|(s, d, _)| *s == sid && *d == 0)
        .map(|(_, _, b)| b)
        .unwrap()
}

fn session<'a>(a: &'a pwgsb::analyze::BuiltAnalysis, sid: usize) -> &'a pwgsb::json::Value {
    a.evidence
        .get("sessions")
        .and_then(|v| v.as_array())
        .unwrap()
        .iter()
        .find(|s| s.get("session_id").and_then(|v| v.as_i64()) == Some(sid as i64))
        .unwrap()
}

fn dir_json<'a>(s: &'a pwgsb::json::Value, dir: usize) -> &'a pwgsb::json::Value {
    s.get("directions")
        .and_then(|v| v.as_array())
        .unwrap()
        .iter()
        .find(|d| d.get("dir").and_then(|v| v.as_i64()) == Some(dir as i64))
        .unwrap()
}

#[test]
fn seq_wraparound_reassembles() {
    let frames = vec![
        f(1_000, syn(C, S, CP, SP, 0xffff_fff8)),
        f(2_000, synack(S, C, SP, CP, 0x0000_0777, 0xffff_fff9)),
        f(3_000, pure_ack(C, S, CP, SP, 0xffff_fff9, 0x0000_0778)),
        f(4_000, ack_bytes(C, S, CP, SP, 0xffff_fff9, 0x0778, b"ABCDEFGH")),
        f(5_000, ack_bytes(C, S, CP, SP, 0x0000_0001, 0x0778, b"IJ")),
    ];
    let a = run(frames, Policy::FirstSeen);
    assert_eq!(a.evidence.get("sessions").unwrap().as_array().unwrap().len(), 1);
    assert_eq!(dir0_stream(&a, 0).as_slice(), b"ABCDEFGHIJ");
    let s = session(&a, 0);
    let d = dir_json(s, 0);
    assert_eq!(d.get("contiguous_len").and_then(|v| v.as_i64()), Some(10));
    assert_eq!(d.get("gaps").unwrap().as_array().unwrap().len(), 0);
}

#[test]
fn retransmission_first_seen_keeps_original() {
    let frames = vec![
        f(1_000, ack_bytes(C, S, CP, SP, 1, 1, b"hello")),
        f(2_000, ack_bytes(C, S, CP, SP, 1, 1, b"hello")),
    ];
    let a = run(frames, Policy::FirstSeen);
    assert_eq!(dir0_stream(&a, 0).as_slice(), b"hello");
    let d = dir_json(session(&a, 0), 0);
    assert_eq!(d.get("retransmissions").and_then(|v| v.as_i64()), Some(1));
}

#[test]
fn overlap_policy_keeps_evidence_either_way() {
    let mk = || {
        vec![
            f(1_000, ack_bytes(C, S, CP, SP, 1, 1, b"hello")),
            f(2_000, ack_bytes(C, S, CP, SP, 1, 1, b"HELL!")),
        ]
    };

    let first = run(mk(), Policy::FirstSeen);
    assert_eq!(dir0_stream(&first, 0).as_slice(), b"hello");
    let events = dir_json(session(&first, 0), 0)
        .get("events")
        .unwrap()
        .as_array()
        .unwrap();
    let ev = events
        .iter()
        .find(|e| e.get("type").and_then(|v| v.as_str()) == Some("overlap_bytes"))
        .expect("overlap evidence");
    assert_eq!(ev.get("action").and_then(|v| v.as_str()), Some("incoming_dropped"));
    assert_eq!(
        ev.get("incoming_bytes_hex").and_then(|v| v.as_str()),
        Some(pwgsb::util::hex_encode(b"HELL!").as_str())
    );

    let last = run(mk(), Policy::LastSeen);
    assert_eq!(dir0_stream(&last, 0).as_slice(), b"HELL!");
    let events = dir_json(session(&last, 0), 0)
        .get("events")
        .unwrap()
        .as_array()
        .unwrap();
    let ev = events
        .iter()
        .find(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("overlap_bytes")
                && e.get("incoming_bytes_hex").and_then(|v| v.as_str())
                    == Some(pwgsb::util::hex_encode(b"HELL!").as_str())
        })
        .expect("replacement evidence preserves covered bytes");
    assert_eq!(
        ev.get("kept_bytes_hex").and_then(|v| v.as_str()),
        Some(pwgsb::util::hex_encode(b"hello").as_str())
    );
}

#[test]
fn out_of_order_is_flagged_and_reassembled() {
    let frames = vec![
        f(1_000, ack_bytes(C, S, CP, SP, 7, 1, b"GHIJ")),
        f(2_000, ack_bytes(C, S, CP, SP, 1, 1, b"ABCDEF")),
    ];
    let a = run(frames, Policy::FirstSeen);
    assert_eq!(dir0_stream(&a, 0).as_slice(), b"ABCDEFGHIJ");
    let d = dir_json(session(&a, 0), 0);
    assert_eq!(d.get("out_of_order").and_then(|v| v.as_i64()), Some(1));
    assert_eq!(d.get("gaps").unwrap().as_array().unwrap().len(), 0);
}

#[test]
fn gap_is_reported_with_zero_fill_stream() {
    let frames = vec![
        f(1_000, ack_bytes(C, S, CP, SP, 1, 1, b"AB")),
        f(2_000, ack_bytes(C, S, CP, SP, 5, 1, b"EF")),
    ];
    let a = run(frames, Policy::FirstSeen);
    assert_eq!(dir0_stream(&a, 0).as_slice(), b"AB\x00\x00EF");
    let d = dir_json(session(&a, 0), 0);
    let gaps = d.get("gaps").unwrap().as_array().unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].as_array().unwrap().len(), 2);
    assert_eq!(d.get("contiguous_len").and_then(|v| v.as_i64()), Some(2));
}

fn handshake_and_data(ts: u64, isn_c: u32, isn_s: u32, data: &[u8]) -> Vec<Vec<u8>> {
    let out = vec![
        syn(C, S, CP, SP, isn_c),
        synack(S, C, SP, CP, isn_s, isn_c.wrapping_add(1)),
        pure_ack(C, S, CP, SP, isn_c.wrapping_add(1), isn_s.wrapping_add(1)),
        ack_bytes(
            C,
            S,
            CP,
            SP,
            isn_c.wrapping_add(1),
            isn_s.wrapping_add(1),
            data,
        ),
    ];
    let _ = ts;
    out
}

#[test]
fn tuple_reuse_creates_new_generation() {
    let mut raw: Vec<Vec<u8>> = Vec::new();
    raw.extend(handshake_and_data(0, 1000, 5000, b"old-connection"));
    raw.push(fin_ack(C, S, CP, SP, 1000 + 1 + 14, 5001));
    raw.push(pure_ack(S, C, SP, CP, 5001, 1000 + 1 + 14 + 1));
    raw.push(fin_ack(S, C, SP, CP, 5001, 1000 + 1 + 14 + 1));
    raw.push(pure_ack(C, S, CP, SP, 1000 + 1 + 14 + 1, 5002));
    // 同一四元组的新连接，ISN 完全不同
    raw.extend(handshake_and_data(0, 900_000, 700_000, b"new-connection"));

    let frames: Vec<Frame> = raw
        .into_iter()
        .enumerate()
        .map(|(i, b)| f((i as u64 + 1) * 1000, b))
        .collect();
    let a = run(frames, Policy::FirstSeen);
    let sessions = a.evidence.get("sessions").unwrap().as_array().unwrap();
    assert_eq!(sessions.len(), 2, "reused tuple must split into generations");
    assert_eq!(sessions[0].get("generation").and_then(|v| v.as_i64()), Some(1));
    assert_eq!(sessions[1].get("generation").and_then(|v| v.as_i64()), Some(2));
    assert_eq!(sessions[0].get("close_reason").and_then(|v| v.as_str()), Some("fin"));
    assert_eq!(sessions[1].get("started_mid_capture").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(dir0_stream(&a, 1).as_slice(), b"new-connection");
}

#[test]
fn mid_capture_is_partial_but_no_fake_handshake() {
    let frames = vec![
        f(1_000, ack_bytes(C, S, CP, SP, 0x4444, 0x5555, b"midstream")),
        f(2_000, pure_ack(S, C, SP, CP, 0x5555, 0x4444 + 8)),
    ];
    let a = run(frames, Policy::FirstSeen);
    let sessions = a.evidence.get("sessions").unwrap().as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    let s = &sessions[0];
    assert_eq!(s.get("started_mid_capture").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(s.get("close_reason").and_then(|v| v.as_str()), Some("open"));
    // 两个方向都没有观测到 ISN
    let isn = s.get("isn").unwrap().as_array().unwrap();
    assert!(isn.iter().all(|v| *v == pwgsb::json::Value::Null));
    // 不能伪造握手：重组 base 直接采用首个数据段的 seq
    let d0 = dir_json(s, 0);
    assert_eq!(d0.get("base_seq").and_then(|v| v.as_i64()), Some(0x4444));
    assert_eq!(dir0_stream(&a, 0).as_slice(), b"midstream");
}

#[test]
fn fin_then_rst_race_closes_and_allows_reuse() {
    let mut raw: Vec<Vec<u8>> = Vec::new();
    raw.extend(handshake_and_data(0, 100, 900, b"race"));
    // FIN 与 RST 竞态：双向 FIN 刚发生，紧接 RST
    raw.push(fin_ack(C, S, CP, SP, 100 + 1 + 4, 901));
    raw.push(rst(S, C, SP, CP, 901, 100 + 1 + 4 + 1));
    // RST 之后同一四元组新 SYN 必须是新代次
    raw.extend(vec![
        syn(C, S, CP, SP, 7_777),
        synack(S, C, SP, CP, 8_888, 7_778),
        pure_ack(C, S, CP, SP, 7_778, 8_889),
    ]);
    let frames: Vec<Frame> = raw
        .into_iter()
        .enumerate()
        .map(|(i, b)| f((i as u64 + 1) * 1000, b))
        .collect();
    let a = run(frames, Policy::FirstSeen);
    let sessions = a.evidence.get("sessions").unwrap().as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].get("close_reason").and_then(|v| v.as_str()), Some("rst"));
    assert_eq!(sessions[1].get("generation").and_then(|v| v.as_i64()), Some(2));
}

#[test]
fn timeout_splits_generations_even_without_fin_or_rst() {
    let frames = vec![
        f(1_000, ack_bytes(C, S, CP, SP, 10, 1, b"first-era")),
        f(200_000_000_000, ack_bytes(C, S, CP, SP, 999, 1, b"second-era")),
    ];
    let a = run(frames, Policy::FirstSeen);
    let sessions = a.evidence.get("sessions").unwrap().as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].get("close_reason").and_then(|v| v.as_str()), Some("timeout"));
    assert_eq!(sessions[1].get("started_mid_capture").and_then(|v| v.as_bool()), Some(true));
}

#[test]
fn overlapping_ipv4_fragments_isolate_datagram_only() {
    // 数据报：一个 TCP 报文（无 eth/ip 外层），40 字节，分成两片并人为重叠
    let datagram = tcp_datagram(CP, SP, 1, 1, 0x18, b"frag-overlap-data");
    assert_eq!(datagram.len(), 20 + 17);
    // 第一片：offset 0, 30 字节，MF
    let f1 = ipv4_fragment(C, S, 0xABCD, 0, true, &datagram[0..30]);
    // 第二片：offset 16（与第一片区间重叠 14 字节），more=false
    let f2 = ipv4_fragment(C, S, 0xABCD, 16, false, &datagram[16..]);

    // 同一抓包里另一条完全独立的会话必须不受影响
    let other = vec![
        f(1_000, syn([10, 1, 0, 1], [10, 1, 0, 2], 2000, 81, 55)),
        f(2_000, synack([10, 1, 0, 2], [10, 1, 0, 1], 81, 2000, 56, 55 + 1)),
        f(3_000, ack_bytes([10, 1, 0, 1], [10, 1, 0, 2], 2000, 81, 56, 81, b"clean")),
    ];

    let mut frames = other;
    frames.push(f(4_000, f1));
    frames.push(f(5_000, f2));

    let a = run(frames, Policy::FirstSeen);
    let sessions = a.evidence.get("sessions").unwrap().as_array().unwrap();
    // 被隔离的数据报不产生 TCP 会话/段，只留下隔离证据
    assert_eq!(sessions.len(), 1, "only the clean session survives");
    let isolated = a
        .evidence
        .get("isolated_datagrams")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(isolated.len(), 1);
    assert!(isolated[0]
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap()
        .contains("overlapping fragments"));
}

#[test]
fn clean_ipv4_fragments_reassemble() {
    let datagram = tcp_datagram(CP, SP, 7, 1, 0x18, b"fragments-joined-ok");
    // 24 + 19 无重叠
    let f1 = ipv4_fragment(C, S, 0x1111, 0, true, &datagram[0..24]);
    let f2 = ipv4_fragment(C, S, 0x1111, 24, false, &datagram[24..]);
    let frames = vec![f(1_000, f1), f(2_000, f2)];
    let a = run(frames, Policy::FirstSeen);
    let sessions = a.evidence.get("sessions").unwrap().as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(a.evidence.get("isolated_datagrams").unwrap().as_array().unwrap().len(), 0);
    assert_eq!(dir0_stream(&a, 0).as_slice(), b"fragments-joined-ok");
}

#[test]
fn equal_timestamps_follow_original_frame_index() {
    // 两段不同序号，帧顺序即正确拼接顺序；若按时间戳乱排，事件与覆盖结果会不同。
    let frames = vec![
        f(1_000, ack_bytes(C, S, CP, SP, 1, 1, b"AB")),
        f(1_000, ack_bytes(C, S, CP, SP, 3, 1, b"CD")),
        f(1_000, ack_bytes(C, S, CP, SP, 5, 1, b"EF")),
    ];
    let a = run(frames, Policy::FirstSeen);
    assert_eq!(dir0_stream(&a, 0).as_slice(), b"ABCDEF");
    let d = dir_json(session(&a, 0), 0);
    assert_eq!(d.get("out_of_order").and_then(|v| v.as_i64()), Some(0));
}

#[test]
fn fixture_roundtrip_keeps_fingerprint_stable() {
    let frames = vec![
        f(1_000, syn(C, S, CP, SP, 42)),
        f(2_000, synack(S, C, SP, CP, 77, 43)),
        f(3_000, pure_ack(C, S, CP, SP, 43, 78)),
        f(4_000, ack_bytes(C, S, CP, SP, 43, 78, b"fingerprint-me")),
        f(5_000, ack_bytes(C, S, CP, SP, 43, 78, b"fingerprint-me")), // 重传
        f(6_000, ack_bytes(C, S, CP, SP, 43 + 15, 78, b"!!")),      // 部分覆盖
    ];
    // 导出夹具 -> 重新导入 -> 再分析，指纹必须一致
    let exported = fixture::build_fixture(&frames);
    let reimported = fixture::parse_fixture(&exported).expect("fixture parses");
    let mut indexed = frames.clone();
    indexed.iter_mut().enumerate().for_each(|(i, fr)| fr.index = i as u32);
    let a1 = run(indexed, Policy::FirstSeen);
    let a2 = analyze("test-corpus", &reimported, Params::default());
    assert_eq!(a1.fingerprint, a2.fingerprint);

    // 换策略必须得到不同分析版本与不同指纹
    let a3 = run(fixture::parse_fixture(&exported).unwrap(), Policy::LastSeen);
    assert_ne!(a1.fingerprint, a3.fingerprint);
}

#[test]
fn store_versions_are_never_overwritten() {
    let tmp = std::env::temp_dir().join(format!("pwgsb-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let store = Store::open(&tmp).unwrap();

    let frames = vec![f(1_000, ack_bytes(C, S, CP, SP, 1, 1, b"versioned"))];
    let json = fixture::build_fixture(&frames);
    let corpus = store.import(json.as_bytes()).unwrap();

    let v1 = store
        .analyze(&corpus.id, Params { policy: Policy::FirstSeen, ..Params::default() })
        .unwrap();
    let v2 = store
        .analyze(&corpus.id, Params { policy: Policy::LastSeen, ..Params::default() })
        .unwrap();
    let v1_again = store
        .analyze(&corpus.id, Params { policy: Policy::FirstSeen, ..Params::default() })
        .unwrap();

    assert_ne!(v1.id, v2.id, "policy change creates a new version");
    assert_eq!(v1.id, v1_again.id, "same params resolve to same version");
    assert_ne!(v1.fingerprint, v2.fingerprint);

    // 两个版本都仍然可读，旧版本没有被覆盖
    let old_evidence = store.read_evidence(&v1.id).unwrap();
    let new_evidence = store.read_evidence(&v2.id).unwrap();
    assert_ne!(old_evidence.serialize(), new_evidence.serialize());
    let stream = store.read_stream(&v1.id, 0, 0).unwrap();
    assert_eq!(stream, b"versioned");

    // 原始帧内容寻址：blob 可直接按哈希取到
    let blob_hash = pwgsb::sha256::sha256_hex(&frames[0].raw);
    assert!(tmp.join("blobs").join(&blob_hash).exists());

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn pcap_roundtrip_import() {
    use pwgsb::pcap;
    let frame1 = syn(C, S, CP, SP, 99);
    let frame2 = ack_bytes(C, S, CP, SP, 100, 1, b"pcap-data");
    let mut pcap_bytes = Vec::new();
    pcap_bytes.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    pcap_bytes.extend_from_slice(&2u16.to_le_bytes()); // major
    pcap_bytes.extend_from_slice(&4u16.to_le_bytes()); // minor
    pcap_bytes.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    pcap_bytes.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    pcap_bytes.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    pcap_bytes.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
    for (i, pkt) in [frame1, frame2].iter().enumerate() {
        pcap_bytes.extend_from_slice(&(100u32 + i as u32).to_le_bytes());
        pcap_bytes.extend_from_slice(&500u32.to_le_bytes());
        pcap_bytes.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap_bytes.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap_bytes.extend_from_slice(pkt);
    }
    assert!(pcap::looks_like_pcap(&pcap_bytes));
    let frames = pcap::parse_pcap(&pcap_bytes).unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].ts_ns, 100_000_500_000);
    let a = run(frames, Policy::FirstSeen);
    assert_eq!(dir0_stream(&a, 0).as_slice(), b"pcap-data");
}
