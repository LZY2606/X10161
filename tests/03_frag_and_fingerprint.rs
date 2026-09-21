mod common;
use common::*;
use reasm::builder::{FrameBuilder, F_ACK, F_PSH, F_SYN};
use reasm::fixture::Fixture;
use reasm::json::{canonical, parse};
use reasm::pcap::{encode as pcap_encode, parse as pcap_parse};
use reasm::seq::OverlapPolicy;
use reasm::store::Store;
use reasm::wire::LINK_ETHERNET;

#[test]
fn ipv4_fragments_reassemble() {
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
    let big: Vec<u8> = (0..40).map(|i| b'A' + (i % 26)).collect();
    b.tcp_v4_fragmented(
        10_000,
        C,
        S,
        CP,
        SP,
        isn.wrapping_add(1),
        5001,
        F_PSH | F_ACK,
        &big,
        24,
        0x4242,
    );
    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let g = &generations(&sessions(&v)[0])[0];
    let client_dir = "B";
    assert_eq!(delivered(g, client_dir), 40, "分片重组后数据完整");
    let q = v.get("quarantined_datagrams").unwrap().as_array().unwrap();
    assert!(q.is_empty());
}

#[test]
fn overlapping_ipv4_fragments_are_quarantined() {
    use reasm::frag::{FragConfig, FragEmit, FragTable};
    use reasm::wire::{parse_frame, FrameOutcome};

    // 构造同一 id、偏移重叠的两片。
    let mk = |offset: u16, more: bool, data: &[u8]| {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        let total = 20 + data.len();
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip[4..6].copy_from_slice(&0x9999u16.to_be_bytes());
        let mut ff = offset;
        if more {
            ff |= 0x2000;
        }
        ip[6..8].copy_from_slice(&ff.to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(data);
        frame
    };
    let f1 = mk(0, true, &[0u8; 16]);
    let f2 = mk(1, false, &[0u8; 8]); // 偏移 8 与第一片 [0,16) 重叠
    let mut table = FragTable::new();
    let cfg = FragConfig::default();
    let p1 = match parse_frame(&f1, LINK_ETHERNET, 0).unwrap() {
        FrameOutcome::Fragment(p) => p,
        _ => panic!("应是分片"),
    };
    let r1 = table.add(p1, 0, &cfg);
    assert!(matches!(r1, FragEmit::None));
    let p2 = match parse_frame(&f2, LINK_ETHERNET, 1).unwrap() {
        FrameOutcome::Fragment(p) => p,
        _ => panic!("应是分片"),
    };
    let r2 = table.add(p2, 1, &cfg);
    match r2 {
        FragEmit::Quarantined(q) => {
            assert_eq!(q.reason, reasm::frag::QuarantineReason::Overlap);
        }
        other => panic!(
            "应隔离，实际 {:?}",
            matches!(other, FragEmit::Quarantined(_))
        ),
    }
}

#[test]
fn equal_timestamps_ordered_by_frame_index() {
    // 两段时间戳相同：先出现（帧序号小）的高序号段不影响最终结果，
    // 但乱序标记必须按帧序判定。
    let mut b = FrameBuilder::new();
    let isn = 1000u32;
    b.tcp(0, C, CP, S, SP, isn, 0, F_SYN, b"");
    b.tcp(
        0,
        S,
        SP,
        C,
        CP,
        5000,
        isn.wrapping_add(1),
        F_SYN | F_ACK,
        b"",
    );
    b.tcp(0, C, CP, S, SP, isn.wrapping_add(1), 5001, F_ACK, b"");
    // 高序号段先进入文件（同时间戳）。
    b.tcp(0, C, CP, S, SP, isn.wrapping_add(6), 5001, F_ACK, b"56789");
    b.tcp(
        0,
        C,
        CP,
        S,
        SP,
        isn.wrapping_add(1),
        5001,
        F_PSH | F_ACK,
        b"01234",
    );
    let v = analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let g = &generations(&sessions(&v)[0])[0];
    let client_dir = "B";
    assert_eq!(delivered(g, client_dir), 10);
    // 段按帧序号展示，data 段第一行帧号是 3（乱序），第二行帧号 4。
    let data_segs: Vec<_> = segs(g, client_dir)
        .iter()
        .filter(|s| s.get("data_len").unwrap().as_i64() == Some(5))
        .collect();
    assert_eq!(data_segs[0].get("frame").unwrap().as_i64(), Some(3));
    assert_eq!(data_segs[1].get("frame").unwrap().as_i64(), Some(4));
}

#[test]
fn pcap_roundtrip_and_fixture_import_share_fingerprint() {
    let tmp = tempdir_name();
    let store = Store::open(&tmp).unwrap();

    // 用 builder 生成确定性帧，编码成 pcap 导入。
    let mut b = FrameBuilder::new();
    established_stream(&mut b, 0, 100, 200, &[b"round-trip"]);
    let raw = b.into_raw();
    let pcap_bytes = pcap_encode(LINK_ETHERNET, &raw);
    let c1 = store.import_bytes(&pcap_bytes).unwrap();

    // 等价夹具 JSON：同时间戳、同帧字节。
    let frames_json: Vec<_> = raw
        .iter()
        .map(|f| {
            reasm::json::Value::obj(vec![
                ("us", reasm::json::Value::Int(f.ts_us)),
                ("hex", reasm::json::Value::Str(reasm::hash::hex(&f.data))),
            ])
        })
        .collect();
    let fx = reasm::json::Value::obj(vec![
        ("format", reasm::json::Value::Str("reasm-fixture/1".into())),
        ("link_type", reasm::json::Value::Str("ethernet".into())),
        ("frames", reasm::json::Value::Array(frames_json)),
    ]);
    let fx_text = reasm::json::pretty(&fx);
    // 自检：夹具可被解析回相同帧。
    let parsed = Fixture::parse(&fx_text).unwrap();
    assert_eq!(parsed.frames.len(), raw.len());
    for (a, b) in parsed.frames.iter().zip(raw.iter()) {
        assert_eq!(a.data, b.data);
        assert_eq!(a.ts_us, b.ts_us);
    }
    let c2 = store.import_bytes(fx_text.as_bytes()).unwrap();
    assert_eq!(c1.capture_id, c2.capture_id, "pcap 与夹具身份应一致");

    let a1 = store
        .analyze(&c1.capture_id, OverlapPolicy::FirstSeen, 120_000_000)
        .unwrap();
    let a2 = store
        .analyze(&c2.capture_id, OverlapPolicy::FirstSeen, 120_000_000)
        .unwrap();
    assert_eq!(a1.analysis_id, a2.analysis_id);
    assert_eq!(a1.fingerprint, a2.fingerprint, "导入导出后指纹必须一致");
}

#[test]
fn policy_change_creates_new_version_without_overwriting() {
    let tmp = tempdir_name();
    let store = Store::open(&tmp).unwrap();
    let fx = reasm::sample::fixture_json_string();
    let c = store.import_bytes(fx.as_bytes()).unwrap();
    let a1 = store
        .analyze(&c.capture_id, OverlapPolicy::FirstSeen, 120_000_000)
        .unwrap();
    let a2 = store
        .analyze(&c.capture_id, OverlapPolicy::LastSeen, 120_000_000)
        .unwrap();
    assert_ne!(a1.analysis_id, a2.analysis_id);
    assert_ne!(a1.fingerprint, a2.fingerprint);
    // 旧版本仍在。
    assert!(store.read_evidence(&a1.analysis_id).is_some());
    assert!(store.read_evidence(&a2.analysis_id).is_some());
    // 重复同样配置应幂等命中同一版本。
    let a1b = store
        .analyze(&c.capture_id, OverlapPolicy::FirstSeen, 120_000_000)
        .unwrap();
    assert_eq!(a1.analysis_id, a1b.analysis_id);
}

#[test]
fn fingerprint_is_canonical_and_stable_across_parse() {
    let v = common::analyze(sample_builder(), OverlapPolicy::FirstSeen, 120_000);
    let canon = canonical(&v);
    // 重新 pretty + parse 再 canonical，必须相同。
    let reparsed = parse(&reasm::json::pretty(&v)).unwrap();
    assert_eq!(canon, canonical(&reparsed));
}

fn sample_builder() -> FrameBuilder {
    let frames = reasm::sample::raw_frames();
    let mut b = FrameBuilder::new();
    for f in frames {
        b.push(f.ts_us, f.data);
    }
    b
}

fn tempdir_name() -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = format!("target/test-store-{}-{}", pid, nanos);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn pcap_reader_parses_own_output() {
    let mut b = FrameBuilder::new();
    established_stream(&mut b, 1234, 7, 8, &[b"xx"]);
    let bytes = pcap_encode(LINK_ETHERNET, &b.into_raw());
    let (hdr, frames) = pcap_parse(&bytes).unwrap();
    assert_eq!(hdr.link_type, LINK_ETHERNET);
    assert_eq!(frames.len(), 4);
    assert_eq!(frames[0].ts_us, 1234);
}
