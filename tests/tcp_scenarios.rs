mod common;
use common::*;
use reasm_bench::reasm::OverlapPolicy;
use reasm_bench::types::decode_hex;

fn client_hex(result: &reasm_bench::analyze::AnalysisResult, idx: usize) -> String {
    let ep = format!("{}:{}", ip(CLIENT), CP);
    result.sessions
        .iter()
        .find(|s| s.session_id == idx)
        .and_then(|s| s.directions.get(&ep))
        .map(|d| d.delivered_hex.clone())
        .expect("client direction present")
}

#[test]
fn sequence_wraparound_reassembles_contiguous_stream() {
    let isn_c = u32::MAX - 3;
    let isn_s = 500;
    let mut specs = handshake(0.0, isn_c, isn_s);
    // Client data starts at isn_c+1 == u32::MAX-2; send enough to wrap to 5.
    let payload1: Vec<u8> = (0..8u8).collect(); // covers MAX-2..MAX+6 => raw seq wraps
    specs.push(spec(0.03, isn_c.wrapping_add(1), Some(isn_s.wrapping_add(1)), PA, &payload1));
    let result = run(build_frames(specs));
    assert_eq!(result.sessions.len(), 1);
    let hex = client_hex(&result, 1);
    assert_eq!(decode_hex(&hex).unwrap(), payload1);
}

#[test]
fn retransmission_is_flagged_and_bytes_stable() {
    let isn_c = 1000;
    let isn_s = 2000;
    let mut specs = handshake(0.0, isn_c, isn_s);
    let payload = b"hello world";
    specs.push(spec(0.03, isn_c + 1, Some(isn_s + 1), PA, payload));
    // Identical retransmission of the whole range.
    specs.push(spec(0.04, isn_c + 1, Some(isn_s + 1), PA, payload));
    let result = run(build_frames(specs));
    let ep = format!("{}:{}", ip(CLIENT), CP);
    let dir = &result.sessions[0].directions[&ep];
    assert_eq!(dir.retransmit_segments, 1);
    assert_eq!(decode_hex(&dir.delivered_hex).unwrap(), payload);
}

#[test]
fn conflicting_overlap_first_seen_keeps_earlier_byte() {
    let isn_c = 100;
    let isn_s = 200;
    let mut specs = handshake(0.0, isn_c, isn_s);
    specs.push(spec(0.03, isn_c + 1, Some(isn_s + 1), PA, b"AAAA"));
    // Second segment overlaps offset 2..4 with conflicting bytes.
    specs.push(spec(0.04, isn_c + 3, Some(isn_s + 1), PA, b"ZZ"));
    let result = run_policy(build_frames(specs), OverlapPolicy::FirstSeen);
    let ep = format!("{}:{}", ip(CLIENT), CP);
    let dir = &result.sessions[0].directions[&ep];
    assert_eq!(decode_hex(&dir.delivered_hex).unwrap(), b"AAAA");
    assert_eq!(dir.overwrite_evidence.len(), 2);
    assert_eq!(dir.conflict_segments, 1);
}

#[test]
fn conflicting_overlap_last_seen_adopts_later_byte() {
    let isn_c = 100;
    let isn_s = 200;
    let mut specs = handshake(0.0, isn_c, isn_s);
    specs.push(spec(0.03, isn_c + 1, Some(isn_s + 1), PA, b"AAAA"));
    specs.push(spec(0.04, isn_c + 3, Some(isn_s + 1), PA, b"ZZ"));
    let result = run_policy(build_frames(specs), OverlapPolicy::LastSeen);
    let ep = format!("{}:{}", ip(CLIENT), CP);
    let dir = &result.sessions[0].directions[&ep];
    assert_eq!(decode_hex(&dir.delivered_hex).unwrap(), b"AAZZ");
    // Superseded bytes remain as evidence.
    assert!(dir.overwrite_evidence.iter().any(|e| e.kept_frame == 4 && e.offered_hex == "41"));
}

#[test]
fn out_of_order_then_gap_fill_reassembles() {
    let isn_c = 9000;
    let isn_s = 8000;
    let mut specs = handshake(0.0, isn_c, isn_s);
    // Send bytes 10..20 first (gap 0..10), then fill 0..10.
    specs.push(spec(0.03, isn_c + 11, Some(isn_s + 1), PA, b"KLMNOPQRST"));
    let result_after_gap = run(build_frames(specs.clone()));
    let ep = format!("{}:{}", ip(CLIENT), CP);
    let dir = &result_after_gap.sessions[0].directions[&ep];
    assert_eq!(dir.gaps.len(), 1);
    assert_eq!(dir.out_of_order_segments, 1);
    assert_eq!(dir.delivered_length, 0);

    let mut specs2 = specs;
    specs2.push(spec(0.05, isn_c + 1, Some(isn_s + 1), PA, b"ABCDEFGHIJ"));
    let result = run(build_frames(specs2));
    let dir = &result.sessions[0].directions[&ep];
    assert_eq!(decode_hex(&dir.delivered_hex).unwrap(), b"ABCDEFGHIJKLMNOPQRST");
    assert!(dir.gaps.is_empty());
}

#[test]
fn missing_gap_is_reported_not_fabricated() {
    let isn_c = 1;
    let isn_s = 2;
    let mut specs = handshake(0.0, isn_c, isn_s);
    // Only bytes 0..3 and 6..9 arrive.
    specs.push(spec(0.03, isn_c + 1, Some(isn_s + 1), PA, b"ABC"));
    specs.push(spec(0.04, isn_c + 7, Some(isn_s + 1), PA, b"GHI"));
    let result = run(build_frames(specs));
    let ep = format!("{}:{}", ip(CLIENT), CP);
    let dir = &result.sessions[0].directions[&ep];
    assert_eq!(dir.gaps.len(), 1);
    assert_eq!(dir.gaps[0].start, 3);
    assert_eq!(dir.gaps[0].end, 6);
    assert_eq!(dir.delivered_length, 3);
}
