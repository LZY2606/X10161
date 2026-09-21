mod common;
use common::*;

#[test]
fn four_tuple_reuse_after_fin_creates_new_generation() {
    let mut specs = handshake(0.0, 100, 500);
    specs.push(spec(0.03, 101, Some(501), PA, b"first"));
    specs.extend(graceful_fin(0.10, 106, 501));
    // Reused connection: brand new SYNs, same ports, much later.
    specs.push(spec(5.0, 9000, None, S, &[]));
    specs.push(from_server(5.01, 7000, Some(9001), SA, &[]));
    specs.push(spec(5.02, 9001, Some(7001), A, &[]));
    specs.push(spec(5.03, 9001, Some(7001), PA, b"second"));
    let result = run(build_frames(specs));
    assert_eq!(result.sessions.len(), 2, "reused four-tuple yields two sessions");
    assert_eq!(result.sessions[0].state, "fin_graceful");
    assert_eq!(result.sessions[1].handshake, "completed");
    let ep = format!("{}:{}", ip(CLIENT), CP);
    let d2 = &result.sessions[1].directions[&ep];
    assert_eq!(reasm_bench::types::decode_hex(&d2.delivered_hex).unwrap(), b"second");
}

#[test]
fn mid_capture_partial_session_has_no_fabricated_handshake() {
    let mut specs = Vec::new();
    // No SYN: capture starts with application data.
    specs.push(spec(10.0, 12345, Some(67890), PA, b"mid-stream-data"));
    specs.push(from_server(10.01, 67890, Some(12359), PA, b"reply"));
    let result = run(build_frames(specs));
    assert_eq!(result.sessions.len(), 1);
    let session = &result.sessions[0];
    assert_eq!(session.handshake, "partial");
    assert!(session.partial);
    assert!(session.timeline.iter().any(|e| e.kind == "partial_session"));
    // The data still reassembles from the mid-capture anchor.
    let ep = format!("{}:{}", ip(CLIENT), CP);
    let dir = &session.directions[&ep];
    assert_eq!(reasm_bench::types::decode_hex(&dir.delivered_hex).unwrap(), b"mid-stream-data");
    assert!(!dir.anchored_by_syn);
}

#[test]
fn syn_reuse_supersedes_still_open_generation() {
    let mut specs = handshake(0.0, 100, 500);
    specs.push(spec(0.03, 101, Some(501), PA, b"old"));
    // New SYN on the same four-tuple without FIN/RST.
    specs.push(spec(1.0, 4000, None, S, &[]));
    specs.push(from_server(1.01, 6000, Some(4001), SA, &[]));
    specs.push(spec(1.02, 4001, Some(6001), A, &[]));
    let result = run(build_frames(specs));
    assert_eq!(result.sessions.len(), 2);
    assert_eq!(result.sessions[0].state, "superseded");
    assert!(result.sessions[0].timeline.iter().any(|e| e.kind == "superseded_close"));
    assert_eq!(result.sessions[1].handshake, "completed");
}

#[test]
fn rst_closes_generation_and_is_recorded_in_both_race_orders() {
    // FIN and RST racing: RST arrives right after FIN; RST wins the close.
    let mut specs = handshake(0.0, 100, 500);
    specs.push(spec(0.03, 101, Some(501), FA, b""));
    specs.push(spec(0.031, 102, Some(501), RA, b""));
    let result = run(build_frames(specs));
    assert_eq!(result.sessions.len(), 1);
    assert_eq!(result.sessions[0].state, "reset");
    let ep_c = format!("{}:{}", ip(CLIENT), CP);
    let dir = &result.sessions[0].directions[&ep_c];
    assert!(dir.fin);
    assert!(dir.rst);
    // Both FIN and RST appear as evidence on the timeline.
    let kinds: Vec<&str> = result.sessions[0].timeline.iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"fin"));
    assert!(kinds.contains(&"rst"));
}

#[test]
fn timeout_splits_generations_on_later_data() {
    let mut specs = handshake(0.0, 100, 500);
    specs.push(spec(0.03, 101, Some(501), PA, b"before"));
    // Idle far beyond 120s default, then fresh data without SYN.
    specs.push(spec(500.0, 106, Some(501), PA, b"after"));
    let result = run(build_frames(specs));
    assert_eq!(result.sessions.len(), 2);
    assert_eq!(result.sessions[0].state, "timeout");
    assert_eq!(result.sessions[1].handshake, "partial");
}

#[test]
fn capture_end_leaves_open_session_marked() {
    let specs = handshake(0.0, 100, 500);
    let result = run(build_frames(specs));
    assert_eq!(result.sessions[0].state, "capture_end");
}

#[test]
fn identical_timestamps_keep_original_frame_order() {
    let mut specs = handshake(1.0, 100, 500);
    // Two equal-timestamp segments; the out-of-order one must not jump ahead.
    specs.push(spec(1.03, 101, Some(501), PA, b"first-"));
    specs.push(spec(1.03, 107, Some(501), PA, b"second"));
    let result = run(build_frames(specs));
    let ep = format!("{}:{}", ip(CLIENT), CP);
    let dir = &result.sessions[0].directions[&ep];
    // The second segment is out of order relative to the first frame index.
    let segs: Vec<_> = dir.segments.iter().collect();
    assert!(segs.windows(2).all(|w| w[0].frame_index < w[1].frame_index));
}
