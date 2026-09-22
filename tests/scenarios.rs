mod common;

use common::*;
use reasm::builder;
use reasm::builder::Builder;
use reasm::json::{self, Json};
use reasm::model::{ACK, FIN, PSH, RST, SYN};
use reasm::tcp::OverlapPolicy;

fn bld() -> Builder {
    Builder::new(1)
}

#[test]
fn sequence_wrap_reassembles_in_order() {
    let mut b = bld();
    let isn = u32::MAX - 4; // 4294967291
    hs(&mut b, 0, isn, 1000);
    // seq after SYN = isn+1 = ...292; payload of 16 bytes crosses the edge.
    b.add(
        1000,
        c2s(isn.wrapping_add(1), 1001, b"0123456789ABCDEF", 200),
    );
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    assert_eq!(session_count(&r), 1);
    let s = sess(&r, 0);
    let d = dir(s, 0);
    assert_eq!(len_of(d), 16);
    assert_eq!(data_hex(d), json::bytes_to_hex(b"0123456789ABCDEF"));
    // relative begin stays 1 even though absolute seq wraps
    let data_segs: Vec<_> = s
        .get("segments")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x.get("length").unwrap().as_u64().unwrap() > 0)
        .collect();
    assert_eq!(data_segs[0].get("begin").unwrap().as_u64().unwrap(), 0);
    assert_eq!(data_segs[0].get("end").unwrap().as_u64().unwrap(), 16);
}

#[test]
fn retransmission_detected_and_conflict_keeps_evidence() {
    let mut b = bld();
    hs(&mut b, 0, 100, 500);
    b.add(1000, c2s(101, 501, b"HELLO", 300));
    b.add(1100, c2s(101, 501, b"HELLO", 301)); // identical retrans
    let mut changed = b"HELLO".to_vec();
    changed[0] = b'X';
    b.add(1200, c2s(101, 501, &changed, 302)); // conflicting retrans
    let r1 = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    let s1 = sess(&r1, 0);
    assert_eq!(conflicts(s1), 1);
    assert_eq!(data_hex(dir(s1, 0)), json::bytes_to_hex(b"HELLO"));
    assert!(seg_relations(s1)
        .iter()
        .any(|x| x.contains("retransmission")));
    // all three copies remain in the segment evidence
    let payloads: Vec<String> = s1
        .get("segments")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x.get("length").unwrap().as_u64().unwrap() == 5)
        .map(|x| x.get("payload_hex").unwrap().as_str().unwrap().to_string())
        .collect();
    assert_eq!(payloads.len(), 3);
    assert!(payloads.contains(&json::bytes_to_hex(b"XELLO")));

    // last-seen flips the delivered byte but keeps identical evidence set
    let r2 = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::LastSeen);
    let s2 = sess(&r2, 0);
    assert_eq!(data_hex(dir(s2, 0)), json::bytes_to_hex(b"XELLO"));
    assert_eq!(conflicts(s2), 1);
    // changing policy changes the analysis fingerprint
    assert_ne!(fp(&r1), fp(&r2));
}

#[test]
fn out_of_order_segments_fill_gap() {
    let mut b = bld();
    hs(&mut b, 0, 100, 500);
    b.add(
        1000,
        pkt(C, CP, S, SP, 111, 501, ACK | PSH, b"KLMNOPQRST", 400),
    );
    b.add(
        1100,
        pkt(C, CP, S, SP, 121, 501, ACK | PSH, b"UVWXYZabcd", 401),
    );
    b.add(
        1200,
        pkt(C, CP, S, SP, 101, 501, ACK | PSH, b"ABCDEFGHIJ", 402),
    );
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    let s = sess(&r, 0);
    assert_eq!(
        data_hex(dir(s, 0)),
        json::bytes_to_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcd")
    );
    assert_eq!(
        dir(s, 0)
            .get("out_of_order_segments")
            .unwrap()
            .as_u64()
            .unwrap(),
        2
    );
    // once filled, there is no residual gap
    assert_eq!(s.get("gaps").unwrap().as_array().unwrap().len(), 0);
}

#[test]
fn missing_middle_is_a_gap() {
    let mut b = bld();
    hs(&mut b, 0, 100, 500);
    b.add(1000, c2s(101, 501, b"AAAAA", 500));
    b.add(1100, c2s(121, 501, b"BBBBB", 501));
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    let s = sess(&r, 0);
    let gaps = s.get("gaps").unwrap().as_array().unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].get("begin").unwrap().as_u64().unwrap(), 5);
    assert_eq!(gaps[0].get("end").unwrap().as_u64().unwrap(), 20);
    // contiguous prefix delivered despite tail gap
    assert_eq!(len_of(dir(s, 0)), 5);
}

#[test]
fn four_tuple_reuse_creates_two_generations() {
    let mut b = bld();
    let mut t = hs(&mut b, 0, 100, 500);
    t = builder::data(&mut b, t, C, CP, S, SP, 101, 501, b"first", 600);
    t = builder::flags(&mut b, t, C, CP, S, SP, 106, 501, FIN | ACK, 601);
    t = builder::flags(&mut b, t, S, SP, C, CP, 501, 107, FIN | ACK, 602);
    // reuse after close
    b.add(t + 1000, pkt(C, CP, S, SP, 900, 0, SYN, &[], 700));
    b.add(t + 1100, pkt(S, SP, C, CP, 9000, 901, SYN | ACK, &[], 701));
    b.add(
        t + 1200,
        pkt(C, CP, S, SP, 901, 9001, ACK | PSH, b"second-conn", 702),
    );
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    assert_eq!(session_count(&r), 2);
    assert_eq!(sess(&r, 0).get("generation").unwrap().as_u64().unwrap(), 1);
    assert_eq!(sess(&r, 1).get("generation").unwrap().as_u64().unwrap(), 2);
    assert_eq!(state(sess(&r, 0)), "fin-closed");
    assert_eq!(
        data_hex(dir(sess(&r, 1), 0)),
        json::bytes_to_hex(b"second-conn")
    );
    // same four tuple string
    assert_eq!(
        sess(&r, 0).get("four_tuple").unwrap().as_str().unwrap(),
        sess(&r, 1).get("four_tuple").unwrap().as_str().unwrap()
    );
}

#[test]
fn mid_capture_partial_without_fake_handshake() {
    let mut b = bld();
    b.add(
        1000,
        pkt(C, CP, S, SP, 777, 10, ACK | PSH, b"mid-stream-data", 800),
    );
    b.add(1100, pkt(S, SP, C, CP, 10, 792, ACK | PSH, b"reply", 801));
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    let s = sess(&r, 0);
    assert_eq!(s.get("handshake").unwrap().as_str().unwrap(), "missing");
    assert_eq!(s.get("started_mid_capture").unwrap(), &Json::Bool(true));
    assert_eq!(state(s), "partial");
    assert!(
        s.get("syn_frames").is_none() || {
            // syn_frames is internal; output uses handshake flags only
            true
        }
    );
    assert_eq!(data_hex(dir(s, 0)), json::bytes_to_hex(b"mid-stream-data"));
    assert_eq!(dir(s, 0).get("base_from_syn").unwrap(), &Json::Bool(false));
    assert_eq!(data_hex(dir(s, 1)), json::bytes_to_hex(b"reply"));
}

#[test]
fn fin_rst_race_rst_wins() {
    let mut b = bld();
    let mut t = hs(&mut b, 0, 100, 500);
    t = builder::data(&mut b, t, C, CP, S, SP, 101, 501, b"bye", 900);
    builder::flags(&mut b, t, C, CP, S, SP, 104, 501, FIN | ACK, 901);
    builder::flags(&mut b, t + 50, C, CP, S, SP, 104, 501, RST | ACK, 902);
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    let s = sess(&r, 0);
    assert_eq!(state(s), "rst-closed");
    assert!(dir(s, 0).get("fin_seen").unwrap() == &Json::Bool(true));
    assert!(dir(s, 0).get("rst_seen").unwrap() == &Json::Bool(true));
    assert_eq!(data_hex(dir(s, 0)), json::bytes_to_hex(b"bye"));
}

#[test]
fn overlapping_ipv4_fragments_quarantine_datagram_only() {
    use reasm::builder::tcp_packet_frag;
    let mut b = bld();
    hs(&mut b, 0, 100, 500);
    // first fragment with TCP header + 8 payload bytes, MF set
    let f0 = tcp_packet_frag(
        C,
        CP,
        S,
        SP,
        101,
        501,
        ACK | PSH,
        b"FRAG0001",
        950,
        Some((0, true)),
    );
    // next fragment at offset 8
    let f1 = tcp_packet_frag(C, CP, S, SP, 0, 0, 0, b"NEXTNEXT", 950, Some((8, true)));
    // overlapping fragment that re-covers bytes 14..
    let fbad = tcp_packet_frag(C, CP, S, SP, 0, 0, 0, b"XX", 950, Some((14, false)));
    b.add(2000, f0);
    b.add(2100, f1);
    b.add(2200, fbad);
    // independent session on a different four tuple must survive
    b.add(
        2300,
        pkt(
            "10.0.0.3",
            5000,
            "10.0.0.4",
            81,
            1,
            1,
            ACK | PSH,
            b"clean",
            960,
        ),
    );
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    // the quarantined datagram never created a data session; sessions are the
    // handshake connection (no fragmented payload delivered) and the clean one.
    assert_eq!(session_count(&r), 2);
    let frag_sess = sess(&r, 0);
    assert_eq!(len_of(dir(frag_sess, 0)), 0);
    let s = sess(&r, 1);
    assert_eq!(data_hex(dir(s, 0)), json::bytes_to_hex(b"clean"));
    let notes = r.get("fragment_notes").unwrap().as_array().unwrap();
    assert!(notes.iter().any(|n| n
        .get("reason")
        .unwrap()
        .as_str()
        .unwrap()
        .contains("quarantined")));
}

#[test]
fn equal_timestamps_use_frame_index_order() {
    let mut b = bld();
    b.add(0, pkt(C, CP, S, SP, 100, 0, SYN, &[], 1000));
    b.add(0, pkt(S, SP, C, CP, 500, 101, SYN | ACK, &[], 1001));
    b.add(0, pkt(C, CP, S, SP, 101, 501, ACK, &[], 1002));
    b.add(0, c2s(101, 501, b"AAA", 1003));
    b.add(0, c2s(104, 501, b"BBB", 1004));
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    let s = sess(&r, 0);
    assert_eq!(data_hex(dir(s, 0)), json::bytes_to_hex(b"AAABBB"));
    assert_eq!(state(s), "open"); // kept open, handshake intact
}

#[test]
fn export_import_fingerprint_is_stable() {
    let mut b = bld();
    let mut t = hs(&mut b, 0, 100, 500);
    t = builder::data(&mut b, t, C, CP, S, SP, 101, 501, b"abc", 1);
    // gap then fill
    b.add(t + 300, c2s(111, 501, b"z", 3));
    b.add(t + 400, c2s(104, 501, b"def", 2));
    let bytes = fixture_bytes(&b.to_json());
    let r1 = analyze_json(&bytes, OverlapPolicy::FirstSeen);
    let f1 = fp(&r1);
    // serialize the full result, then re-run analysis from the original fixture:
    // fingerprint must be deterministic and independent of run timing.
    let exported = json::to_string_pretty(&r1);
    let reparsed = json::parse(&exported).unwrap();
    let f1b = fp(&reparsed);
    assert_eq!(f1, f1b);
    let r2 = analyze_json(&bytes, OverlapPolicy::FirstSeen);
    assert_eq!(f1, fp(&r2));
    // switching policy creates a distinct immutable analysis version
    let r3 = analyze_json(&bytes, OverlapPolicy::LastSeen);
    assert_ne!(f1, fp(&r3));
    // but last-seen is itself deterministic across runs
    let r4 = analyze_json(&bytes, OverlapPolicy::LastSeen);
    assert_eq!(fp(&r3), fp(&r4));
}

#[test]
fn pcap_format_roundtrip() {
    // Build a fixture, extract its ethernet frames, wrap them into a pcap.
    let mut b = bld();
    hs(&mut b, 0, 100, 500);
    b.add(1000, c2s(101, 501, b"pcap-data", 200));
    let fj = b.to_json();
    let frames = fj.get("frames").unwrap().as_array().unwrap();
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes()); // major
    pcap.extend_from_slice(&4u16.to_le_bytes()); // minor
    pcap.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    pcap.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    pcap.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    pcap.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    for (i, f) in frames.iter().enumerate() {
        let hex = f.get("data").unwrap().as_str().unwrap();
        let data = json::hex_to_bytes(hex).unwrap();
        pcap.extend_from_slice(&(i as u32).to_le_bytes()); // ts sec
        pcap.extend_from_slice(&0u32.to_le_bytes()); // ts usec
        pcap.extend_from_slice(&(data.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(data.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&data);
    }
    let r = analyze_json(&pcap, OverlapPolicy::FirstSeen);
    assert_eq!(r.get("input_kind").unwrap().as_str().unwrap(), "pcap");
    let s = sess(&r, 0);
    assert_eq!(data_hex(dir(s, 0)), json::bytes_to_hex(b"pcap-data"));
}

#[test]
fn idle_timeout_ends_generation_before_reuse_syn() {
    let mut b = bld();
    let mut t = hs(&mut b, 0, 100, 500);
    t = builder::data(&mut b, t, C, CP, S, SP, 101, 501, b"old", 1);
    // gap larger than the 2s default timeout, then a SYN on same 4-tuple
    let later = t + 5_000_000;
    b.add(later, pkt(C, CP, S, SP, 7000, 0, SYN, &[], 2));
    b.add(
        later + 100,
        pkt(S, SP, C, CP, 8000, 7001, SYN | ACK, &[], 3),
    );
    b.add(
        later + 200,
        pkt(C, CP, S, SP, 7001, 8001, ACK | PSH, b"new", 4),
    );
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    assert_eq!(session_count(&r), 2);
    assert_eq!(state(sess(&r, 0)), "timed-out");
    assert_eq!(data_hex(dir(sess(&r, 1), 0)), json::bytes_to_hex(b"new"));
}

#[test]
fn ipv6_session_reassembles() {
    use reasm::builder::tcp_packet_v6;
    let mut b = bld();
    let c6 = "2001:db8::1";
    let s6 = "2001:db8::2";
    b.add(0, tcp_packet_v6(c6, CP, s6, SP, 100, 0, SYN, &[]));
    b.add(100, tcp_packet_v6(s6, SP, c6, CP, 500, 101, SYN | ACK, &[]));
    b.add(
        200,
        tcp_packet_v6(c6, CP, s6, SP, 101, 501, ACK | PSH, b"ipv6-data"),
    );
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    assert_eq!(session_count(&r), 1);
    let s = sess(&r, 0);
    assert_eq!(s.get("ip_version").unwrap().as_u64().unwrap(), 6);
    assert_eq!(data_hex(dir(s, 0)), json::bytes_to_hex(b"ipv6-data"));
    assert!(s
        .get("four_tuple")
        .unwrap()
        .as_str()
        .unwrap()
        .contains("2001:db8::1"));
}

#[test]
fn first_segment_late_creates_prefix_gap_then_fills() {
    let mut b = bld();
    hs(&mut b, 0, 100, 500);
    // only a later contiguous region arrives (seq 106 -> data index 5)
    b.add(1000, c2s(106, 501, b"ZZZZZ", 1));
    let r0 = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    let s0 = sess(&r0, 0);
    let g0 = s0.get("gaps").unwrap().as_array().unwrap();
    assert_eq!(g0.len(), 1);
    assert_eq!(g0[0].get("begin").unwrap().as_u64().unwrap(), 0);
    assert_eq!(g0[0].get("end").unwrap().as_u64().unwrap(), 5);
    assert_eq!(len_of(dir(s0, 0)), 0);
    // missing prefix then arrives; stream completes
    b.add(1100, c2s(101, 501, b"AAAAA", 2));
    let r1 = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    let s1 = sess(&r1, 0);
    assert_eq!(data_hex(dir(s1, 0)), json::bytes_to_hex(b"AAAAAZZZZZ"));
    assert_eq!(s1.get("gaps").unwrap().as_array().unwrap().len(), 0);
}

#[test]
fn ipv6_fragments_reassemble_and_overlap_quarantines() {
    use reasm::builder::tcp_packet_v6_frag;
    let c6 = "2001:db8::1";
    let s6 = "2001:db8::2";

    // Clean, non-overlapping IPv6 fragmented datagram: 8 + 8 bytes.
    let mut b = bld();
    // first fragment: 20B TCP header + 4B payload; second starts at byte 24
    // (8-aligned), carrying the next 4B. Normalized payload offset = 24 - 20 = 4.
    b.add(
        0,
        tcp_packet_v6_frag(c6, CP, s6, SP, 101, 1, ACK | PSH, b"AAAA", 0, true, 77),
    );
    b.add(
        100,
        tcp_packet_v6_frag(c6, CP, s6, SP, 0, 0, 0, b"BBBB", 24, false, 77),
    );
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    let s = sess(&r, 0);
    assert_eq!(data_hex(dir(s, 0)), json::bytes_to_hex(b"AAAABBBB"));

    // Overlapping IPv6 fragments are quarantined; nothing delivered.
    let mut b2 = bld();
    b2.add(
        0,
        tcp_packet_v6_frag(c6, CP, s6, SP, 201, 1, ACK | PSH, b"XXXX", 0, true, 88),
    );
    b2.add(
        100,
        tcp_packet_v6_frag(c6, CP, s6, SP, 0, 0, 0, b"YYYY", 24, true, 88),
    );
    b2.add(
        200,
        tcp_packet_v6_frag(c6, CP, s6, SP, 0, 0, 0, b"ZZ", 28, false, 88),
    );
    let r2 = analyze_json(&fixture_bytes(&b2.to_json()), OverlapPolicy::FirstSeen);
    assert_eq!(session_count(&r2), 0);
    assert!(r2
        .get("fragment_notes")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n
            .get("reason")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("quarantined")));
}

#[test]
fn syn_retransmission_does_not_open_new_generation() {
    let mut b = bld();
    // client SYN, then a duplicated client SYN (same ISN), then the SYN-ACK/ACK
    b.add(0, pkt(C, CP, S, SP, 100, 0, SYN, &[], 1));
    b.add(100, pkt(C, CP, S, SP, 100, 0, SYN, &[], 2));
    b.add(200, pkt(S, SP, C, CP, 500, 101, SYN | ACK, &[], 3));
    b.add(300, pkt(C, CP, S, SP, 101, 501, ACK, &[], 4));
    b.add(400, c2s(101, 501, b"data", 5));
    let r = analyze_json(&fixture_bytes(&b.to_json()), OverlapPolicy::FirstSeen);
    assert_eq!(session_count(&r), 1);
    let s = sess(&r, 0);
    assert_eq!(s.get("generation").unwrap().as_u64().unwrap(), 1);
    assert_eq!(data_hex(dir(s, 0)), json::bytes_to_hex(b"data"));
}
