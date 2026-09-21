mod common;
use common::*;
use reasm_bench::builder::{build_ipv4_fragment, raw_ip_frame};
use reasm_bench::types::{Ip, RawFrame};

// We rebuild TCP bytes through the public frame spec by encoding one whole
// datagram and then slicing at IP boundaries.
#[test]
fn overlapping_ipv4_fragments_quarantine_datagram_only() {
    // Build two independent TCP-over-IPv4 conversations; corrupt fragments for
    // the first and ensure the second still reconstructs normally.
    let good = {
        let mut h = handshake(0.0, 100, 500);
        h.push(spec(0.03, 101, Some(501), PA, b"healthy-session"));
        build_frames(h)
    };

    // Manually craft overlapping fragments for a different four-tuple.
    let src = Ip::V4([10, 1, 1, 1]);
    let dst = Ip::V4([10, 1, 1, 2]);
    let whole_spec = TcpFrameSpecForFrag::new(0.02, src.clone(), dst.clone(), 5000, 6000)
        .seq(42).ack(99).data(b"abcdefghijklmnop");
    let tcp = whole_spec.tcp_bytes();
    // Fragment 1 offset 0 len 16, fragment 2 offset 8 len 8 -> overlap.
    let frag1 = build_ipv4_fragment(&[10,1,1,1], &[10,1,1,2], &tcp[..16], 777, 0, true);
    let frag2 = build_ipv4_fragment(&[10,1,1,1], &[10,1,1,2], &tcp[8..16], 777, 8, false);
    let bad = vec![
        raw_ip_frame(0.02, &src, &frag1, Some("frag0".into())),
        raw_ip_frame(0.021, &src, &frag2, Some("frag-overlap".into())),
    ];

    // Interleave ordering: bad fragments between healthy traffic timestamps.
    let mut all = Vec::new();
    all.push(good[0].clone());
    all.push(bad[0].clone());
    all.push(good[1].clone());
    all.push(bad[1].clone());
    all.extend(good[2..].iter().cloned());

    let result = run(all);
    assert!(!result.quarantined_datagrams.is_empty(), "overlapping fragment datagram must be isolated");
    let q = &result.quarantined_datagrams[0];
    assert!(q.reason.to_lowercase().contains("overlap"));
    // Healthy session unaffected.
    assert!(result.sessions.iter().any(|s| {
        let ep = format!("{}:{}", ip(CLIENT), CP);
        s.directions.get(&ep)
            .map(|d| reasm_bench::types::decode_hex(&d.delivered_hex).unwrap() == b"healthy-session")
            .unwrap_or(false)
    }));
}

#[test]
fn benign_ipv4_fragmentation_reassembles_tcp() {
    let whole = TcpFrameSpecForFrag::new(0.03, ip(CLIENT), ip(SERVER), CP, SP)
        .seq(101).ack(501).data(b"fragmented-payload-123456");
    let tcp = whole.tcp_bytes();
    assert!(tcp.len() > 20);
    // 8-byte aligned chunks: first chunk keeps the 20-byte TCP header + bytes.
    let chunk = 24usize;
    let mut frames_out = Vec::new();
    let mut offset = 0usize;
    let ident = 4242u16;
    let count = (tcp.len() + chunk - 1) / chunk;
    for i in 0..count {
        let end = (offset + chunk).min(tcp.len());
        // IP offsets must be multiples of 8; our TCP is built so total length
        // fits this fixture (24-byte chunk is 8-aligned).
        let more = i + 1 < count;
        let pkt = build_ipv4_fragment(&[10,0,0,1], &[10,0,0,2], &tcp[offset..end], ident, offset, more);
        frames_out.push(raw_ip_frame(0.03 + i as f64 * 0.001, &ip(CLIENT), &pkt, None));
        offset = end;
    }
    // Need handshake context for a clean session: add full handshake frames.
    let mut h = handshake(0.0, 100, 500);
    let mut all: Vec<RawFrame> = h.drain(..).collect();
    all.extend(frames_out);
    let result = run(all);
    let ep = format!("{}:{}", ip(CLIENT), CP);
    let dir = &result.sessions[0].directions[&ep];
    assert_eq!(
        reasm_bench::types::decode_hex(&dir.delivered_hex).unwrap(),
        b"fragmented-payload-123456"
    );
    let frag_frames = result.frames.iter().filter(|f| f.role == "ip_fragment").count();
    let assembled = result.frames.iter().filter(|f| f.role == "ip_fragment_reassembled_tcp").count();
    assert!(frag_frames >= 1);
    assert_eq!(assembled, 1);
}

// Helper exposing TCP-only bytes for fragment slicing.
struct TcpFrameSpecForFrag {
    inner: reasm_bench::builder::TcpFrameSpec,
}

impl TcpFrameSpecForFrag {
    fn new(t: f64, src: Ip, dst: Ip, sp: u16, dp: u16) -> Self {
        let inner = reasm_bench::builder::TcpFrameSpec::new(t, src, dst, sp, dp);
        TcpFrameSpecForFrag { inner }
    }
    fn seq(mut self, seq: u32) -> Self { self.inner = self.inner.seq(seq); self }
    fn ack(mut self, ack: u32) -> Self { self.inner = self.inner.ack(ack); self }
    fn data(mut self, data: &[u8]) -> Self { self.inner = self.inner.payload(data.to_vec()); self }
    fn tcp_bytes(&self) -> Vec<u8> {
        reasm_bench::builder::tcp_segment_bytes(&self.inner)
    }
}
