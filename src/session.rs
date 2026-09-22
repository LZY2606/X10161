use crate::packet::{seq_offset, TcpSegment, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapPolicy {
    FirstSeen,
    LastSeen,
}

impl OverlapPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            OverlapPolicy::FirstSeen => "first_seen",
            OverlapPolicy::LastSeen => "last_seen",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "first_seen" | "first-seen" | "first" => Some(OverlapPolicy::FirstSeen),
            "last_seen" | "last-seen" | "last" => Some(OverlapPolicy::LastSeen),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SessionConfig {
    /// Idle time after which an open generation is considered ended.
    pub timeout_ns: u64,
    pub overlap: OverlapPolicy,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_ns: 120_000_000_000,
            overlap: OverlapPolicy::FirstSeen,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub fn label(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct TupleKey {
    pub a: Endpoint,
    pub b: Endpoint,
}

impl TupleKey {
    /// Normalized key; direction 0 means traffic from `a` to `b`.
    fn new(src: Endpoint, dst: Endpoint) -> (TupleKey, usize) {
        if src <= dst {
            (TupleKey { a: src, b: dst }, 0)
        } else {
            (TupleKey { a: dst, b: src }, 1)
        }
    }
}

#[derive(Clone, Debug)]
struct Seg {
    seq: u32,
    frame: u64,
    ts_ns: u64,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Interval {
    pub start_seq: u32,
    pub end_seq: u32,
    pub offset: i64,
    pub len: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SegInfo {
    pub seq: u32,
    pub end_seq: u32,
    pub offset: i64,
    pub len: u64,
    pub frame: u64,
    pub ts_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FrameEv {
    pub seq: u32,
    pub len: u64,
    pub frame: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct OverlapEv {
    pub offset: i64,
    pub start_seq: u32,
    pub len: u64,
    pub kept_frame: u64,
    pub dropped_frame: u64,
    pub policy: String,
    /// Bytes that lost the overlap resolution, preserved as evidence.
    pub dropped_bytes_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DirectionResult {
    pub isn: Option<u32>,
    pub anchor_seq: Option<u32>,
    pub byte_count: u64,
    pub payload_sha256: String,
    pub payload_file: String,
    pub intervals: Vec<Interval>,
    pub gaps: Vec<Interval>,
    pub retransmissions: Vec<FrameEv>,
    pub out_of_order: Vec<FrameEv>,
    pub overlaps: Vec<OverlapEv>,
    pub segments: Vec<SegInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionResult {
    pub id: usize,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub generation: u32,
    pub partial: bool,
    pub close_reason: String,
    pub first_ts_ns: u64,
    pub last_ts_ns: u64,
    pub frames: Vec<u64>,
    pub directions: Vec<DirectionResult>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionEvent {
    pub session: usize,
    pub generation: u32,
    pub kind: String,
    pub frame: Option<u64>,
    pub detail: serde_json::Value,
}

/// Covered byte range with the frame that owns it.
type Cover = (i64, i64, u64);

fn uncovered_ranges(cov: &[Cover], start: i64, end: i64) -> Vec<(i64, i64)> {
    let mut res = Vec::new();
    let mut cur = start;
    for &(cs, ce, _) in cov {
        if ce <= cur {
            continue;
        }
        if cs >= end {
            break;
        }
        if cs > cur {
            res.push((cur, cs.min(end)));
        }
        cur = cur.max(ce);
        if cur >= end {
            break;
        }
    }
    if cur < end {
        res.push((cur, end));
    }
    res
}

fn intersect_ranges(cov: &[Cover], start: i64, end: i64) -> Vec<Cover> {
    let mut res = Vec::new();
    for &(cs, ce, cf) in cov {
        let s = start.max(cs);
        let e = end.min(ce);
        if s < e {
            res.push((s, e, cf));
        }
    }
    res
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    crate::pcap::to_hex(&h.finalize())
}

fn seq_of(anchor: u32, off: i64) -> u32 {
    anchor.wrapping_add(off as u32)
}

fn make_interval(anchor: u32, start: i64, end: i64) -> Interval {
    Interval {
        start_seq: seq_of(anchor, start),
        end_seq: seq_of(anchor, end),
        offset: start,
        len: (end - start) as u64,
    }
}

/// Reassemble one direction from its data segments (in arrival order).
/// Returns the direction result, the reassembled bytes, and overlap events.
fn analyze_direction(
    session: usize,
    generation: u32,
    dir: usize,
    isn: Option<u32>,
    segs: &[Seg],
    policy: OverlapPolicy,
) -> (DirectionResult, Vec<u8>, Vec<SessionEvent>) {
    let empty = DirectionResult {
        isn,
        anchor_seq: None,
        byte_count: 0,
        payload_sha256: sha256_hex(&[]),
        payload_file: String::new(),
        intervals: Vec::new(),
        gaps: Vec::new(),
        retransmissions: Vec::new(),
        out_of_order: Vec::new(),
        overlaps: Vec::new(),
        segments: Vec::new(),
    };
    let anchor = match isn.map(|i| i.wrapping_add(1)).or_else(|| segs.first().map(|s| s.seq)) {
        Some(a) => a,
        None => return (empty, Vec::new(), Vec::new()),
    };
    let mut result = empty;
    result.anchor_seq = Some(anchor);

    let base_off = segs
        .iter()
        .map(|s| seq_offset(s.seq, anchor))
        .min()
        .unwrap_or(0)
        .min(0);

    let mut buf: Vec<u8> = Vec::new();
    let mut cov: Vec<Cover> = Vec::new();
    let mut max_end: i64 = i64::MIN;
    let mut events: Vec<SessionEvent> = Vec::new();

    for seg in segs {
        let off = seq_offset(seg.seq, anchor);
        let len = seg.payload.len() as i64;
        let end = off + len;
        let need = (end - base_off) as usize;
        if buf.len() < need {
            buf.resize(need, 0);
        }
        result.segments.push(SegInfo {
            seq: seg.seq,
            end_seq: seg.seq.wrapping_add(seg.payload.len() as u32),
            offset: off,
            len: seg.payload.len() as u64,
            frame: seg.frame,
            ts_ns: seg.ts_ns,
        });

        let overlaps = intersect_ranges(&cov, off, end);
        let overlap_len: i64 = overlaps.iter().map(|&(s, e, _)| e - s).sum();

        for &(s, e, owner_frame) in &overlaps {
            let new_bytes = &seg.payload[(s - off) as usize..(e - off) as usize];
            let old_bytes = &buf[(s - base_off) as usize..(e - base_off) as usize];
            let (kept_frame, dropped_frame, dropped) = match policy {
                OverlapPolicy::FirstSeen => (owner_frame, seg.frame, new_bytes),
                OverlapPolicy::LastSeen => (seg.frame, owner_frame, old_bytes),
            };
            let ev = OverlapEv {
                offset: s,
                start_seq: seq_of(anchor, s),
                len: (e - s) as u64,
                kept_frame,
                dropped_frame,
                policy: policy.as_str().to_string(),
                dropped_bytes_hex: crate::pcap::to_hex(dropped),
            };
            events.push(SessionEvent {
                session,
                generation,
                kind: "overlap".into(),
                frame: Some(seg.frame),
                detail: serde_json::json!({
                    "direction": dir,
                    "offset": ev.offset,
                    "start_seq": ev.start_seq,
                    "len": ev.len,
                    "kept_frame": ev.kept_frame,
                    "dropped_frame": ev.dropped_frame,
                    "policy": ev.policy,
                    "dropped_bytes_hex": ev.dropped_bytes_hex,
                }),
            });
            result.overlaps.push(ev);
        }

        if overlap_len == len {
            result.retransmissions.push(FrameEv {
                seq: seg.seq,
                len: len as u64,
                frame: seg.frame,
            });
        } else if off < max_end {
            result.out_of_order.push(FrameEv {
                seq: seg.seq,
                len: len as u64,
                frame: seg.frame,
            });
        }

        // Apply bytes according to the overlap policy.
        match policy {
            OverlapPolicy::FirstSeen => {
                for (s, e) in uncovered_ranges(&cov, off, end) {
                    let dst = (s - base_off) as usize;
                    let src = (s - off) as usize;
                    buf[dst..dst + (e - s) as usize]
                        .copy_from_slice(&seg.payload[src..src + (e - s) as usize]);
                }
            }
            OverlapPolicy::LastSeen => {
                let dst = (off - base_off) as usize;
                buf[dst..dst + len as usize].copy_from_slice(&seg.payload);
            }
        }

        // Update coverage: uncovered pieces owned by this frame; with
        // last_seen the overlapped ranges also change owner.
        let mut next: Vec<Cover> = cov
            .iter()
            .filter(|&&(cs, ce, _)| ce <= off || cs >= end)
            .copied()
            .collect();
        for &(cs, ce, cf) in &cov {
            if ce <= off || cs >= end {
                continue;
            }
            if cs < off {
                next.push((cs, off, cf));
            }
            if ce > end {
                next.push((end, ce, cf));
            }
        }
        for (s, e) in uncovered_ranges(&cov, off, end) {
            next.push((s, e, seg.frame));
        }
        if policy == OverlapPolicy::LastSeen {
            for &(s, e, _) in &overlaps {
                next.push((s, e, seg.frame));
            }
        } else {
            for &(s, e, cf) in &overlaps {
                next.push((s, e, cf));
            }
        }
        next.sort_by_key(|&(s, _, _)| s);
        cov = next;
        max_end = max_end.max(end);
    }

    // Merge adjacent coverage into display intervals.
    let mut merged: Vec<(i64, i64)> = Vec::new();
    for &(s, e, _) in &cov {
        if let Some(last) = merged.last_mut() {
            if last.1 == s {
                last.1 = e;
                continue;
            }
        }
        merged.push((s, e));
    }

    let mut reassembled: Vec<u8> = Vec::new();
    for &(s, e) in &merged {
        let start = (s - base_off) as usize;
        reassembled.extend_from_slice(&buf[start..start + (e - s) as usize]);
    }

    result.intervals = merged
        .iter()
        .map(|&(s, e)| make_interval(anchor, s, e))
        .collect();
    result.byte_count = merged.iter().map(|&(s, e)| (e - s) as u64).sum();
    if let Some(&(_, top)) = merged.last() {
        let mut cur = base_off;
        for &(s, e) in &merged {
            if s > cur {
                result.gaps.push(make_interval(anchor, cur, s));
            }
            cur = cur.max(e);
        }
        let _ = top;
    }
    result.payload_sha256 = sha256_hex(&reassembled);
    (result, reassembled, events)
}

struct Generation {
    id: u32,
    key: TupleKey,
    partial: bool,
    initiator: Option<usize>,
    isn: [Option<u32>; 2],
    fin: [bool; 2],
    segs: [Vec<Seg>; 2],
    first_ts: u64,
    last_ts: u64,
    frames: Vec<u64>,
    events: Vec<SessionEvent>,
}

impl Generation {
    fn new(id: u32, key: TupleKey, partial: bool, ts: u64) -> Self {
        let mut g = Generation {
            id,
            key,
            partial,
            initiator: None,
            isn: [None, None],
            fin: [false, false],
            segs: [Vec::new(), Vec::new()],
            first_ts: ts,
            last_ts: ts,
            frames: Vec::new(),
            events: Vec::new(),
        };
        g.events.push(SessionEvent {
            session: 0,
            generation: id,
            kind: "generation".into(),
            frame: None,
            detail: serde_json::json!({"event": "opened", "partial": partial}),
        });
        g
    }
}

#[derive(Default)]
struct TupleTracker {
    current: Option<Generation>,
    /// Index into `done` of the most recently closed generation (for RST-after-FIN).
    last_closed: Option<usize>,
    next_gen: u32,
}

pub struct FinishedSession {
    pub result: SessionResult,
    pub events: Vec<SessionEvent>,
    /// Reassembled payload per direction.
    pub payloads: [Vec<u8>; 2],
}

pub struct SessionEngine {
    cfg: SessionConfig,
    trackers: BTreeMap<TupleKey, TupleTracker>,
    done: Vec<FinishedSession>,
}

impl SessionEngine {
    pub fn new(cfg: SessionConfig) -> Self {
        SessionEngine {
            cfg,
            trackers: BTreeMap::new(),
            done: Vec::new(),
        }
    }

    fn close_generation(&mut self, key: &TupleKey, reason: &str, ts: u64) {
        let tr = self.trackers.get_mut(key).expect("tracker exists");
        let Some(mut gen) = tr.current.take() else {
            return;
        };
        gen.last_ts = gen.last_ts.max(ts);
        gen.events.push(SessionEvent {
            session: 0,
            generation: gen.id,
            kind: "generation".into(),
            frame: None,
            detail: serde_json::json!({"event": "closed", "reason": reason}),
        });
        let session_id = self.done.len();
        let mut events = Vec::new();
        let mut directions = Vec::new();
        let mut payloads: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        for dir in 0..2 {
            let (mut res, bytes, mut ev) = analyze_direction(
                session_id,
                gen.id,
                dir,
                gen.isn[dir],
                &gen.segs[dir],
                self.cfg.overlap,
            );
            res.payload_file = format!("payload_s{session_id}_d{dir}.bin");
            directions.push(res);
            payloads[dir] = bytes;
            events.append(&mut ev);
        }
        for e in &mut gen.events {
            e.session = session_id;
        }
        let mut all_events = gen.events.clone();
        all_events.append(&mut events);
        let result = SessionResult {
            id: session_id,
            endpoint_a: gen.key.a.label(),
            endpoint_b: gen.key.b.label(),
            generation: gen.id,
            partial: gen.partial,
            close_reason: reason.to_string(),
            first_ts_ns: gen.first_ts,
            last_ts_ns: gen.last_ts,
            frames: gen.frames.clone(),
            directions,
        };
        self.done.push(FinishedSession {
            result,
            events: all_events,
            payloads,
        });
        let tr = self.trackers.get_mut(key).expect("tracker exists");
        tr.last_closed = Some(session_id);
    }

    pub fn process(
        &mut self,
        src: Endpoint,
        dst: Endpoint,
        seg: &TcpSegment<'_>,
        ts_ns: u64,
        frame: u64,
    ) {
        let (key, dir) = TupleKey::new(src, dst);
        // Idle timeout closes the current generation.
        let timed_out = self
            .trackers
            .get(&key)
            .and_then(|t| t.current.as_ref())
            .map(|cur| ts_ns.saturating_sub(cur.last_ts) > self.cfg.timeout_ns)
            .unwrap_or(false);
        if timed_out {
            self.close_generation(&key, "timeout", ts_ns);
        }
        let tr = self.trackers.entry(key).or_default();

        let syn = seg.flags & TCP_SYN != 0;
        let syn_only = syn && seg.flags & TCP_ACK == 0;
        let rst = seg.flags & TCP_RST != 0;

        if tr.current.is_none() {
            // RST racing just after a FIN-closed generation: attach as evidence
            // instead of fabricating a new partial generation.
            if rst && !syn && seg.payload.is_empty() {
                if let Some(idx) = tr.last_closed {
                    let closed = &self.done[idx];
                    if closed.result.close_reason == "fin"
                        && ts_ns.saturating_sub(closed.result.last_ts_ns) <= self.cfg.timeout_ns
                    {
                        let generation = closed.result.generation;
                        let ev = SessionEvent {
                            session: idx,
                            generation,
                            kind: "rst-after-close".into(),
                            frame: Some(frame),
                            detail: serde_json::json!({
                                "note": "RST arrived after FIN-closed generation",
                            }),
                        };
                        self.done[idx].events.push(ev);
                        return;
                    }
                }
            }
            let gen_id = tr.next_gen;
            tr.next_gen += 1;
            let mut gen = Generation::new(gen_id, key, !syn_only, ts_ns);
            if syn_only {
                gen.initiator = Some(dir);
                gen.isn[dir] = Some(seg.seq);
            }
            tr.current = Some(gen);
        } else if syn_only {
            let cur = tr.current.as_ref().expect("current");
            let same_syn = !cur.partial && cur.isn[dir] == Some(seg.seq);
            if same_syn {
                let gen_id = cur.id;
                let cur = tr.current.as_mut().expect("current");
                cur.last_ts = ts_ns;
                cur.events.push(SessionEvent {
                    session: 0,
                    generation: gen_id,
                    kind: "syn-retransmission".into(),
                    frame: Some(frame),
                    detail: serde_json::json!({"direction": dir, "seq": seg.seq}),
                });
                return;
            }
            // Same tuple reused: a different SYN supersedes the old generation.
            self.close_generation(&key, "superseded-by-syn", ts_ns);
            let tr = self.trackers.entry(key).or_default();
            let gen_id = tr.next_gen;
            tr.next_gen += 1;
            let mut gen = Generation::new(gen_id, key, false, ts_ns);
            gen.initiator = Some(dir);
            gen.isn[dir] = Some(seg.seq);
            tr.current = Some(gen);
        }

        let tr = self.trackers.entry(key).or_default();
        let cur = tr.current.as_mut().expect("current");
        if syn && cur.isn[dir].is_none() {
            cur.isn[dir] = Some(seg.seq);
        }
        if !seg.payload.is_empty() {
            cur.segs[dir].push(Seg {
                seq: seg.seq,
                frame,
                ts_ns,
                payload: seg.payload.to_vec(),
            });
        }
        if seg.flags & TCP_FIN != 0 {
            cur.fin[dir] = true;
        }
        cur.last_ts = ts_ns;
        cur.frames.push(frame);
        let both_fin = cur.fin[0] && cur.fin[1];
        if rst {
            self.close_generation(&key, "rst", ts_ns);
        } else if both_fin {
            self.close_generation(&key, "fin", ts_ns);
        }
    }

    /// Finalize all still-open generations at end of capture.
    pub fn finish(mut self) -> Vec<FinishedSession> {
        let keys: Vec<TupleKey> = self.trackers.keys().copied().collect();
        for key in keys {
            let open = self
                .trackers
                .get(&key)
                .map(|t| t.current.is_some())
                .unwrap_or(false);
            if open {
                self.close_generation(&key, "end-of-capture", 0);
            }
        }
        self.done
    }
}
