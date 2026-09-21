//! TCP session tracking: bidirectional flow merging, connection generations
//! (SYN / FIN / RST / timeout), 32-bit wrap-around sequence comparison and
//! configurable first-seen / last-seen overlap reassembly with evidence.

use crate::packet::{Endpoint, TcpPacket, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use std::collections::{BTreeMap, HashMap};

/// Generations are split when silence exceeds this budget.
pub const TIMEOUT_MICROS: i64 = 120 * 1_000_000;

// ---- RFC 1982 style 32-bit sequence comparison ----
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
pub fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}
fn seq_off(seq: u32, base: u32) -> i64 {
    seq.wrapping_sub(base) as i32 as i64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub a: Endpoint,
    pub b: Endpoint,
}

impl FlowKey {
    pub fn new(x: Endpoint, y: Endpoint) -> FlowKey {
        if x <= y {
            FlowKey { a: x, b: y }
        } else {
            FlowKey { a: y, b: x }
        }
    }
    pub fn label(&self) -> String {
        format!("{} <> {}", self.a, self.b)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Fin,
    Rst,
    Timeout,
}

impl CloseReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            CloseReason::Fin => "fin",
            CloseReason::Rst => "rst",
            CloseReason::Timeout => "timeout",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Segment {
    pub seq: u32,
    pub payload: Vec<u8>,
    pub frame: u32,
    pub ts: i64,
}

#[derive(Debug, Default)]
pub struct Direction {
    pub endpoint: Option<Endpoint>,
    pub isn: Option<u32>,
    pub syn_seen: bool,
    pub fin_seen: bool,
    pub rst_seen: bool,
    pub packet_count: u64,
    pub syn_only_count: u64,
    pub segments: Vec<Segment>,
}

#[derive(Debug)]
pub struct Session {
    pub id: usize,
    pub key: FlowKey,
    pub generation: u32,
    /// Capture started mid-stream: no handshake observed, none fabricated.
    pub partial: bool,
    pub handshake: bool,
    pub closed_by: Option<CloseReason>,
    pub dirs: [Direction; 2],
    pub first_ts: i64,
    pub last_ts: i64,
    pub first_frame: u32,
    pub last_frame: u32,
}

impl Session {
    fn total_packets(&self) -> u64 {
        self.dirs[0].packet_count + self.dirs[1].packet_count
    }
    /// True when this generation so far only carries bare SYNs (no ACK) from
    /// one direction with the same ISS: a retransmitted SYN, not a new gen.
    fn is_pure_syn_from(&self, dir: usize, seq: u32) -> bool {
        let d = &self.dirs[dir];
        d.syn_seen
            && d.isn == Some(seq)
            && self.total_packets() == d.syn_only_count
    }
}

#[derive(Default)]
pub struct Engine {
    pub sessions: Vec<Session>,
    by_key: HashMap<FlowKey, Vec<usize>>,
}

impl Engine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process(&mut self, pkt: &TcpPacket, ts: i64, frame: u32) {
        let key = FlowKey::new(pkt.src, pkt.dst);
        let dir = if pkt.src == key.a { 0 } else { 1 };
        let is_syn_only = pkt.flags & FLAG_SYN != 0 && pkt.flags & FLAG_ACK == 0;

        let gens = self.by_key.entry(key).or_default();
        let mut new_gen = match gens.last() {
            None => true,
            Some(&idx) => {
                let cur = &self.sessions[idx];
                if is_syn_only {
                    !cur.is_pure_syn_from(dir, pkt.seq)
                } else {
                    cur.closed_by.is_some() || ts - cur.last_ts > TIMEOUT_MICROS
                }
            }
        };
        // A bare SYN after a long silence is a new generation even if the
        // previous one happened to be a lone retransmitted SYN.
        if !new_gen && is_syn_only {
            if let Some(&idx) = gens.last() {
                if ts - self.sessions[idx].last_ts > TIMEOUT_MICROS {
                    new_gen = true;
                }
            }
        }

        let idx = if new_gen {
            if let Some(&prev) = gens.last() {
                let prev_s = &mut self.sessions[prev];
                if prev_s.closed_by.is_none() {
                    prev_s.closed_by = Some(CloseReason::Timeout);
                }
            }
            let generation = gens.len() as u32;
            let id = self.sessions.len();
            let mut dirs: [Direction; 2] = [Direction::default(), Direction::default()];
            dirs[0].endpoint = Some(key.a);
            dirs[1].endpoint = Some(key.b);
            self.sessions.push(Session {
                id,
                key,
                generation,
                partial: !is_syn_only,
                handshake: is_syn_only,
                closed_by: None,
                dirs,
                first_ts: ts,
                last_ts: ts,
                first_frame: frame,
                last_frame: frame,
            });
            gens.push(id);
            id
        } else {
            *gens.last().unwrap()
        };

        let s = &mut self.sessions[idx];
        s.last_ts = ts;
        s.last_frame = frame;
        let d = &mut s.dirs[dir];
        d.packet_count += 1;
        if pkt.flags & FLAG_SYN != 0 {
            if !d.syn_seen {
                d.isn = Some(pkt.seq);
            }
            d.syn_seen = true;
            if pkt.flags & FLAG_ACK == 0 {
                d.syn_only_count += 1;
            }
        }
        if pkt.flags & FLAG_FIN != 0 {
            d.fin_seen = true;
        }
        if pkt.flags & FLAG_RST != 0 {
            d.rst_seen = true;
        }
        if !pkt.payload.is_empty() {
            d.segments.push(Segment {
                seq: pkt.seq,
                payload: pkt.payload.clone(),
                frame,
                ts,
            });
        }
        if s.closed_by.is_none() {
            if s.dirs[0].rst_seen || s.dirs[1].rst_seen {
                s.closed_by = Some(CloseReason::Rst);
            } else if s.dirs[0].fin_seen && s.dirs[1].fin_seen {
                s.closed_by = Some(CloseReason::Fin);
            }
        }
    }
}

// ---------------- Reassembly ----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapPolicy {
    FirstSeen,
    LastSeen,
}

impl OverlapPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            OverlapPolicy::FirstSeen => "first-seen",
            OverlapPolicy::LastSeen => "last-seen",
        }
    }
    pub fn parse(s: &str) -> Option<OverlapPolicy> {
        match s {
            "first-seen" | "first" => Some(OverlapPolicy::FirstSeen),
            "last-seen" | "last" => Some(OverlapPolicy::LastSeen),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SegView {
    pub seq_start: u32,
    pub seq_end: u32,
    pub len: u32,
    pub frame: u32,
    pub ts: i64,
    pub status: &'static str, // ok | retransmission | overlap
    pub out_of_order: bool,
}

#[derive(Debug, Clone)]
pub struct OverlapEvent {
    pub seq_start: u32,
    pub len: u32,
    pub existing_frame: u32,
    pub incoming_frame: u32,
    pub existing_bytes: Vec<u8>,
    pub incoming_bytes: Vec<u8>,
    pub kept: &'static str, // which side the active policy kept
}

#[derive(Debug, Clone)]
pub struct RetransEvent {
    pub seq_start: u32,
    pub len: u32,
    pub frame: u32,
}

#[derive(Debug, Clone)]
pub struct OooEvent {
    pub seq: u32,
    pub expected: u32,
    pub frame: u32,
}

#[derive(Debug, Clone)]
pub struct Gap {
    pub start: u32,
    pub end: u32, // exclusive
}

#[derive(Debug, Default)]
pub struct DirAnalysis {
    pub base_seq: Option<u32>,
    pub segments: Vec<SegView>,
    pub overlaps: Vec<OverlapEvent>,
    pub retransmissions: Vec<RetransEvent>,
    pub out_of_order: Vec<OooEvent>,
    pub gaps: Vec<Gap>,
    pub reassembled: Vec<u8>,
    pub covered_bytes: u64,
    pub max_seq: Option<u32>,
}

pub fn analyze_direction(dir: &Direction, policy: OverlapPolicy) -> DirAnalysis {
    let mut out = DirAnalysis::default();
    if dir.segments.is_empty() {
        out.base_seq = dir.isn.map(|i| i.wrapping_add(1));
        return out;
    }
    // Anchor = earliest sequence number in wrap-around order.
    let mut base = dir.segments[0].seq;
    for s in &dir.segments[1..] {
        if seq_lt(s.seq, base) {
            base = s.seq;
        }
    }
    if let Some(isn) = dir.isn {
        let d0 = isn.wrapping_add(1);
        if seq_lt(d0, base) {
            base = d0;
        }
    }
    out.base_seq = Some(base);

    let mut covered: BTreeMap<i64, (u8, u32)> = BTreeMap::new();
    let mut contig_end: i64 = 0;

    for seg in &dir.segments {
        let off = seq_off(seg.seq, base);
        let len = seg.payload.len() as i64;
        let mut status = "ok";
        let mut ooo = false;
        if off > contig_end {
            ooo = true;
            out.out_of_order.push(OooEvent {
                seq: seg.seq,
                expected: base.wrapping_add(contig_end as u32),
                frame: seg.frame,
            });
        }
        // Find runs already covered.
        let mut runs: Vec<(i64, i64)> = Vec::new();
        let mut i = 0i64;
        while i < len {
            if covered.contains_key(&(off + i)) {
                let start = i;
                while i < len && covered.contains_key(&(off + i)) {
                    i += 1;
                }
                runs.push((start, i));
            } else {
                i += 1;
            }
        }
        let fully = len > 0 && runs.len() == 1 && runs[0].0 == 0 && runs[0].1 == len;
        if fully {
            let identical = (0..len).all(|k| covered[&(off + k)].0 == seg.payload[k as usize]);
            if identical {
                out.retransmissions.push(RetransEvent {
                    seq_start: seg.seq,
                    len: len as u32,
                    frame: seg.frame,
                });
                status = "retransmission";
                out.segments.push(SegView {
                    seq_start: seg.seq,
                    seq_end: seg.seq.wrapping_add(len as u32),
                    len: len as u32,
                    frame: seg.frame,
                    ts: seg.ts,
                    status,
                    out_of_order: ooo,
                });
                continue;
            }
        }
        if !runs.is_empty() {
            status = "overlap";
            for &(s0, e0) in &runs {
                let existing_bytes: Vec<u8> = (s0..e0).map(|k| covered[&(off + k)].0).collect();
                let existing_frame = covered[&(off + s0)].1;
                let incoming_bytes: Vec<u8> =
                    (s0..e0).map(|k| seg.payload[k as usize]).collect();
                out.overlaps.push(OverlapEvent {
                    seq_start: base.wrapping_add((off + s0) as u32),
                    len: (e0 - s0) as u32,
                    existing_frame,
                    incoming_frame: seg.frame,
                    existing_bytes,
                    incoming_bytes,
                    kept: policy.as_str(),
                });
            }
        }
        // Place bytes according to the configured policy.
        for k in 0..len {
            let pos = off + k;
            let b = seg.payload[k as usize];
            match covered.get(&pos) {
                None => {
                    covered.insert(pos, (b, seg.frame));
                }
                Some(_) => {
                    if policy == OverlapPolicy::LastSeen {
                        covered.insert(pos, (b, seg.frame));
                    }
                }
            }
        }
        while covered.contains_key(&contig_end) {
            contig_end += 1;
        }
        out.segments.push(SegView {
            seq_start: seg.seq,
            seq_end: seg.seq.wrapping_add(len as u32),
            len: len as u32,
            frame: seg.frame,
            ts: seg.ts,
            status,
            out_of_order: ooo,
        });
    }

    out.covered_bytes = covered.len() as u64;
    let max_end = covered.keys().next_back().map(|k| k + 1).unwrap_or(0);
    out.max_seq = Some(base.wrapping_add(max_end as u32));
    // Gaps: holes inside [0, max_end).
    let mut cursor = 0i64;
    for (&pos, _) in covered.iter() {
        if pos > cursor {
            out.gaps.push(Gap {
                start: base.wrapping_add(cursor as u32),
                end: base.wrapping_add(pos as u32),
            });
        }
        cursor = cursor.max(pos + 1);
    }
    // Reassembled stream = contiguous prefix up to the first gap.
    let prefix = out
        .gaps
        .first()
        .map(|g| seq_off(g.start, base))
        .unwrap_or(max_end);
    out.reassembled = (0..prefix).map(|k| covered[&k].0).collect();
    out
}
