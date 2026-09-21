//! Per-direction TCP sequence-space reassembly.
//!
//! Coordinates: the first data byte after the ISN is relative offset 0, the SYN
//! occupies -1 and a trailing FIN sits at the first offset past the data. All
//! 32-bit sequence math is expanded into signed 64-bit deltas so wrap-around is
//! handled uniformly.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverlapPolicy {
    FirstSeen,
    LastSeen,
}

impl Default for OverlapPolicy {
    fn default() -> Self {
        OverlapPolicy::FirstSeen
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Interval {
    pub start: i64,
    pub end: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverwriteEvidence {
    pub offset: i64,
    pub kept_frame: usize,
    pub superseded_frame: usize,
    /// Byte retained and byte offered by the losing segment, respectively.
    pub kept_hex: String,
    pub offered_hex: String,
    pub policy: OverlapPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SegmentRecord {
    pub frame_index: usize,
    pub seq: u32,
    pub end_seq: u32,
    pub rel_start: i64,
    pub rel_end: i64,
    pub data_len: usize,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub ack: bool,
    pub classifications: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectionReport {
    pub endpoint: String,
    pub anchored_by_syn: bool,
    pub isn: Option<u32>,
    pub syn: bool,
    pub fin: bool,
    pub fin_rel: Option<i64>,
    pub rst: bool,
    pub rst_seq: Option<u32>,
    pub first_seq: Option<u32>,
    pub last_seq: Option<u32>,
    pub data_rel_range: Interval,
    pub delivered_length: i64,
    pub delivered_hex: String,
    pub gaps: Vec<Interval>,
    pub covered_intervals: Vec<Interval>,
    pub segments: Vec<SegmentRecord>,
    pub retransmit_segments: usize,
    pub conflict_segments: usize,
    pub out_of_order_segments: usize,
    pub overwrite_evidence: Vec<OverwriteEvidence>,
}

struct Cell {
    owner: usize,
    byte: u8,
}

pub struct Direction {
    endpoint: String,
    isn: Option<u32>,
    anchored_by_syn: bool,
    syn_seen: bool,
    fin_seen: bool,
    fin_rel: Option<i64>,
    rst_seen: bool,
    rst_seq: Option<u32>,
    first_seq: Option<u32>,
    last_seq: Option<u32>,
    cells: BTreeMap<i64, Cell>,
    frontier: i64,
    observed_end: i64,
    segments: Vec<SegmentRecord>,
    overwrite_evidence: Vec<OverwriteEvidence>,
    retransmit_segments: usize,
    conflict_segments: usize,
    out_of_order_segments: usize,
}

impl Direction {
    pub fn new(endpoint: String) -> Self {
        Direction {
            endpoint,
            isn: None,
            anchored_by_syn: false,
            syn_seen: false,
            fin_seen: false,
            fin_rel: None,
            rst_seen: false,
            rst_seq: None,
            first_seq: None,
            last_seq: None,
            cells: BTreeMap::new(),
            frontier: 0,
            observed_end: 0,
            segments: segments_init(),
            overwrite_evidence: Vec::new(),
            retransmit_segments: 0,
            conflict_segments: 0,
            out_of_order_segments: 0,
        }
    }

    fn anchor_data(&mut self, first_data_seq: u32) {
        if self.isn.is_none() {
            // Mid-capture anchor: the first observed byte is treated as offset
            // 0 without fabricating an ISN handshake.
            self.isn = Some(first_data_seq.wrapping_sub(1));
            self.anchored_by_syn = false;
        }
    }

    pub fn isn_raw(&self) -> Option<u32> {
        self.isn
    }

    fn rel(&self, raw: u32) -> i64 {
        let isn1 = self.isn.expect("direction must be anchored").wrapping_add(1);
        expand_delta(isn1, raw)
    }

    pub fn add_syn(&mut self, frame_index: usize, seg: &crate::frame::TcpSegment) {
        if self.isn.is_none() {
            self.isn = Some(seg.seq);
            self.anchored_by_syn = true;
        }
        self.syn_seen = true;
        if self.first_seq.is_none() {
            self.first_seq = Some(seg.seq);
        }
        self.last_seq = Some(seg.seq);
        self.segments.push(SegmentRecord {
            frame_index,
            seq: seg.seq,
            end_seq: seg.seq.wrapping_add(1),
            rel_start: -1,
            rel_end: 0,
            data_len: 0,
            syn: true,
            fin: seg.fin(),
            rst: seg.rst(),
            ack: seg.ack_flag(),
            classifications: vec!["syn".to_string()],
        });
    }

    /// Insert one data-carrying (and/or FIN) segment.
    pub fn add_data(
        &mut self,
        frame_index: usize,
        seg: &crate::frame::TcpSegment,
        policy: OverlapPolicy,
    ) {
        if seg.payload.is_empty() && !seg.syn() && !seg.fin() && !seg.rst() {
            // Pure ACK: no sequence-space contribution.
            return;
        }
        if self.isn.is_none() {
            if seg.syn() {
                self.isn = Some(seg.seq);
                self.anchored_by_syn = true;
                self.syn_seen = true;
            } else {
                self.anchor_data(seg.seq);
            }
        } else if seg.syn() {
            self.syn_seen = true;
        }
        if self.first_seq.is_none() {
            self.first_seq = Some(seg.seq);
        }
        self.last_seq = Some(seg.seq.wrapping_add(seg.seq_len()));

        let data_seq = if seg.syn() {
            seg.seq.wrapping_add(1)
        } else {
            seg.seq
        };
        let start = self.rel(data_seq);
        let end = start + seg.payload.len() as i64;

        let mut classifications = BTreeSet::new();
        if seg.syn() {
            classifications.insert("syn".to_string());
        }
        if seg.rst() {
            classifications.insert("rst".to_string());
            self.rst_seen = true;
            self.rst_seq = Some(seg.seq);
        }

        // Coverage analysis before mutation.
        let mut existing_bytes = 0usize;
        let mut differing = false;
        for (i, b) in seg.payload.iter().enumerate() {
            if let Some(cell) = self.cells.get(&(start + i as i64)) {
                existing_bytes += 1;
                if cell.byte != *b {
                    differing = true;
                }
            }
        }
        let fully_covered = !seg.payload.is_empty() && existing_bytes == seg.payload.len();
        let was_beyond_frontier = start > self.frontier;
        if fully_covered {
            classifications.insert("retransmission".to_string());
            self.retransmit_segments += 1;
        } else if existing_bytes > 0 {
            classifications.insert("overlap".to_string());
            if differing {
                classifications.insert("overlap-conflict".to_string());
                self.conflict_segments += 1;
            } else {
                classifications.insert("retransmission".to_string());
                self.retransmit_segments += 1;
            }
        }
        if was_beyond_frontier {
            classifications.insert("out-of-order".to_string());
            self.out_of_order_segments += 1;
        }

        // Byte-level merge under the configured policy.
        for (i, b) in seg.payload.iter().enumerate() {
            let pos = start + i as i64;
            if let Some(existing) = self.cells.get(&pos) {
                if existing.byte == *b || policy == OverlapPolicy::FirstSeen {
                    if existing.byte != *b {
                        self.overwrite_evidence.push(OverwriteEvidence {
                            offset: pos,
                            kept_frame: existing.owner,
                            superseded_frame: frame_index,
                            kept_hex: crate::hash::hex(&[existing.byte]),
                            offered_hex: crate::hash::hex(&[*b]),
                            policy,
                        });
                    }
                    continue;
                }
                // Last-seen replacement.
                self.overwrite_evidence.push(OverwriteEvidence {
                    offset: pos,
                    kept_frame: frame_index,
                    superseded_frame: existing.owner,
                    kept_hex: crate::hash::hex(&[*b]),
                    offered_hex: crate::hash::hex(&[existing.byte]),
                    policy,
                });
                self.cells.insert(pos, Cell { owner: frame_index, byte: *b });
            } else {
                self.cells.insert(pos, Cell { owner: frame_index, byte: *b });
            }
        }

        if end > self.observed_end {
            self.observed_end = end;
        }
        if seg.fin() {
            self.fin_seen = true;
            self.fin_rel = Some(end);
            classifications.insert("fin".to_string());
        }

        // Advance the contiguous delivery frontier.
        let before = self.frontier;
        while self.cells.contains_key(&self.frontier) {
            self.frontier += 1;
        }
        if !was_beyond_frontier && self.frontier > before {
            classifications.insert("extends-delivered".to_string());
        } else if was_beyond_frontier && start <= before {
            classifications.insert("gap-filling".to_string());
        }

        let mut order: Vec<String> = classifications.into_iter().collect();
        order.sort();
        self.segments.push(SegmentRecord {
            frame_index,
            seq: seg.seq,
            end_seq: seg.seq.wrapping_add(seg.seq_len()),
            rel_start: start,
            rel_end: end,
            data_len: seg.payload.len(),
            syn: seg.syn(),
            fin: seg.fin(),
            rst: seg.rst(),
            ack: seg.ack_flag(),
            classifications: order,
        });
    }

    pub fn finalize(self) -> DirectionReport {
        let mut delivered = Vec::with_capacity(self.frontier.max(0) as usize);
        for pos in 0..self.frontier {
            delivered.push(self.cells.get(&pos).map(|c| c.byte).unwrap_or(0));
        }
        let mut gaps = Vec::new();
        let mut cursor = 0i64;
        while cursor < self.observed_end {
            if self.cells.contains_key(&cursor) {
                cursor += 1;
            } else {
                let start = cursor;
                while cursor < self.observed_end && !self.cells.contains_key(&cursor) {
                    cursor += 1;
                }
                gaps.push(Interval { start, end: cursor });
            }
        }
        DirectionReport {
            endpoint: self.endpoint,
            anchored_by_syn: self.anchored_by_syn,
            isn: self.isn,
            syn: self.syn_seen,
            fin: self.fin_seen,
            fin_rel: self.fin_rel,
            rst: self.rst_seen,
            rst_seq: self.rst_seq,
            first_seq: self.first_seq,
            last_seq: self.last_seq,
            data_rel_range: Interval { start: 0, end: self.observed_end },
            delivered_length: self.frontier,
            delivered_hex: crate::hash::hex(&delivered),
            gaps,
            covered_intervals: compress_intervals(&self.cells),
            segments: self.segments,
            retransmit_segments: self.retransmit_segments,
            conflict_segments: self.conflict_segments,
            out_of_order_segments: self.out_of_order_segments,
            overwrite_evidence: self.overwrite_evidence,
        }
    }
}

fn segments_init() -> Vec<SegmentRecord> {
    Vec::new()
}

fn compress_intervals(cells: &BTreeMap<i64, Cell>) -> Vec<Interval> {
    let mut out = Vec::new();
    let mut start = None;
    let mut prev = 0i64;
    for &pos in cells.keys() {
        match start {
            None => {
                start = Some(pos);
                prev = pos;
            }
            Some(s) => {
                if pos == prev + 1 {
                    prev = pos;
                } else {
                    out.push(Interval { start: s, end: prev + 1 });
                    start = Some(pos);
                    prev = pos;
                }
            }
        }
    }
    if let Some(s) = start {
        out.push(Interval { start: s, end: prev + 1 });
    }
    out
}

/// Expand a 32-bit raw sequence into a signed delta relative to `base`, choosing
/// the candidate on the same wrap whose absolute distance is smallest. Valid for
/// segments within ~2 GiB of each other — far larger than any fixture window.
pub fn expand_delta(base: u32, raw: u32) -> i64 {
    let diff = raw.wrapping_sub(base) as i32;
    diff as i64
}
