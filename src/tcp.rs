//! TCP sequence-space tracking and per-direction reassembly.
//!
//! Sequence numbers are compared per RFC 1982 style 32-bit wrap semantics.
//! Internally every position is unwrapped onto a signed i64 line relative to
//! the direction's anchor (the SYN's ISN when seen, otherwise the earliest
//! observed data byte of a partial capture). Overlapping bytes implement a
//! configurable `first-seen` / `last-seen` policy, and every overwritten byte
//! is preserved in the evidence trail.

use std::collections::BTreeMap;

use crate::json::Json;
use crate::sha256;
use crate::wire::{TcpSegment, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};

/// Signed modular distance from `a` to `b` on the u32 ring.
pub fn rel32(a: u32, b: u32) -> i64 {
    b.wrapping_sub(a) as i32 as i64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapPolicy {
    FirstSeen,
    LastSeen,
}

impl OverlapPolicy {
    pub fn name(self) -> &'static str {
        match self {
            OverlapPolicy::FirstSeen => "first-seen",
            OverlapPolicy::LastSeen => "last-seen",
        }
    }
    pub fn parse(s: &str) -> Option<OverlapPolicy> {
        match s {
            "first-seen" => Some(OverlapPolicy::FirstSeen),
            "last-seen" => Some(OverlapPolicy::LastSeen),
            _ => None,
        }
    }
}

/// One winning byte block (half-open, positions on the unwrapped line).
#[derive(Debug, Clone)]
struct Block {
    data: Vec<u8>,
    /// Original frame number that owns these bytes under current policy.
    owner: u64,
    owner_hash: String,
}

#[derive(Debug, Clone)]
struct OverwriteGroup {
    frame_seq: u64,
    frame_hash: String,
    /// Absolute intervals (relative to anchor) where this frame lost bytes.
    ranges: Vec<(i64, i64)>,
    lost: u64,
}

#[derive(Debug, Clone)]
struct GapOpen {
    start: i64,
    opened_by: u64,
    opened_at: (u64, u64),
}

#[derive(Debug, Clone)]
struct ControlMark {
    kind: String,
    seq_endpoint: u32,
    absolute: i64,
    frame_seq: u64,
    frame_hash: String,
    timestamp: u64,
}

/// Evidence about a single incoming TCP segment on one direction.
#[derive(Debug, Clone)]
pub struct SegmentRecord {
    pub frame_seq: u64,
    pub frame_hash: String,
    pub timestamp: u64,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload_len: u64,
    pub payload_sha256: String,
    pub abs_start: Option<i64>,
    pub abs_end: Option<i64>,
    pub classification: String,
    pub accepted: u64,
    pub overwritten: u64,
    pub lost: u64,
    pub wrap_cross: bool,
}

#[derive(Debug, Clone)]
pub struct DirectionStream {
    label: String,
    /// SYN ISN unwrapped to the zero point, if the handshake was observed.
    syn_isn: Option<u32>,
    anchor: Option<u32>,
    anchor_is_syn: bool,
    blocks: BTreeMap<i64, Block>,
    overwrites: Vec<OverwriteGroup>,
    segments: Vec<SegmentRecord>,
    gaps_open: Vec<GapOpen>,
    gaps_closed: Vec<Json>,
    fin_marks: Vec<ControlMark>,
    rst_marks: Vec<ControlMark>,
    /// Highest absolute position ever reached (frontier candidate).
    high_water: i64,
    /// Lowest absolute position ever anchored with data/control.
    low_water: i64,
    total_overlapping: u64,
    duplicate_segments: u64,
    retransmissions: u64,
    out_of_order: u64,
}

impl DirectionStream {
    pub fn new(label: String) -> Self {
        DirectionStream {
            label,
            syn_isn: None,
            anchor: None,
            anchor_is_syn: false,
            blocks: BTreeMap::new(),
            overwrites: Vec::new(),
            segments: Vec::new(),
            gaps_open: Vec::new(),
            gaps_closed: Vec::new(),
            fin_marks: Vec::new(),
            rst_marks: Vec::new(),
            high_water: i64::MIN,
            low_water: i64::MAX,
            total_overlapping: 0,
            duplicate_segments: 0,
            retransmissions: 0,
            out_of_order: 0,
        }
    }

    /// Convert a 32-bit sequence number onto the unwrapped line.
    fn unwrap(&self, seq: u32) -> i64 {
        match self.anchor {
            Some(a) => rel32(a, seq),
            None => 0,
        }
    }

    fn set_anchor(&mut self, seq: u32, is_syn: bool) {
        if self.anchor.is_none() {
            self.anchor = Some(seq);
            self.anchor_is_syn = is_syn;
            if is_syn {
                self.syn_isn = Some(seq);
            }
            self.high_water = 0;
            self.low_water = 0;
        }
    }

    /// Process one segment. Returns a human-readable classification.
    pub fn ingest(&mut self, seg: &TcpSegment, policy: OverlapPolicy) {
        if seg.syn() && self.anchor.is_none() {
            self.set_anchor(seg.seq, true);
        }

        let len = seg.payload.len() as u64;
        let has_data = len > 0;

        // Detect sequence wraparound inside this data segment.
        let wrap_cross = has_data
            && seg
                .seq
                .checked_add(len as u32 - 1)
                .map(|last| last < seg.seq)
                .unwrap_or(true);

        let mut abs_start = None;
        let mut abs_end = None;
        let mut classification;
        let mut accepted = 0u64;
        let mut overwritten = 0u64;
        let mut lost = 0u64;

        if has_data {
            // For a partial capture with no anchor, anchor at this segment.
            if self.anchor.is_none() {
                self.set_anchor(seg.seq, false);
            }
            let start = self.unwrap(seg.seq);
            let end = start + len as i64;
            abs_start = Some(start);
            abs_end = Some(end);

            self.low_water = self.low_water.min(start);
            let cover_end_before = self.covered_end();
            let data_start_before = self.first_data_pos();

            if start < cover_end_before {
                // Overlaps bytes already covered.
                if start >= data_start_before.unwrap_or(i64::MAX)
                    && end <= cover_end_before
                    && self.range_content_equals(start, end, &seg.payload)
                {
                    classification = "duplicate";
                    self.duplicate_segments += 1;
                } else if start >= data_start_before.unwrap_or(i64::MAX)
                    && end <= cover_end_before
                {
                    classification = "retransmission-conflicting";
                    self.retransmissions += 1;
                } else {
                    classification = "retransmission-partial-overlap";
                    self.retransmissions += 1;
                }
                let (acc, ov, ls) = self.merge_bytes(seg, start, &seg.payload, policy);
                accepted = acc;
                overwritten = ov;
                lost = ls;
            } else if start == cover_end_before {
                classification = "in-order";
                let (acc, _, _) = self.merge_bytes(seg, start, &seg.payload, policy);
                accepted = acc;
            } else {
                // start > cover_end_before: creates or lands in a gap.
                classification = "out-of-order";
                self.out_of_order += 1;
                let (acc, _, _) = self.merge_bytes(seg, start, &seg.payload, policy);
                accepted = acc;
                self.note_gap_for(seg, start);
            }
            self.high_water = self.high_water.max(end);
        } else {
            classification = "control-only";
            if self.anchor.is_none() {
                // Pure ACK/RST with no anchor yet: use its seq for ordering
                // space but never fabricate a handshake.
                self.set_anchor(seg.seq, false);
            }
        }

        let abs_pos = self.unwrap(seg.seq);
        self.low_water = self.low_water.min(abs_pos);
        self.high_water = self.high_water.max(abs_pos);

        if seg.fin() {
            let fin_endpoint = if has_data {
                seg.seq.wrapping_add(len as u32)
            } else {
                seg.seq
            };
            self.fin_marks.push(ControlMark {
                kind: "FIN".into(),
                seq_endpoint: fin_endpoint,
                absolute: self.unwrap(fin_endpoint),
                frame_seq: seg.frame_seq,
                frame_hash: seg.frame_hash.clone(),
                timestamp: seg.seen_at.0,
            });
        }
        if seg.rst() {
            self.rst_marks.push(ControlMark {
                kind: "RST".into(),
                seq_endpoint: seg.seq,
                absolute: abs_pos,
                frame_seq: seg.frame_seq,
                frame_hash: seg.frame_hash.clone(),
                timestamp: seg.seen_at.0,
            });
        }

        // After merging, see whether any open gaps got filled.
        self.update_gaps();

        self.total_overlapping += overwritten;

        self.segments.push(SegmentRecord {
            frame_seq: seg.frame_seq,
            frame_hash: seg.frame_hash.clone(),
            timestamp: seg.seen_at.0,
            seq: seg.seq,
            ack: seg.ack,
            flags: seg.flags,
            payload_len: len,
            payload_sha256: sha256::hex(&sha256::hash(&seg.payload)),
            abs_start,
            abs_end,
            classification: classification.to_string(),
            accepted,
            overwritten,
            lost,
            wrap_cross,
        });
    }

    fn first_data_pos(&self) -> Option<i64> {
        self.blocks.keys().next().copied()
    }

    /// End of the contiguous cover starting at the earliest present byte.
    fn covered_end(&self) -> i64 {
        let Some((&first, _)) = self.blocks.iter().next() else {
            return 0;
        };
        let mut pos = first;
        for (&s, block) in &self.blocks {
            if s == pos {
                pos = s + block.data.len() as i64;
            } else if s > pos {
                break;
            }
        }
        pos
    }

    fn range_content_equals(&self, start: i64, end: i64, data: &[u8]) -> bool {
        let mut off = 0usize;
        for (&s, block) in &self.blocks {
            let b_end = s + block.data.len() as i64;
            if b_end <= start {
                continue;
            }
            if s >= end {
                break;
            }
            let lo = start.max(s);
            let hi = end.min(b_end);
            let existing = &block.data[(lo - s) as usize..(hi - s) as usize];
            if &data[off..off + (hi - lo) as usize] != existing {
                return false;
            }
            off += (hi - lo) as usize;
        }
        off == (end - start) as usize
    }

    /// Merge incoming payload, returning (accepted_bytes, overwritten_bytes,
    /// lost_by_incoming_bytes).
    fn merge_bytes(
        &mut self,
        seg: &TcpSegment,
        start: i64,
        data: &[u8],
        policy: OverlapPolicy,
    ) -> (u64, u64, u64) {
        let end = start + data.len() as i64;
        let mut overwritten = 0u64;
        let mut lost_ranges: Vec<(i64, i64)> = Vec::new();

        match policy {
            OverlapPolicy::FirstSeen => {
                // Insert only pieces not already owned; existing bytes win.
                let mut cuts: Vec<(i64, i64)> = vec![(start, end)];
                for (&s, block) in self.blocks.iter() {
                    let b_end = s + block.data.len() as i64;
                    let mut next = Vec::new();
                    for (a, b) in cuts {
                        if b <= s || a >= b_end {
                            next.push((a, b));
                        } else {
                            let lo = a.max(s);
                            let hi = b.min(b_end);
                            lost_ranges.push((lo, hi));
                            if a < lo {
                                next.push((a, lo));
                            }
                            if hi < b {
                                next.push((hi, b));
                            }
                        }
                    }
                    cuts = next;
                }
                let mut accepted = 0u64;
                for (a, b) in cuts {
                    if b > a {
                        let chunk = data[(a - start) as usize..(b - start) as usize].to_vec();
                        accepted += chunk.len() as u64;
                        self.blocks.insert(
                            a,
                            Block {
                                data: chunk,
                                owner: seg.frame_seq,
                                owner_hash: seg.frame_hash.clone(),
                            },
                        );
                    }
                }
                let lost: u64 = lost_ranges
                    .iter()
                    .map(|(a, b)| (b - a) as u64)
                    .sum();
                if lost > 0 {
                    self.record_lost(seg.frame_seq, seg.frame_hash.clone(), lost_ranges, lost);
                }
                (accepted, 0, lost)
            }
            OverlapPolicy::LastSeen => {
                // Incoming wins; split/remove existing blocks and keep evidence.
                let mut displaced: BTreeMap<u64, OverwriteGroup> = BTreeMap::new();
                let existing: Vec<(i64, i64, u64, Vec<u8>)> = self
                    .blocks
                    .iter()
                    .map(|(s, b)| (*s, s + b.data.len() as i64, b.owner, b.data.clone()))
                    .collect();
                for (s, b_end, owner, bytes) in existing {
                    if b_end <= start || s >= end {
                        continue;
                    }
                    let lo = s.max(start);
                    let hi = b_end.min(end);
                    overwritten += (hi - lo) as u64;
                    let lost_slice =
                        bytes[(lo - s) as usize..(hi - s) as usize].to_vec();
                    let group = displaced.entry(owner).or_insert_with(|| OverwriteGroup {
                        frame_seq: owner,
                        frame_hash: String::new(),
                        ranges: Vec::new(),
                        lost: 0,
                    });
                    group.ranges.push((lo, hi));
                    group.lost += (hi - lo) as u64;
                    // Resolve hash lazily below; stash in range payload map.
                    group.frame_hash = sha256::hex(&sha256::hash(&lost_slice));

                    self.blocks.remove(&s);
                    if lo > s {
                        self.blocks.insert(
                            s,
                            Block {
                                data: bytes[..(lo - s) as usize].to_vec(),
                                owner,
                                owner_hash: self
                                    .blocks
                                    .iter()
                                    .find(|(_, b)| b.owner == owner)
                                    .map(|(_, b)| b.owner_hash.clone())
                                    .unwrap_or_default(),
                            },
                        );
                    }
                    if hi < b_end {
                        self.blocks.insert(
                            hi,
                            Block {
                                data: bytes[(hi - s) as usize..].to_vec(),
                                owner,
                                owner_hash: self
                                    .blocks
                                    .iter()
                                    .find(|(_, b)| b.owner == owner)
                                    .map(|(_, b)| b.owner_hash.clone())
                                    .unwrap_or_default(),
                            },
                        );
                    }
                }
                for (_, g) in displaced {
                    let g = OverwriteGroup {
                        frame_hash: g.frame_hash,
                        ..g
                    };
                    self.overwrites.push(g);
                }
                self.blocks.insert(
                    start,
                    Block {
                        data: data.to_vec(),
                        owner: seg.frame_seq,
                        owner_hash: seg.frame_hash.clone(),
                    },
                );
                (data.len() as u64, overwritten, 0)
            }
        }
    }

    fn record_lost(
        &mut self,
        frame_seq: u64,
        frame_hash: String,
        ranges: Vec<(i64, i64)>,
        lost: u64,
    ) {
        self.overwrites.push(OverwriteGroup {
            frame_seq,
            frame_hash,
            ranges,
            lost,
        });
    }

    fn note_gap_for(&mut self, seg: &TcpSegment, start: i64) {
        let frontier = self.covered_end();
        if start > frontier {
            if !self
                .gaps_open
                .iter()
                .any(|g| g.start == frontier && start >= g.start)
            {
                self.gaps_open.push(GapOpen {
                    start: frontier,
                    opened_by: seg.frame_seq,
                    opened_at: seg.seen_at,
                });
            }
        }
    }

    fn update_gaps(&mut self) {
        let covered = self.covered_end();
        let mut still_open = Vec::new();
        for g in self.gaps_open.drain(..) {
            if covered > g.start {
                self.gaps_closed.push(
                    Json::obj()
                        .with("start", Json::from(g.start))
                        .with("end", Json::from(covered))
                        .with("bytes", Json::from((covered - g.start) as u64))
                        .with("opened_by", Json::from(g.opened_by))
                        .with(
                            "closed_at_ts",
                            Json::Num(g.opened_at.0.to_string()),
                        ),
                );
            } else {
                still_open.push(g);
            }
        }
        self.gaps_open = still_open;
    }

    fn to_seq32(&self, abs: i64) -> u32 {
        let anchor = self.anchor.unwrap_or(0);
        anchor.wrapping_add(abs as u32)
    }

    /// Contiguous prefix from the earliest observed byte.
    pub fn reassembled_bytes(&self) -> Vec<u8> {
        let Some((first, _)) = self.blocks.iter().next() else {
            return Vec::new();
        };
        let mut pos = *first;
        let mut out = Vec::new();
        for (&s, block) in &self.blocks {
            if s == pos {
                out.extend_from_slice(&block.data);
                pos = s + block.data.len() as i64;
            } else if s > pos {
                break;
            }
        }
        out
    }

    pub fn finalize(&mut self) -> Json {
        self.update_gaps();

        // Build sorted coverage intervals in *relative* coordinates
        // (relative to direction anchor; SYN space keeps byte 0 as ISN).
        let mut coverage: Vec<Json> = Vec::new();
        for (&s, block) in &self.blocks {
            let e = s + block.data.len() as i64;
            coverage.push(
                Json::obj()
                    .with("abs_start", Json::Num(s.to_string()))
                    .with("abs_end", Json::Num(e.to_string()))
                    .with("seq_start", Json::Num(self.to_seq32(s).to_string()))
                    .with("seq_end_exclusive", Json::Num(self.to_seq32(e).to_string()))
                    .with("bytes", Json::from(block.data.len()))
                    .with("owner_frame", Json::from(block.owner)),
            );
        }

        let prefix = self.reassembled_bytes();
        let prefix_end = if self.blocks.is_empty() {
            0
        } else {
            let first = *self.blocks.keys().next().unwrap();
            first + prefix.len() as i64
        };
        let first_data = self.first_data_pos();

        // Remaining holes in observed range (up to high-water of data).
        let mut holes: Vec<Json> = Vec::new();
        if let Some(first) = first_data {
            let mut pos = first;
            for (&s, block) in &self.blocks {
                if s > pos {
                    holes.push(
                        Json::obj()
                            .with("abs_start", Json::Num(pos.to_string()))
                            .with("abs_end", Json::Num(s.to_string()))
                            .with("bytes", Json::from((s - pos) as u64))
                            .with("seq_start", Json::Num(self.to_seq32(pos).to_string()))
                            .with("seq_end_exclusive", Json::Num(self.to_seq32(s).to_string())),
                    );
                }
                pos = pos.max(s + block.data.len() as i64);
            }
        }

        let open_gaps: Vec<Json> = self
            .gaps_open
            .iter()
            .map(|g| {
                Json::obj()
                    .with("abs_start", Json::Num(g.start.to_string()))
                    .with("opened_by", Json::from(g.opened_by))
                    .with("opened_at_ts", Json::Num(g.opened_at.0.to_string()))
            })
            .collect();

        let marks = |marks: &[ControlMark]| -> Vec<Json> {
            marks
                .iter()
                .map(|m| {
                    Json::obj()
                        .with("kind", Json::from(m.kind.as_str()))
                        .with("seq", Json::Num(m.seq_endpoint.to_string()))
                        .with("absolute", Json::Num(m.absolute.to_string()))
                        .with("frame", Json::from(m.frame_seq))
                        .with("frame_sha256", Json::from(m.frame_hash.as_str()))
                        .with("ts_micros", Json::Num(m.timestamp.to_string()))
                })
                .collect()
        };

        let overwrites: Vec<Json> = self
            .overwrites
            .iter()
            .map(|g| {
                let ranges: Vec<Json> = g
                    .ranges
                    .iter()
                    .map(|r| {
                        Json::obj()
                            .with("abs_start", Json::Num(r.0.to_string()))
                            .with("abs_end", Json::Num(r.1.to_string()))
                            .with("bytes", Json::from((r.1 - r.0) as u64))
                            .with("seq_start", Json::Num(self.to_seq32(r.0).to_string()))
                    })
                    .collect();
                Json::obj()
                    .with("frame", Json::from(g.frame_seq))
                    .with("frame_sha256", Json::from(g.frame_hash.as_str()))
                    .with("ranges", Json::Array(ranges))
                    .with("total_bytes", Json::from(g.lost))
            })
            .collect();

        let segs: Vec<Json> = self
            .segments
            .iter()
            .map(|r| {
                let mut o = Json::obj()
                    .with("frame", Json::from(r.frame_seq))
                    .with("frame_sha256", Json::from(r.frame_hash.as_str()))
                    .with("ts_micros", Json::Num(r.timestamp.to_string()))
                    .with("seq", Json::Num(r.seq.to_string()))
                    .with("ack", Json::Num(r.ack.to_string()))
                    .with("flags", Json::from(flag_names(r.flags).as_str()))
                    .with("payload_len", Json::from(r.payload_len))
                    .with("payload_sha256", Json::from(r.payload_sha256.as_str()))
                    .with("classification", Json::from(r.classification.as_str()))
                    .with("accepted_bytes", Json::from(r.accepted))
                    .with("overwritten_by_new", Json::from(r.overwritten))
                    .with("bytes_lost_to_policy", Json::from(r.lost))
                    .with("crosses_u32_wrap", Json::Bool(r.wrap_cross));
                if let Some(s) = r.abs_start {
                    o.put("abs_start", Json::Num(s.to_string()));
                }
                if let Some(e) = r.abs_end {
                    o.put("abs_end", Json::Num(e.to_string()));
                }
                o
            })
            .collect();

        let data_start_abs = first_data;
        let data_end_abs = self.high_water;

        Json::obj()
            .with("direction", Json::from(self.label.as_str()))
            .with(
                "handshake_seen",
                Json::Bool(self.syn_isn.is_some()),
            )
            .with(
                "anchor_isn",
                self.syn_isn
                    .map(|i| Json::Num(i.to_string()))
                    .unwrap_or(Json::Null),
            )
            .with(
                "anchor_is_partial_data",
                Json::Bool(self.anchor.is_some() && !self.anchor_is_syn && self.syn_isn.is_none()),
            )
            .with(
                "abs_data_start",
                data_start_abs.map(|v| Json::Num(v.to_string())).unwrap_or(Json::Null),
            )
            .with(
                "abs_data_end_high_water",
                Json::Num(data_end_abs.to_string()),
            )
            .with("segments", Json::Array(segs))
            .with("coverage", Json::Array(coverage))
            .with("holes", Json::Array(holes))
            .with("gaps_opened_then_filled", Json::Array(self.gaps_closed.clone()))
            .with("gaps_still_open", Json::Array(open_gaps))
            .with("retransmissions", Json::from(self.retransmissions))
            .with("duplicates", Json::from(self.duplicate_segments))
            .with("out_of_order_segments", Json::from(self.out_of_order))
            .with("overlapping_bytes_total", Json::from(self.total_overlapping))
            .with("overwrite_evidence", Json::Array(overwrites))
            .with("fin_marks", Json::Array(marks(&self.fin_marks)))
            .with("rst_marks", Json::Array(marks(&self.rst_marks)))
            .with(
                "contiguous_prefix_bytes",
                Json::from(prefix.len() as u64),
            )
            .with(
                "contiguous_prefix_abs_start",
                Json::Num(first_data.unwrap_or(0).to_string()),
            )
            .with(
                "contiguous_prefix_abs_end",
                Json::Num(prefix_end.to_string()),
            )
            .with(
                "contiguous_prefix_sha256",
                Json::from(sha256::hex(&sha256::hash(&prefix)).as_str()),
            )
    }

    pub fn prefix_for_download(&self) -> Vec<u8> {
        self.reassembled_bytes()
    }
}

pub fn flag_names(flags: u8) -> String {
    let mut names = Vec::new();
    if flags & TCP_FIN != 0 {
        names.push("FIN");
    }
    if flags & TCP_SYN != 0 {
        names.push("SYN");
    }
    if flags & TCP_RST != 0 {
        names.push("RST");
    }
    if flags & TCP_PSH != 0 {
        names.push("PSH");
    }
    if flags & TCP_ACK != 0 {
        names.push("ACK");
    }
    if names.is_empty() {
        "NONE".into()
    } else {
        names.join("|")
    }
}
