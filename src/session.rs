//! Bidirectional session merging and connection-generation tracking.
//!
//! A flow key is the unordered endpoint pair (canonical four-tuple). Multiple
//! generations can share a key; SYN / FIN / RST / idle timeout decide when one
//! generation ends and a reused connection begins. Mid-capture generations are
//! explicitly `partial` and never gain a fabricated handshake.

use crate::frame::TcpSegment;
use crate::reasm::{Direction, OverlapPolicy};
use crate::types::Endpoint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct FlowKey {
    pub low: Endpoint,
    pub high: Endpoint,
}

impl FlowKey {
    pub fn new(a: Endpoint, b: Endpoint) -> Self {
        if a <= b {
            FlowKey { low: a, high: b }
        } else {
            FlowKey { low: b, high: a }
        }
    }
    fn label(&self) -> String {
        format!("{} <-> {}", self.low, self.high)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub frame_index: usize,
    pub timestamp: f64,
    pub kind: String,
    pub endpoint: String,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    /// Both directions saw FIN and each FIN was acknowledged.
    FinGraceful,
    Reset,
    /// A later SYN on the same four-tuple superseded this generation.
    Superseded,
    /// Idle gap before a later data exceeded the configured timeout.
    Timeout,
    /// Capture ended with no closure observed.
    CaptureEnd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeState {
    /// Full three-way handshake completed.
    Completed,
    /// One or more SYNs seen but handshake did not finish.
    Incomplete,
    /// Capture started in the middle; no handshake was ever observed.
    Partial,
}

struct DirTrack {
    dir: Direction,
    syn_acked: bool,
    fin_seen: bool,
    fin_seq_raw: Option<u32>,
    fin_acked_by_peer: bool,
}

struct Generation {
    id: usize,
    key: FlowKey,
    started_at: f64,
    last_activity: f64,
    first_frame: usize,
    last_frame: usize,
    handshake: HandshakeState,
    // Endpoints that sent SYN / SYN+ACK, by their own endpoint key.
    syn_from: BTreeMap<Endpoint, bool>,
    closed: bool,
    close_reason: Option<CloseReason>,
    a2b: DirTrack,
    b2a: DirTrack,
    events: Vec<TimelineEvent>,
    frame_indices: std::collections::BTreeSet<usize>,
}

fn dir_track(endpoint: String) -> DirTrack {
    DirTrack {
        dir: Direction::new(endpoint),
        syn_acked: false,
        fin_seen: false,
        fin_seq_raw: None,
        fin_acked_by_peer: false,
    }
}

impl DirTrack {
    fn isn(&self) -> Option<u32> {
        self.dir.isn_raw()
    }
}

enum SynAction {
    /// Segment belongs to the current generation.
    Join,
    /// Current generation must be closed and a new one started.
    Reuse,
}

impl Generation {
    /// Decide how an incoming SYN relates to this generation.
    fn syn_action(&self, src: &Endpoint, seg: &TcpSegment) -> SynAction {
        let sender_isn_same = self
            .track_ref(src)
            .map(|t| t.isn() == Some(seg.seq))
            .unwrap_or(false);
        if seg.ack_flag() {
            // SYN-ACK that acknowledges the peer's seen SYN completes the open
            // handshake; anything else starts a new generation.
            let peer_ack_ok = self
                .track_ref(&self.peer_of(src))
                .map(|t| t.isn().map(|isn| seg.ack == isn.wrapping_add(1)).unwrap_or(false))
                .unwrap_or(false);
            if self.handshake == HandshakeState::Incomplete && peer_ack_ok {
                SynAction::Join
            } else {
                SynAction::Reuse
            }
        } else if self.handshake == HandshakeState::Incomplete
            && !self.closed
            && sender_isn_same
        {
            // Retransmitted initial SYN.
            SynAction::Join
        } else {
            SynAction::Reuse
        }
    }

    fn peer_of(&self, src: &Endpoint) -> Endpoint {
        if src == &self.key.low {
            self.key.high.clone()
        } else {
            self.key.low.clone()
        }
    }

    fn track_ref(&self, src: &Endpoint) -> Option<&DirTrack> {
        if src == &self.key.low {
            Some(&self.a2b)
        } else if src == &self.key.high {
            Some(&self.b2a)
        } else {
            None
        }
    }

}

impl Generation {
    fn track(&mut self, src: &Endpoint) -> &mut DirTrack {
        if src == &self.key.low {
            &mut self.a2b
        } else {
            &mut self.b2a
        }
    }

    fn peer_track(&mut self, src: &Endpoint) -> &mut DirTrack {
        if src == &self.key.low {
            &mut self.b2a
        } else {
            &mut self.a2b
        }
    }

    fn push(&mut self, frame_index: usize, ts: f64, kind: &str, ep: &Endpoint, detail: Option<String>) {
        self.events.push(TimelineEvent {
            frame_index,
            timestamp: ts,
            kind: kind.to_string(),
            endpoint: ep.to_string(),
            detail,
        });
    }

    /// Feed a segment whose direction is identified by `src`.
    fn feed(
        &mut self,
        frame_index: usize,
        ts: f64,
        src: &Endpoint,
        dst: &Endpoint,
        seg: &TcpSegment,
        policy: OverlapPolicy,
    ) {
        self.last_activity = ts;
        self.last_frame = frame_index;
        self.frame_indices.insert(frame_index);

        // Sequence-space contribution first (anchors on SYN if present).
        self.track(src).dir.add_data(frame_index, seg, policy);

        let sender_syn = seg.syn();
        let sender_fin = seg.fin();
        let sender_rst = seg.rst();
        let sender_ack = seg.ack_flag();

        if sender_syn {
            self.syn_from.insert(src.clone(), seg.ack_flag());
            self.push(frame_index, ts, "syn", src, None);
        }
        if sender_fin {
            let track = self.track(src);
            track.fin_seen = true;
            // FIN consumes one sequence number after any data.
            track.fin_seq_raw = Some(seg.seq.wrapping_add(seg.payload.len() as u32));
            self.push(frame_index, ts, "fin", src, None);
        }
        if sender_rst {
            self.push(frame_index, ts, "rst", src, None);
            self.closed = true;
            self.close_reason = Some(CloseReason::Reset);
        }

        // ACK can acknowledge the peer's SYN and/or FIN.
        if sender_ack {
            // SYN ack: ack == peer_isn + 1.
            let peer = self.peer_track(src);
            if let Some(peer_isn) = peer.dir.isn_raw() {
                if seg.ack == peer_isn.wrapping_add(1) && !peer.syn_acked {
                    peer.syn_acked = true;
                }
            }
            // FIN ack: FIN occupies one seq after data, so the ack that covers
            // it is fin_seq + 1.
            let peer = self.peer_track(src);
            if let Some(fin_seq) = peer.fin_seq_raw {
                let want = fin_seq.wrapping_add(1);
                if seq_ge(seg.ack, want) {
                    if !peer.fin_acked_by_peer {
                        peer.fin_acked_by_peer = true;
                        self.push(frame_index, ts, "fin_acked", dst, None);
                    }
                }
            }
        }

        if !sender_rst
            && !matches!(self.handshake, HandshakeState::Partial)
            && self.syn_from.len() == 2
            && self.a2b.syn_acked
            && self.b2a.syn_acked
        {
            self.handshake = HandshakeState::Completed;
            self.push(frame_index, ts, "handshake_complete", src, None);
        }

        if !self.closed {
            let f1 = self.a2b.fin_seen && self.a2b.fin_acked_by_peer;
            let f2 = self.b2a.fin_seen && self.b2a.fin_acked_by_peer;
            if f1 && f2 {
                self.closed = true;
                self.close_reason = Some(CloseReason::FinGraceful);
                self.push(frame_index, ts, "graceful_close", src, None);
            }
        }
    }
}

/// Modular 32-bit sequence comparison: `a >= b` in sequence space.
fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

use crate::reasm::DirectionReport;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionReport {
    pub session_id: usize,
    pub flow: String,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub started_at: f64,
    pub ended_at: f64,
    pub first_frame: usize,
    pub last_frame: usize,
    pub handshake: HandshakeState,
    pub state: CloseReason,
    pub partial: bool,
    pub directions: BTreeMap<String, DirectionReport>,
    pub timeline: Vec<TimelineEvent>,
    pub frame_count: usize,
}

pub struct SessionManager {
    gens: BTreeMap<FlowKey, Vec<Generation>>,
    next_id: usize,
    policy: OverlapPolicy,
    timeout_seconds: f64,
}

impl SessionManager {
    pub fn new(policy: OverlapPolicy, timeout_seconds: f64) -> Self {
        SessionManager {
            gens: BTreeMap::new(),
            next_id: 1,
            policy,
            timeout_seconds,
        }
    }

    fn new_generation(&mut self, key: FlowKey, ts: f64, frame_index: usize, partial: bool) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        let handshake = if partial {
            HandshakeState::Partial
        } else {
            HandshakeState::Incomplete
        };
        let gen = Generation {
            id,
            key: key.clone(),
            started_at: ts,
            last_activity: ts,
            first_frame: frame_index,
            last_frame: frame_index,
            handshake,
            syn_from: BTreeMap::new(),
            closed: false,
            close_reason: None,
            a2b: dir_track(key.low.to_string()),
            b2a: dir_track(key.high.to_string()),
            events: if partial {
                vec![TimelineEvent {
                    frame_index,
                    timestamp: ts,
                    kind: "partial_session".to_string(),
                    endpoint: key.low.to_string(),
                    detail: Some(
                        "capture starts mid-connection; handshake not fabricated".to_string(),
                    ),
                }]
            } else {
                Vec::new()
            },
            frame_indices: std::iter::once(frame_index).collect(),
        };
        self.gens.entry(key).or_default().push(gen);
        id
    }

    /// Feed a fully parsed TCP segment.
    pub fn feed(
        &mut self,
        frame_index: usize,
        ts: f64,
        src: Endpoint,
        dst: Endpoint,
        seg: &TcpSegment,
    ) {
        let key = FlowKey::new(src.clone(), dst.clone());
        let existing = self.gens.get(&key).and_then(|v| v.last());
        let existing = existing.map(|g| (g.id, g.closed, g.handshake, g.last_activity));

        let mut chosen: Option<usize> = None;
        let mut close_previous: Option<(FlowKey, usize, CloseReason)> = None;

        match existing {
            None => {}
            Some((id, closed, _hs, last_activity)) => {
                if seg.syn() {
                    let needs_reuse = {
                        let gen = self
                            .gens
                            .get(&key)
                            .and_then(|v| v.iter().find(|g| g.id == id))
                            .expect("generation present");
                        matches!(gen.syn_action(&src, seg), SynAction::Reuse)
                    };
                    if needs_reuse {
                        close_previous = Some((key.clone(), id, CloseReason::Superseded));
                    } else {
                        chosen = Some(id);
                    }
                } else if closed {
                    // Closed four-tuple carrying new data: reused connection
                    // whose handshake was not captured -> partial generation.
                } else if self.timeout_seconds > 0.0
                    && ts - last_activity > self.timeout_seconds
                    && (!seg.payload.is_empty() || seg.fin())
                {
                    close_previous = Some((key.clone(), id, CloseReason::Timeout));
                } else {
                    chosen = Some(id);
                }
            }
        }

        if let Some((key, id, reason)) = close_previous {
            if let Some(g) = self.gens.get_mut(&key).and_then(|v| v.iter_mut().find(|g| g.id == id)) {
                if !g.closed {
                    g.closed = true;
                    g.close_reason = Some(reason);
                    g.push(
                        frame_index,
                        ts,
                        match reason {
                            CloseReason::Timeout => "timeout_close",
                            CloseReason::Superseded => "superseded_close",
                            _ => "generation_close",
                        },
                        &src,
                        None,
                    );
                }
            }
        }

        let gen_id = match chosen {
            Some(id) => id,
            None => self.new_generation(key.clone(), ts, frame_index, !seg.syn()),
        };

        let gen = self
            .gens
            .get_mut(&key)
            .and_then(|v| v.iter_mut().find(|g| g.id == gen_id))
            .expect("generation exists");
        gen.feed(frame_index, ts, &src, &dst, seg, self.policy);
    }

    pub fn finish(mut self) -> Vec<SessionReport> {
        // Close every generation that remained open at capture end.
        for gens in self.gens.values_mut() {
            for g in gens.iter_mut() {
                if !g.closed {
                    g.closed = true;
                    g.close_reason = Some(CloseReason::CaptureEnd);
                }
            }
        }
        let mut reports = Vec::new();
        for (key, gens) in self.gens {
            for g in gens {
                let frame_count = g.frame_indices.len();
                let mut directions = BTreeMap::new();
                directions.insert(key.low.to_string(), g.a2b.dir.finalize());
                directions.insert(key.high.to_string(), g.b2a.dir.finalize());
                reports.push(SessionReport {
                    session_id: g.id,
                    flow: key.label(),
                    endpoint_a: key.low.to_string(),
                    endpoint_b: key.high.to_string(),
                    started_at: g.started_at,
                    ended_at: g.last_activity,
                    first_frame: g.first_frame,
                    last_frame: g.last_frame,
                    handshake: g.handshake,
                    state: g.close_reason.unwrap_or(CloseReason::CaptureEnd),
                    partial: matches!(g.handshake, HandshakeState::Partial),
                    directions,
                    timeline: g.events,
                    frame_count,
                });
            }
        }
        reports.sort_by_key(|r| r.session_id);
        reports
    }
}
