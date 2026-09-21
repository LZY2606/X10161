//! TCP session tracking: 4-tuple + generation. SYN / FIN / RST / idle timeout
//! decide generation boundaries; mid-stream captures become partial sessions
//! without fabricating a handshake.

use crate::parse::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
}

impl Endpoint {
    pub fn label(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

/// Direction-normalized 4-tuple: `a` is the lexicographically smaller endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct FlowKey {
    pub a: Endpoint,
    pub b: Endpoint,
}

impl FlowKey {
    pub fn new(x: Endpoint, y: Endpoint) -> Self {
        if x <= y { FlowKey { a: x, b: y } } else { FlowKey { a: y, b: x } }
    }
    /// 0 = a->b, 1 = b->a
    pub fn dir_of(&self, src: &Endpoint) -> usize {
        if *src == self.a { 0 } else { 1 }
    }
    pub fn label(&self) -> String {
        format!("{} <-> {}", self.a.label(), self.b.label())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SegmentRec {
    pub frame_index: u64,
    pub frame_hash: String,
    pub ts_ns: i64,
    pub seq: u32,
    /// end of payload in sequence space (== seq when no payload)
    pub seq_end: u32,
    pub payload_len: usize,
    pub flags: u8,
    #[serde(skip)]
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DirState {
    pub isn: Option<u32>,
    pub syn_seen: bool,
    pub fin_seen: bool,
    pub segments: Vec<SegmentRec>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Handshake observed (SYN or SYN-ACK seen).
    Syn,
    /// Capture started mid-stream; handshake was never observed and is not fabricated.
    Partial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Close {
    Open,
    Fin,
    Rst,
    Timeout,
    /// A new SYN with a different ISN reused the tuple before a clean close.
    Superseded,
}

#[derive(Clone, Debug, Serialize)]
pub struct Session {
    pub id: usize,
    pub key: FlowKey,
    pub generation: usize,
    pub origin: Origin,
    pub close: Close,
    pub rst_seen: bool,
    pub start_ts_ns: i64,
    pub last_ts_ns: i64,
    pub first_frame: u64,
    pub last_frame: u64,
    pub dirs: [DirState; 2],
}

pub struct TcpPacket<'a> {
    pub ts_ns: i64,
    pub frame_index: u64,
    pub frame_hash: &'a str,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

pub struct TcpTracker {
    pub timeout_ns: i64,
    pub sessions: Vec<Session>,
    open: HashMap<FlowKey, usize>,
    gen_counter: HashMap<FlowKey, usize>,
}

impl TcpTracker {
    pub fn new(timeout_ns: i64) -> Self {
        TcpTracker { timeout_ns, sessions: Vec::new(), open: HashMap::new(), gen_counter: HashMap::new() }
    }

    fn new_session(&mut self, key: FlowKey, pkt: &TcpPacket, origin: Origin) -> usize {
        let generation = {
            let c = self.gen_counter.entry(key.clone()).or_insert(0);
            let g = *c;
            *c += 1;
            g
        };
        let id = self.sessions.len();
        self.sessions.push(Session {
            id,
            key: key.clone(),
            generation,
            origin,
            close: Close::Open,
            rst_seen: false,
            start_ts_ns: pkt.ts_ns,
            last_ts_ns: pkt.ts_ns,
            first_frame: pkt.frame_index,
            last_frame: pkt.frame_index,
            dirs: [DirState::default(), DirState::default()],
        });
        self.open.insert(key, id);
        id
    }

    fn pick_session(&mut self, key: &FlowKey, dir: usize, pkt: &TcpPacket) -> usize {
        let syn_only = pkt.flags & TCP_SYN != 0 && pkt.flags & TCP_ACK == 0;
        let existing = self.open.get(key).copied();
        let mut retire: Option<Close> = None;
        let need_new = match existing {
            None => true,
            Some(i) => {
                let s = &self.sessions[i];
                if s.close != Close::Open {
                    true
                } else if pkt.ts_ns - s.last_ts_ns > self.timeout_ns {
                    retire = Some(Close::Timeout);
                    true
                } else if syn_only {
                    let d = &s.dirs[dir];
                    if d.syn_seen && d.isn == Some(pkt.seq) {
                        false // retransmitted SYN of the current generation
                    } else if !d.syn_seen && s.origin == Origin::Syn && d.segments.is_empty() {
                        false // duplicate path of the same handshake
                    } else {
                        retire = Some(Close::Superseded);
                        true
                    }
                } else {
                    false
                }
            }
        };
        if need_new {
            if let (Some(i), Some(c)) = (existing, retire) {
                self.sessions[i].close = c;
            }
            let origin = if pkt.flags & TCP_SYN != 0 { Origin::Syn } else { Origin::Partial };
            self.new_session(key.clone(), pkt, origin)
        } else {
            existing.unwrap()
        }
    }

    pub fn process(&mut self, pkt: TcpPacket) {
        let key = FlowKey::new(pkt.src.clone(), pkt.dst.clone());
        let dir = key.dir_of(&pkt.src);
        let idx = self.pick_session(&key, dir, &pkt);
        let s = &mut self.sessions[idx];
        let d = &mut s.dirs[dir];
        if pkt.flags & TCP_SYN != 0 && !d.syn_seen {
            d.syn_seen = true;
            d.isn = Some(pkt.seq);
        }
        if pkt.flags & TCP_FIN != 0 {
            d.fin_seen = true;
        }
        d.segments.push(SegmentRec {
            frame_index: pkt.frame_index,
            frame_hash: pkt.frame_hash.to_string(),
            ts_ns: pkt.ts_ns,
            seq: pkt.seq,
            seq_end: pkt.seq.wrapping_add(pkt.payload.len() as u32),
            payload_len: pkt.payload.len(),
            flags: pkt.flags,
            payload: pkt.payload.to_vec(),
        });
        if pkt.flags & TCP_RST != 0 {
            s.rst_seen = true;
            s.close = Close::Rst;
        }
        if s.close == Close::Open && s.dirs[0].fin_seen && s.dirs[1].fin_seen {
            s.close = Close::Fin;
        }
        s.last_ts_ns = pkt.ts_ns;
        s.last_frame = pkt.frame_index;
    }
}

// ---------------------------------------------------------------------------
// 32-bit wrap-aware sequence comparisons (RFC 1982 style)
// ---------------------------------------------------------------------------

/// signed a - b in sequence space
pub fn seq_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

pub fn seq_lt(a: u32, b: u32) -> bool {
    seq_diff(a, b) < 0
}

pub fn seq_leq(a: u32, b: u32) -> bool {
    seq_diff(a, b) <= 0
}
