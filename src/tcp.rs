// TCP session demultiplexing, generation tracking and byte-stream reassembly.

use std::collections::BTreeMap;

use crate::model::{ACK, FIN, RST, SYN};

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
    pub fn parse(s: &str) -> OverlapPolicy {
        match s {
            "last-seen" => OverlapPolicy::LastSeen,
            _ => OverlapPolicy::FirstSeen,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub policy: OverlapPolicy,
    pub timeout_us: i128,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            policy: OverlapPolicy::FirstSeen,
            timeout_us: 2_000_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SegRecord {
    pub frame_idx: usize,
    pub dir: u8, // 0 = client->server, 1 = server->client
    pub seq_abs: u32,
    pub begin: i64,
    pub end: i64,
    pub len: usize,
    pub flags: u8,
    pub ts_us: i128,
    pub relation: String, // in-order / retransmission / overlap / out-of-order / pure-ack / control
    pub overwritten: usize,
    pub kept: usize,
    pub data: Vec<u8>,
    pub conflict: bool,
}

#[derive(Debug, Clone)]
pub struct Gap {
    pub begin: i64,
    pub end: i64,
    pub len: i64,
    pub dir: u8,
}

#[derive(Debug, Clone)]
pub struct DirState {
    pub base: Option<u32>,
    pub base_frame: Option<usize>,
    pub base_syn: bool,
    pub frontier: i64,
    pub max_end: i64,
    pub fin: bool,
    pub fin_seq: Option<u32>,
    pub fin_off: Option<i64>,
    pub rst: bool,
    pub rst_frame: Option<usize>,
    pub bytes: Vec<u8>,
    pub owner: Vec<usize>,
    /// Future (out-of-order) bytes: logical offset -> (byte, frame_idx).
    pub pending: BTreeMap<i64, (u8, usize)>,
    pub out_of_order: usize,
    pub retrans: usize,
    pub overlap_events: usize,
}

impl DirState {
    fn new() -> Self {
        DirState {
            base: None,
            base_frame: None,
            base_syn: false,
            frontier: 0,
            max_end: 0,
            fin: false,
            fin_seq: None,
            fin_off: None,
            rst: false,
            rst_frame: None,
            bytes: Vec::new(),
            owner: Vec::new(),
            pending: BTreeMap::new(),
            out_of_order: 0,
            retrans: 0,
            overlap_events: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub gen: usize,
    pub key: String,
    pub c_ip: String,
    pub s_ip: String,
    pub c_port: u16,
    pub s_port: u16,
    pub ip_version: u8,
    pub start_frame: usize,
    pub end_frame: usize,
    pub start_ts: i128,
    pub last_ts: i128,
    pub state: String, // open / fin-closed / rst-closed / timed-out / superseded / partial
    pub handshake: String, // seen / partial / missing
    pub mid_capture: bool,
    pub dirs: [DirState; 2],
    pub segments: Vec<SegRecord>,
    pub close_reason: String,
    pub syn_frames: Vec<usize>,
}

fn rel(base: u32, seq: u32) -> i64 {
    seq.wrapping_sub(base) as i32 as i64
}

pub struct Engine {
    cfg: EngineConfig,
    // canonical key (smaller endpoint first) -> generations in order
    gens: BTreeMap<String, Vec<usize>>,
    pub sessions: Vec<Session>,
    // mapping session id -> index, and active generation index per canonical key
}

pub struct DatagramFrame {
    pub frame_idx: usize,
    pub ts_us: i128,
    pub src: String,
    pub dst: String,
    pub ip_version: u8,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Engine {
    pub fn new(cfg: EngineConfig) -> Engine {
        Engine {
            cfg,
            gens: BTreeMap::new(),
            sessions: Vec::new(),
        }
    }

    pub fn ingest(&mut self, d: &DatagramFrame) {
        let a = format!("{}:{}", d.src, d.sport);
        let b = format!("{}:{}", d.dst, d.dport);
        let canon = if a <= b {
            format!("{}|{}", a, b)
        } else {
            format!("{}|{}", b, a)
        };
        let is_syn = d.flags & SYN != 0;
        let is_ack = d.flags & ACK != 0;
        let is_rst = d.flags & RST != 0;

        // Apply idle timeout to the most recent generation on this 4-tuple.
        if let Some(list) = self.gens.get(&canon).cloned() {
            if let Some(&si) = list.last() {
                if self.sessions[si].state == "open" {
                    self.timeout_check_one(si, d.ts_us, d.frame_idx);
                }
            }
        }

        // A SYN-ACK belongs to an existing open generation (the listener's
        // reply to the client SYN). A bare SYN that matches an open generation
        // is a retransmission; otherwise it opens a new generation.
        let mut target: Option<usize> = None;
        if let Some(list) = self.gens.get(&canon).cloned() {
            for &si in list.iter().rev() {
                if self.sessions[si].state != "open" {
                    continue;
                }
                if endpoint_match(&self.sessions[si], d) && plausible(&self.sessions[si], d) {
                    target = Some(si);
                    break;
                }
            }
        }

        let opens_new = is_syn
            && !is_rst
            && match target {
                Some(si) => {
                    let dir = direction_of(&self.sessions[si], d);
                    // SYN-ACK from the server direction never opens a new gen.
                    if dir == 1 && is_ack {
                        false
                    } else if dir == 0 {
                        // client->server SYN matching existing open gen:
                        // a different ISN means a new generation; same ISN is a retrans.
                        starts_new_syn(&self.sessions[si], d)
                    } else {
                        true
                    }
                }
                None => true,
            };

        let sess = if opens_new {
            self.ensure_gen(&canon, d)
        } else {
            target.unwrap_or_else(|| self.ensure_gen(&canon, d))
        };
        let dir = direction_of(&self.sessions[sess], d);
        self.place(sess, dir, d);
        self.update_close(sess);
    }

    fn ensure_gen(&mut self, canon: &str, d: &DatagramFrame) -> usize {
        // Supersede any still-open prior generation on the same 4-tuple.
        if let Some(list) = self.gens.get(canon).cloned() {
            if let Some(&prev) = list.last() {
                if self.sessions[prev].state == "open" {
                    self.sessions[prev].state = "superseded".into();
                    self.sessions[prev].close_reason =
                        "new generation opened on reused 4-tuple".into();
                    self.sessions[prev].end_frame = d.frame_idx;
                    self.sessions[prev].last_ts = d.ts_us;
                }
            }
        }
        let gen = self.gens.get(canon).map(|v| v.len()).unwrap_or(0) + 1;
        // The initiator of a bare SYN (or first mid-capture packet) is client.
        let (c_ip, s_ip, c_port, s_port) = (d.src.clone(), d.dst.clone(), d.sport, d.dport);
        let syn = d.flags & SYN != 0;
        let key = format!("{}:{}<->{}:{}", c_ip, c_port, s_ip, s_port);
        let sess = Session {
            id: format!("g{}-{}", gen, canon),
            gen,
            key,
            c_ip,
            s_ip,
            c_port,
            s_port,
            ip_version: d.ip_version,
            start_frame: d.frame_idx,
            end_frame: d.frame_idx,
            start_ts: d.ts_us,
            last_ts: d.ts_us,
            state: "open".into(),
            handshake: if syn { "seen".into() } else { "missing".into() },
            mid_capture: !syn,
            dirs: [DirState::new(), DirState::new()],
            segments: Vec::new(),
            close_reason: String::new(),
            syn_frames: if syn { vec![d.frame_idx] } else { Vec::new() },
        };
        let idx = self.sessions.len();
        self.sessions.push(sess);
        self.gens.entry(canon.to_string()).or_default().push(idx);
        idx
    }

    fn timeout_check_one(&mut self, si: usize, ts: i128, frame: usize) {
        if self.sessions[si].state == "open" && ts - self.sessions[si].last_ts > self.cfg.timeout_us
        {
            self.sessions[si].state = "timed-out".into();
            self.sessions[si].close_reason = format!(
                "idle gap {} us exceeded timeout {} us",
                ts - self.sessions[si].last_ts,
                self.cfg.timeout_us
            );
            self.sessions[si].end_frame = frame;
            self.sessions[si].last_ts = ts;
        }
    }

    fn place(&mut self, si: usize, dir: u8, d: &DatagramFrame) {
        let syn = d.flags & SYN != 0;
        let fin = d.flags & FIN != 0;
        let rst = d.flags & RST != 0;

        if syn {
            let st = &mut self.sessions[si].dirs[dir as usize];
            if st.base.is_none() {
                st.base = Some(d.seq);
                st.base_frame = Some(d.frame_idx);
                st.base_syn = true;
                st.frontier = 0;
                st.max_end = 0;
            }
            if !self.sessions[si].syn_frames.contains(&d.frame_idx) {
                self.sessions[si].syn_frames.push(d.frame_idx);
            }
        }

        let base = match self.sessions[si].dirs[dir as usize].base {
            Some(b) => b,
            None => {
                let st = &mut self.sessions[si].dirs[dir as usize];
                st.base = Some(d.seq);
                st.base_frame = Some(d.frame_idx);
                st.base_syn = false;
                if self.sessions[si].handshake == "seen" {
                    self.sessions[si].handshake = "partial".into();
                }
                d.seq
            }
        };

        if rst {
            let st = &mut self.sessions[si].dirs[dir as usize];
            st.rst = true;
            st.rst_frame = Some(d.frame_idx);
            self.push_seg(si, dir, d, base, 0, 0, 0, "rst".into(), 0, 0, false);
            let s = &mut self.sessions[si];
            s.end_frame = d.frame_idx;
            s.last_ts = d.ts_us;
            return;
        }

        let begin = rel(base, d.seq);
        // Data-space index: 0 is the first payload byte. A SYN consumes one
        // sequence number but is not a data byte.
        let data_off = begin
            - if self.sessions[si].dirs[dir as usize].base_syn {
                1
            } else {
                0
            };
        let data_end = data_off + d.payload.len() as i64;
        let mut span_end = data_end;
        if syn {
            span_end += 1;
        }
        if fin {
            span_end += 1;
        }
        {
            let st = &mut self.sessions[si].dirs[dir as usize];
            st.max_end = st.max_end.max(span_end);
        }
        if fin {
            let st = &mut self.sessions[si].dirs[dir as usize];
            st.fin = true;
            st.fin_seq = Some(d.seq.wrapping_add(d.payload.len() as u32));
            st.fin_off = Some(data_end);
        }

        if d.payload.is_empty() {
            let relation = if syn {
                "syn".into()
            } else if fin {
                "fin".into()
            } else {
                "pure-ack".into()
            };
            self.push_seg(si, dir, d, base, begin, span_end, 0, relation, 0, 0, false);
            let s = &mut self.sessions[si];
            s.end_frame = d.frame_idx;
            s.last_ts = d.ts_us;
            return;
        }

        let frontier_before = self.sessions[si].dirs[dir as usize].frontier;
        let policy = self.cfg.policy;
        let mut conflict = false;
        let mut overwritten = 0usize;
        let mut inside_existing = 0usize;
        let mut inside_match = 0usize;

        for (i, nb) in d.payload.iter().enumerate() {
            let pos = data_off + i as i64;
            if pos < 0 {
                continue;
            }
            let st = &mut self.sessions[si].dirs[dir as usize];
            if (pos as usize) < st.bytes.len() {
                inside_existing += 1;
                if st.bytes[pos as usize] == *nb {
                    inside_match += 1;
                } else {
                    conflict = true;
                    if matches!(policy, OverlapPolicy::LastSeen) {
                        self.sessions[si].dirs[dir as usize].bytes[pos as usize] = *nb;
                        self.sessions[si].dirs[dir as usize].owner[pos as usize] = d.frame_idx;
                        overwritten += 1;
                    }
                }
            } else if let Some((existing, owner)) = st.pending.get(&pos).copied() {
                inside_existing += 1;
                if existing == *nb {
                    inside_match += 1;
                } else {
                    conflict = true;
                    if matches!(policy, OverlapPolicy::LastSeen) {
                        self.sessions[si].dirs[dir as usize]
                            .pending
                            .insert(pos, (*nb, d.frame_idx));
                        overwritten += 1;
                    }
                }
                let _ = owner;
            } else {
                self.sessions[si].dirs[dir as usize]
                    .pending
                    .insert(pos, (*nb, d.frame_idx));
            }
        }

        {
            let st = &mut self.sessions[si].dirs[dir as usize];
            // Drain every contiguous position starting at the current frontier,
            // continuing across gaps that this segment may have just filled.
            let mut p = st.bytes.len() as i64;
            while let Some((b, owner)) = st.pending.remove(&p) {
                st.bytes.push(b);
                st.owner.push(owner);
                p += 1;
            }
            st.frontier = st.bytes.len() as i64;
        }

        let st = &mut self.sessions[si].dirs[dir as usize];
        let is_pure_retx = inside_existing > 0
            && inside_match == inside_existing
            && data_end <= st.frontier.max(frontier_before);
        let relation = if conflict {
            st.overlap_events += 1;
            if data_off >= frontier_before {
                "overlap(out-of-order)".into()
            } else {
                "overlap".into()
            }
        } else if is_pure_retx {
            st.retrans += 1;
            "retransmission".into()
        } else if inside_existing > 0 {
            st.retrans += 1;
            "retransmission+in-order".into()
        } else if data_off > frontier_before {
            st.out_of_order += 1;
            "out-of-order".into()
        } else {
            "in-order".into()
        };

        self.push_seg(
            si,
            dir,
            d,
            base,
            data_off,
            data_end,
            d.payload.len(),
            relation,
            overwritten,
            d.payload.len(),
            conflict,
        );
        let s = &mut self.sessions[si];
        s.end_frame = d.frame_idx;
        s.last_ts = d.ts_us;
        s.segments.last_mut().unwrap().data = d.payload.clone();
    }

    fn push_seg(
        &mut self,
        si: usize,
        dir: u8,
        d: &DatagramFrame,
        _base: u32,
        begin: i64,
        end: i64,
        len: usize,
        relation: String,
        overwritten: usize,
        kept: usize,
        conflict: bool,
    ) {
        self.sessions[si].segments.push(SegRecord {
            frame_idx: d.frame_idx,
            dir,
            seq_abs: d.seq,
            begin,
            end,
            len,
            flags: d.flags,
            ts_us: d.ts_us,
            relation,
            overwritten,
            kept,
            data: Vec::new(),
            conflict,
        });
    }

    fn update_close(&mut self, si: usize) {
        let s = &mut self.sessions[si];
        if s.state != "open" {
            return;
        }
        if s.dirs[0].rst || s.dirs[1].rst {
            s.state = "rst-closed".into();
            s.close_reason = "RST received".into();
            return;
        }
        if s.dirs[0].fin && s.dirs[1].fin {
            s.state = "fin-closed".into();
            s.close_reason = "FIN seen in both directions".into();
        }
    }

    pub fn finalize(&mut self) {
        // End-of-capture: open sessions stay open/partial; nothing is fabricated.
        for s in self.sessions.iter_mut() {
            if s.state == "open" && s.handshake == "missing" {
                s.state = "partial".into();
                s.close_reason = "capture ended with no observed handshake".into();
            }
        }
    }

    /// Missing *data* ranges. Pending (out-of-order) byte positions define the
    /// far edge; control-only sequence slots (SYN/FIN) are not counted.
    pub fn gaps(&self, si: usize) -> Vec<(u8, i64, i64)> {
        let mut out = Vec::new();
        let s = &self.sessions[si];
        for dir in 0u8..2 {
            let st = &s.dirs[dir as usize];
            if st.pending.is_empty() {
                continue;
            }
            // Highest pending position that still lies beyond the contiguous
            // prefix; merge into contiguous missing runs up to that point.
            let max_pending = *st.pending.keys().max().unwrap() + 1;
            let mut pos = st.frontier;
            while pos < max_pending {
                if !st.pending.contains_key(&pos) {
                    let begin = pos;
                    while pos < max_pending && !st.pending.contains_key(&pos) {
                        pos += 1;
                    }
                    out.push((dir, begin, pos));
                } else {
                    pos += 1;
                }
            }
        }
        out
    }
}

fn direction_of(s: &Session, d: &DatagramFrame) -> u8 {
    if d.src == s.c_ip && d.sport == s.c_port && d.dst == s.s_ip && d.dport == s.s_port {
        0
    } else {
        1
    }
}

fn plausible(s: &Session, d: &DatagramFrame) -> bool {
    let dir = direction_of(s, d);
    let st = &s.dirs[dir as usize];
    if d.flags & RST != 0 {
        return true;
    }
    match st.base {
        None => true,
        Some(base) => {
            let off = rel(base, d.seq);
            let span = d.payload.len() as i64
                + if d.flags & SYN != 0 { 1 } else { 0 }
                + if d.flags & FIN != 0 { 1 } else { 0 };
            let window = 2_000_000i64;
            off + span >= -window && off <= st.max_end + window
        }
    }
}

fn endpoint_match(s: &Session, d: &DatagramFrame) -> bool {
    let fwd = d.src == s.c_ip && d.sport == s.c_port && d.dst == s.s_ip && d.dport == s.s_port;
    let rev = d.src == s.s_ip && d.sport == s.s_port && d.dst == s.c_ip && d.dport == s.c_port;
    fwd || rev
}

/// A client-direction SYN starts a new generation when its ISN differs from
/// the known base (i.e. it is not a retransmission of the opening SYN).
fn starts_new_syn(s: &Session, d: &DatagramFrame) -> bool {
    let st = &s.dirs[0];
    match st.base {
        None => true,
        Some(base) => {
            let off = rel(base, d.seq);
            !(0..=1).contains(&off)
        }
    }
}
