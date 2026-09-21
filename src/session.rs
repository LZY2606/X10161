//! 会话代次识别与 TCP 方向重组。

use std::collections::HashMap;

use crate::frag::{FragParams, FragReassembler};
use crate::json::Value;
use crate::model::{Endpoint, Frame, Packet, ACK, FIN, RST, SYN};
use crate::parse::{parse_frame, parse_reassembled_tcp, FragPiece, L3};
use crate::util::hex_encode;

/// 32 位环绕的有符号差值：a - b，落在 [-2^31, 2^31)。
pub fn seq_diff(a: u32, b: u32) -> i64 {
    a.wrapping_sub(b) as i32 as i64
}

pub fn seq_lt(a: u32, b: u32) -> bool {
    seq_diff(a, b) < 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    FirstSeen,
    LastSeen,
}

impl Policy {
    pub fn name(&self) -> &'static str {
        match self {
            Policy::FirstSeen => "first-seen",
            Policy::LastSeen => "last-seen",
        }
    }
    pub fn from_name(s: &str) -> Policy {
        match s {
            "last-seen" | "last" => Policy::LastSeen,
            _ => Policy::FirstSeen,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub policy: Policy,
    pub timeout_ns: u64,
    pub frag: FragParams,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            policy: Policy::FirstSeen,
            timeout_ns: 120_000_000_000,
            frag: FragParams::default(),
        }
    }
}

impl Params {
    pub fn to_json(&self) -> Value {
        let mut o = Value::obj();
        o.set("overlap_policy", Value::Str(self.policy.name().into()));
        o.set("timeout_ns", Value::Int(self.timeout_ns as i128));
        o.set(
            "frag_max_datagram",
            Value::Int(self.frag.max_datagram as i128),
        );
        o.set(
            "frag_max_fragments",
            Value::Int(self.frag.max_fragments as i128),
        );
        o.set(
            "frag_max_buffered",
            Value::Int(self.frag.max_buffered as i128),
        );
        o
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TupleKey {
    pub lo: Endpoint,
    pub hi: Endpoint,
}

impl TupleKey {
    pub fn new(a: Endpoint, b: Endpoint) -> (TupleKey, usize) {
        if a <= b {
            (TupleKey { lo: a, hi: b }, 0)
        } else {
            (TupleKey { lo: b, hi: a }, 1)
        }
    }
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub seq: u32,
    pub data: Vec<u8>,
    pub frame: u32,
    pub ts_ns: u64,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub id: usize,
    pub key: TupleKey,
    pub generation: u32,
    pub partial: bool,
    pub close_reason: String,
    pub first_ts: u64,
    pub last_ts: u64,
    pub isn: [Option<u32>; 2],
    pub segments: [Vec<Segment>; 2],
    pub fin_frame: [Option<u32>; 2],
    pub rst_frame: Option<u32>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct IsolationRecord {
    pub frame_index: u32,
    pub ts_ns: u64,
    pub key: String,
    pub reason: String,
}

pub struct AnalysisResult {
    pub params: Params,
    pub frame_count: usize,
    pub sessions: Vec<Session>,
    pub isolated: Vec<IsolationRecord>,
    pub ignored: usize,
    pub malformed: Vec<(u32, String)>,
}

struct GenState {
    session_id: usize,
    closed: bool,
    last_ts: u64,
}

pub struct Analyzer {
    params: Params,
    frag: FragReassembler,
    states: HashMap<TupleKey, GenState>,
    generation_counts: HashMap<TupleKey, u32>,
    sessions: Vec<Session>,
    isolated: Vec<IsolationRecord>,
    ignored: usize,
    malformed: Vec<(u32, String)>,
}

impl Analyzer {
    pub fn new(params: Params) -> Self {
        Analyzer {
            params,
            frag: FragReassembler::new(params.frag),
            states: HashMap::new(),
            generation_counts: HashMap::new(),
            sessions: Vec::new(),
            isolated: Vec::new(),
            ignored: 0,
            malformed: Vec::new(),
        }
    }

    pub fn run(mut self, frames: &[Frame]) -> AnalysisResult {
        // 时间排序：时间戳优先；相同时间戳使用原始帧序号（数组下标）。
        let mut order: Vec<u32> = (0..frames.len() as u32).collect();
        order.sort_by(|&a, &b| {
            frames[a as usize]
                .ts_ns
                .cmp(&frames[b as usize].ts_ns)
                .then(a.cmp(&b))
        });

        for idx in order {
            let frame = &frames[idx as usize];
            match parse_frame(frame) {
                L3::Tcp(pkt) => self.handle_packet(pkt),
                L3::Frag(piece) => self.handle_fragment(piece),
                L3::Ignored => self.ignored += 1,
                L3::Malformed(msg) => self.malformed.push((frame.index, msg)),
            }
        }

        AnalysisResult {
            params: self.params,
            frame_count: frames.len(),
            sessions: self.sessions,
            isolated: self.isolated,
            ignored: self.ignored,
            malformed: self.malformed,
        }
    }

    fn handle_fragment(&mut self, piece: FragPiece) {
        match self.frag.add(piece) {
            crate::frag::FragOut::Pending => {}
            crate::frag::FragOut::Isolated(iso) => self.isolated.push(IsolationRecord {
                frame_index: iso.frame_index,
                ts_ns: iso.ts_ns,
                key: iso.key,
                reason: iso.reason,
            }),
            crate::frag::FragOut::Complete(datagram, meta) => {
                let piece_ref = FragPiece {
                    ip_version: meta.ip_version,
                    src: meta.src,
                    dst: meta.dst,
                    ident: 0,
                    proto: meta.proto,
                    offset_bytes: 0,
                    more: false,
                    data: Vec::new(),
                    frame_index: meta.frame_index,
                    ts_ns: meta.ts_ns,
                };
                match parse_reassembled_tcp(&piece_ref, &datagram) {
                    L3::Tcp(pkt) => self.handle_packet(pkt),
                    L3::Ignored => self.ignored += 1,
                    L3::Malformed(msg) => self.malformed.push((meta.frame_index, msg)),
                    L3::Frag(_) => unreachable!(),
                }
            }
        }
    }

    fn handle_packet(&mut self, pkt: Packet) {
        let src_ep = Endpoint {
            ip: pkt.src,
            port: pkt.src_port,
        };
        let dst_ep = Endpoint {
            ip: pkt.dst,
            port: pkt.dst_port,
        };
        let (key, rev) = TupleKey::new(src_ep, dst_ep);
        // rev=1 表示报文发送方是规范化元组的 hi 端，即方向 1。
        let dir = rev;

        let syn = (pkt.flags & SYN) != 0;
        let ack = (pkt.flags & ACK) != 0;
        let fin = (pkt.flags & FIN) != 0;
        let rst = (pkt.flags & RST) != 0;
        let opens = syn && !ack;

        let need_new = match self.states.get(&key) {
            None => true,
            Some(st) => {
                let timed_out = self.params.timeout_ns > 0
                    && pkt.ts_ns.saturating_sub(st.last_ts) > self.params.timeout_ns;
                if timed_out {
                    true
                } else if st.closed {
                    // 旧代次已正式关闭：只有新的连接发起 SYN 才开启下一代；
                    // FIN/RST 之后的迟到报文仍归属旧代次，绝不伪造新连接。
                    opens
                } else {
                    false
                }
            }
        };

        let sid = if need_new {
            // 旧代次若尚未正式关闭，则按超时收尾。
            if let Some(st) = self.states.get(&key) {
                if !st.closed {
                    let old = &mut self.sessions[st.session_id];
                    if old.close_reason == "open" {
                        old.close_reason = "timeout".into();
                    }
                }
            }
            let generation = self.generation_counts.get(&key).copied().unwrap_or(0) + 1;
            self.generation_counts.insert(key, generation);
            let session = Session {
                id: self.sessions.len(),
                key,
                generation,
                partial: !opens,
                close_reason: "open".into(),
                first_ts: pkt.ts_ns,
                last_ts: pkt.ts_ns,
                isn: [None, None],
                segments: [Vec::new(), Vec::new()],
                fin_frame: [None, None],
                rst_frame: None,
                notes: Vec::new(),
            };
            self.sessions.push(session);
            self.sessions.len() - 1
        } else {
            self.states.get(&key).unwrap().session_id
        };

        // SYN 记录 ISN；未握手代次中重复出现的 SYN 只记证据，不修改代次。
        if syn {
            let session = &mut self.sessions[sid];
            match session.isn[dir] {
                None => session.isn[dir] = Some(pkt.seq),
                Some(existing) if existing != pkt.seq => session.notes.push(format!(
                        "frame {}: SYN seq changed {} -> {}",
                        pkt.frame_index, existing, pkt.seq
                    )),
                Some(_) => {}
            }
        }

        if !pkt.payload.is_empty() {
            self.sessions[sid].segments[dir].push(Segment {
                seq: pkt.seq,
                data: pkt.payload,
                frame: pkt.frame_index,
                ts_ns: pkt.ts_ns,
            });
        }

        let (closed_now, reason) = {
            let session = &mut self.sessions[sid];
            session.last_ts = pkt.ts_ns;
            if fin {
                session.fin_frame[dir] = Some(pkt.frame_index);
            }
            if rst {
                session.rst_frame = Some(pkt.frame_index);
                session.close_reason = "rst".into();
            } else if session.fin_frame[0].is_some() && session.fin_frame[1].is_some() {
                session.close_reason = "fin".into();
            }
            let rst_close = session.rst_frame.is_some();
            let fin_close = session.fin_frame[0].is_some() && session.fin_frame[1].is_some();
            (rst_close || fin_close, session.close_reason.clone())
        };

        self.states.insert(
            key,
            GenState {
                session_id: sid,
                closed: closed_now,
                last_ts: pkt.ts_ns,
            },
        );
        let _ = reason;
    }
}

/// 被覆盖字节的证据（first-seen 丢弃新字节 / last-seen 替换旧字节时均保留双方内容）。
#[derive(Clone, Debug)]
pub struct OverlapBytes {
    pub frame: u32,
    pub old_frames: Vec<u32>,
    pub offset: i64,
    pub kept_hex: String,
    pub incoming_hex: String,
    pub action: &'static str,
}

#[derive(Clone, Debug)]
pub struct DirOutcome {
    pub base: Option<u32>,
    pub ranges: Vec<(i64, i64)>,
    pub gaps: Vec<(i64, i64)>,
    pub stream: Vec<u8>,
    pub stream_offset: i64,
    pub contiguous_len: usize,
    pub retransmissions: usize,
    pub out_of_order: usize,
    pub overlaps: usize,
    pub events: Value,
}

fn merge_ranges(ranges: &mut Vec<(i64, i64)>) {
    ranges.sort();
    let mut merged: Vec<(i64, i64)> = Vec::new();
    for (s, e) in ranges.drain(..) {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        merged.push((s, e));
    }
    *ranges = merged;
}

pub fn reassemble_direction(
    segments: &[Segment],
    isn: Option<u32>,
    policy: Policy,
) -> DirOutcome {
    let mut events: Vec<Value> = Vec::new();

    let base = match isn {
        Some(i) => Some(i.wrapping_add(1)),
        None => segments.first().map(|s| s.seq),
    };
    let base = match base {
        Some(b) => b,
        None => {
            return DirOutcome {
                base: None,
                ranges: Vec::new(),
                gaps: Vec::new(),
                stream: Vec::new(),
                stream_offset: 0,
                contiguous_len: 0,
                retransmissions: 0,
                out_of_order: 0,
                overlaps: 0,
                events: Value::Arr(Vec::new()),
            };
        }
    };

    // 事件检测（按到达顺序），并得到最终覆盖区间。
    let mut covered: Vec<(i64, i64)> = Vec::new();
    let mut max_end = i64::MIN;
    let mut retransmissions = 0usize;
    let mut out_of_order = 0usize;
    let mut overlaps = 0usize;

    for seg in segments {
        let len = seg.data.len() as i64;
        if len == 0 {
            continue;
        }
        let s = seq_diff(seg.seq, base);
        let e = s + len;
        let mut covered_now = 0i64;
        for (cs, ce) in &covered {
            let os = s.max(*cs);
            let oe = e.min(*ce);
            if os < oe {
                covered_now += oe - os;
            }
        }
        if covered_now == len {
            retransmissions += 1;
            push_event(
                &mut events,
                seg.frame,
                "retransmission",
                s,
                e,
                "segment already fully covered",
            );
        } else if covered_now > 0 {
            overlaps += 1;
            push_event(
                &mut events,
                seg.frame,
                "partial_overlap",
                s,
                e,
                "segment overlaps previously covered bytes",
            );
        }
        if covered_now < len && s < max_end {
            out_of_order += 1;
            push_event(
                &mut events,
                seg.frame,
                "out_of_order",
                s,
                e,
                "new data arrives after later bytes",
            );
        }
        if e > max_end {
            max_end = e;
        }
        covered.push((s, e));
        merge_ranges(&mut covered);
    }

    // 字节级合并：first-seen 保留先到字节，last-seen 后到字节替换；
    // 无论哪种策略，被覆盖的双方字节都进入证据。
    let mut map: std::collections::BTreeMap<i64, (u8, u32)> =
        std::collections::BTreeMap::new();
    let mut overlap_bytes: Vec<OverlapBytes> = Vec::new();

    for seg in segments {
        let len = seg.data.len();
        if len == 0 {
            continue;
        }
        let s = seq_diff(seg.seq, base);

        // 收集与现有字节冲突的连续游程。
        let mut runs: Vec<(i64, Vec<u8>, Vec<u8>, Vec<u32>)> = Vec::new();
        for (i, &byte) in seg.data.iter().enumerate() {
            let pos = s + i as i64;
            if let Some((old, old_frame)) = map.get(&pos) {
                let action = match policy {
                    Policy::FirstSeen => "incoming_dropped",
                    Policy::LastSeen => "replaced",
                };
                let is_same = match runs.last() {
                    Some((start, kept, _inc, frames)) => {
                        let same_action = true;
                        let contiguous = *start + kept.len() as i64 == pos;
                        let same_frame = frames.last() == Some(old_frame);
                        let _ = action;
                        same_action && contiguous && same_frame
                    }
                    None => false,
                };
                if is_same {
                    let last = runs.last_mut().unwrap();
                    last.1.push(*old);
                    last.2.push(byte);
                } else {
                    runs.push((pos, vec![*old], vec![byte], vec![*old_frame]));
                }
            }
        }
        for (start, old_bytes, new_bytes, old_frames) in runs {
            let action = match policy {
                Policy::FirstSeen => "incoming_dropped",
                Policy::LastSeen => "replaced",
            };
            overlap_bytes.push(OverlapBytes {
                frame: seg.frame,
                old_frames,
                offset: start,
                kept_hex: hex_encode(&old_bytes),
                incoming_hex: hex_encode(&new_bytes),
                action,
            });
        }

        match policy {
            Policy::FirstSeen => {
                for (i, &byte) in seg.data.iter().enumerate() {
                    map.entry(s + i as i64).or_insert((byte, seg.frame));
                }
            }
            Policy::LastSeen => {
                for (i, &byte) in seg.data.iter().enumerate() {
                    map.insert(s + i as i64, (byte, seg.frame));
                }
            }
        }
    }

    for ob in &overlap_bytes {
        let mut ev = Value::obj();
        ev.set("frame", Value::Int(ob.frame as i128));
        ev.set("type", Value::Str("overlap_bytes".into()));
        ev.set("action", Value::Str(ob.action.into()));
        ev.set("offset", Value::Int(ob.offset as i128));
        ev.set("length", Value::Int(ob.kept_hex.len() as i128 / 2));
        ev.set("kept_bytes_hex", Value::Str(ob.kept_hex.clone()));
        ev.set("incoming_bytes_hex", Value::Str(ob.incoming_hex.clone()));
        let frames: Vec<Value> = ob
            .old_frames
            .iter()
            .map(|f| Value::Int(*f as i128))
            .collect();
        ev.set("conflicting_frame", Value::Arr(frames));
        events.push(ev);
    }

    // 最终覆盖区间与缺口。
    let mut ranges: Vec<(i64, i64)> = Vec::new();
    if let (Some(first), Some(last)) = (map.keys().next(), map.keys().next_back()) {
        let lo = *first;
        let hi = *last + 1;
        let mut cursor = lo;
        let mut run_start: Option<i64> = None;
        let mut gaps: Vec<(i64, i64)> = Vec::new();
        for pos in lo..hi {
            if map.contains_key(&pos) {
                if run_start.is_none() {
                    run_start = Some(pos);
                }
            } else {
                if let Some(rs) = run_start.take() {
                    ranges.push((rs, pos));
                }
                match gaps.last_mut() {
                    Some((_, ge)) if *ge == pos => *ge = pos + 1,
                    _ => gaps.push((pos, pos + 1)),
                }
            }
            cursor = pos + 1;
        }
        if let Some(rs) = run_start.take() {
            ranges.push((rs, hi));
        }
        let _ = cursor;

        // 重组字节：覆盖轴 [lo,hi)，缺口处填 0；下载时附带 offset 与缺口区间。
        let mut stream = vec![0u8; (hi - lo) as usize];
        for (pos, (byte, _)) in &map {
            stream[(*pos - lo) as usize] = *byte;
        }
        let mut contiguous_len = 0usize;
        let mut pos = 0i64.max(-lo);
        while pos < hi - lo && map.contains_key(&(lo + pos)) {
            contiguous_len += 1;
            pos += 1;
        }

        DirOutcome {
            base: Some(base),
            ranges,
            gaps,
            stream,
            stream_offset: lo,
            contiguous_len,
            retransmissions,
            out_of_order,
            overlaps,
            events: Value::Arr(events),
        }
    } else {
        DirOutcome {
            base: Some(base),
            ranges: Vec::new(),
            gaps: Vec::new(),
            stream: Vec::new(),
            stream_offset: 0,
            contiguous_len: 0,
            retransmissions,
            out_of_order,
            overlaps,
            events: Value::Arr(events),
        }
    }
}

fn push_event(events: &mut Vec<Value>, frame: u32, ty: &str, start: i64, end: i64, msg: &str) {
    let mut ev = Value::obj();
    ev.set("frame", Value::Int(frame as i128));
    ev.set("type", Value::Str(ty.into()));
    ev.set("range_start", Value::Int(start as i128));
    ev.set("range_end", Value::Int(end as i128));
    ev.set("length", Value::Int((end - start) as i128));
    ev.set("detail", Value::Str(msg.into()));
    events.push(ev);
}
