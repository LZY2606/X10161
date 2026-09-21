//! TCP 会话重组：代次识别、32 位环绕序号空间、双向乱序/重传/缺口分析。

use std::net::IpAddr;

use crate::model::{Datagram, OverlapPolicy, TcpSegment, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

/// 一段不可变入站数据（即使字节未被当前策略采用也完整保留）。
#[derive(Debug, Clone)]
struct Segment {
    event_idx: usize,
    frame_no: u64,
    start: i64,
    data_off: usize,
    len: usize,
}

/// 被覆盖而未进入当前策略结果的字节，仍作为证据保留。
#[derive(Debug, Clone)]
pub struct OverwriteRecord {
    pub event_idx: usize,
    pub frame_no: u64,
    pub start: i64,
    pub end: i64,
    pub bytes: String,
}

/// 单方向字节空间：扁平占用表 + 不可变段池，first/last-seen 均可留证。
#[derive(Debug, Clone)]
struct ByteSpace {
    occupied: Vec<(i64, i64, usize)>,
    segments: Vec<Segment>,
    store: Vec<u8>,
    overwrites: Vec<OverwriteRecord>,
}

impl ByteSpace {
    fn new() -> Self {
        ByteSpace { occupied: Vec::new(), segments: Vec::new(), store: Vec::new(), overwrites: Vec::new() }
    }

    fn locate(&self, pos: i64) -> Option<usize> {
        self.occupied
            .binary_search_by(|(s, e, _)| {
                if pos < *s {
                    std::cmp::Ordering::Greater
                } else if pos >= *e {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()
    }

    fn segment_byte(&self, seg_idx: usize, pos: i64) -> Option<u8> {
        let seg = self.segments.get(seg_idx)?;
        let off = (pos - seg.start) as usize;
        self.store.get(seg.data_off + off).copied()
    }

    fn byte_at(&self, pos: i64) -> Option<u8> {
        let ci = self.locate(pos)?;
        let seg_idx = self.occupied[ci].2;
        self.segment_byte(seg_idx, pos)
    }

    fn is_occupied(&self, pos: i64) -> bool {
        self.locate(pos).is_some()
    }

    fn covers(&self, start: i64, end: i64) -> bool {
        if start >= end {
            return true;
        }
        let mut pos = start;
        while pos < end {
            match self.locate(pos) {
                Some(ci) => pos = self.occupied[ci].1,
                None => return false,
            }
        }
        true
    }

    fn owner_frame(&self, pos: i64) -> u64 {
        let ci = self.locate(pos).unwrap_or(0);
        self.occupied.get(ci).map(|(_, _, si)| self.segments[*si].frame_no).unwrap_or(0)
    }

    fn add_segment(&mut self, event_idx: usize, frame_no: u64, start: i64, bytes: &[u8]) -> usize {
        let idx = self.segments.len();
        let off = self.store.len();
        self.store.extend_from_slice(bytes);
        self.segments.push(Segment { event_idx, frame_no, start, data_off: off, len: bytes.len() });
        idx
    }

    fn set_owner(&mut self, start: i64, end: i64, seg_idx: usize) {
        let mut next = Vec::with_capacity(self.occupied.len() + 1);
        let mut inserted = false;
        for (s, e, c) in self.occupied.drain(..) {
            if e <= start {
                next.push((s, e, c));
            } else if s >= end {
                if !inserted {
                    next.push((start, end, seg_idx));
                    inserted = true;
                }
                next.push((s, e, c));
            } else {
                // 调用方保证空洞；残留左侧
                if s < start {
                    next.push((s, start, c));
                }
                if e > end {
                    next.push((end, e, c));
                }
            }
        }
        if !inserted {
            next.push((start, end, seg_idx));
        }
        self.occupied = next;
        self.occupied.sort_by_key(|(s, _, _)| *s);
    }

    /// 加入一段新数据。返回（重叠字节数，是否完全重复）。
    fn insert(&mut self, event_idx: usize, frame_no: u64, start: i64, incoming: &[u8], policy: OverlapPolicy) -> (i64, bool) {
        let end = start + incoming.len() as i64;
        if start >= end {
            return (0, false);
        }

        let mut lo = end;
        let mut hi = start;
        for (s, e, _) in &self.occupied {
            if *e <= start || *s >= end {
                continue;
            }
            lo = lo.min(*s);
            hi = hi.max(*e);
        }
        let has_overlap = lo < hi;
        let clo = lo.max(start);
        let chi = hi.min(end);

        let mut same = true;
        if has_overlap {
            for pos in clo..chi {
                if self.byte_at(pos) != Some(incoming[(pos - start) as usize]) {
                    same = false;
                    break;
                }
            }
        }
        let overlapped = if has_overlap { chi - clo } else { 0 };
        let pure_duplicate = has_overlap && same && self.covers(start, end);
        let seg_idx = self.add_segment(event_idx, frame_no, start, incoming);

        match policy {
            OverlapPolicy::FirstSeen => {
                if has_overlap && !same {
                    let slice = incoming[(clo - start) as usize..(chi - start) as usize].to_vec();
                    self.overwrites.push(OverwriteRecord {
                        event_idx,
                        frame_no,
                        start: clo,
                        end: chi,
                        bytes: bytes_hex(&slice),
                    });
                }
                let mut pos = start;
                while pos < end {
                    if self.is_occupied(pos) {
                        pos += 1;
                        continue;
                    }
                    let run_start = pos;
                    while pos < end && !self.is_occupied(pos) {
                        pos += 1;
                    }
                    self.set_owner(run_start, pos, seg_idx);
                }
            }
            OverlapPolicy::LastSeen => {
                if has_overlap && !same {
                    let old: Vec<u8> = (clo..chi).filter_map(|p| self.byte_at(p)).collect();
                    let owner = self.owner_frame(clo);
                    self.overwrites.push(OverwriteRecord {
                        event_idx: self
                            .locate(clo)
                            .map(|ci| self.segments[self.occupied[ci].2].event_idx)
                            .unwrap_or(0),
                        frame_no: owner,
                        start: clo,
                        end: chi,
                        bytes: bytes_hex(&old),
                    });
                    self.remove_owner(clo, chi);
                }
                self.set_owner(start, end, seg_idx);
            }
        }
        (overlapped, pure_duplicate)
    }

    fn remove_owner(&mut self, rlo: i64, rhi: i64) {
        let mut kept = Vec::new();
        for (s, e, c) in self.occupied.drain(..) {
            if e <= rlo || s >= rhi {
                kept.push((s, e, c));
            } else if s < rlo && e > rhi {
                kept.push((s, rlo, c));
                kept.push((rhi, e, c));
            } else if s < rlo {
                kept.push((s, rlo, c));
            } else if e > rhi {
                kept.push((rhi, e, c));
            }
        }
        self.occupied = kept;
        self.occupied.sort_by_key(|(s, _, _)| *s);
    }

    fn contiguous(&self) -> Vec<u8> {
        if self.occupied.is_empty() {
            return Vec::new();
        }
        let min = self.occupied.first().unwrap().0;
        let mut out = Vec::new();
        let mut pos = min;
        while let Some(b) = self.byte_at(pos) {
            out.push(b);
            pos += 1;
        }
        out
    }

    fn min_pos(&self) -> Option<i64> {
        self.occupied.first().map(|(s, _, _)| *s)
    }

    fn max_pos(&self) -> Option<i64> {
        self.occupied.last().map(|(_, e, _)| *e)
    }

    fn gaps(&self) -> Vec<(i64, i64)> {
        let mut gaps = Vec::new();
        let mut prev_end: Option<i64> = None;
        for (s, e, _) in &self.occupied {
            if let Some(pe) = prev_end {
                if *s > pe {
                    gaps.push((pe, *s));
                }
            }
            prev_end = Some(prev_end.map_or(*e, |pe| pe.max(*e)));
        }
        gaps
    }
}

pub fn bytes_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

/// 单个 TCP 段事件的分析记录。
#[derive(Debug, Clone)]
pub struct SegmentEvent {
    pub frame_no: u64,
    pub frame_nos: Vec<u64>,
    pub ts_ns: i64,
    pub seq: u32,
    pub end_seq: u32,
    pub payload_len: usize,
    pub flags: u8,
    pub kind: String,
    pub note: String,
    pub rel_start: Option<i64>,
    pub rel_end: Option<i64>,
    pub filled_gap: bool,
    pub new_bytes: usize,
    pub fragmented: bool,
}

/// 对外暴露的方向汇总。
#[derive(Debug, Clone)]
pub struct DirSummary {
    pub is_client: bool,
    pub endpoint: String,
    pub saw_syn: bool,
    pub saw_synack: bool,
    pub syn_seq: Option<u32>,
    pub anchor_seq: Option<u32>,
    pub first_data_seq: Option<u32>,
    pub seq_first: Option<u32>,
    pub seq_last: Option<u32>,
    pub rel_data_first: Option<i64>,
    pub rel_data_last: Option<i64>,
    pub fin_seq: Option<u32>,
    pub rst_seq: Option<u32>,
    pub expected_len: Option<i64>,
    pub contiguous_len: usize,
    pub gaps: Vec<(i64, i64)>,
    pub total_data_bytes: i64,
    pub events: Vec<SegmentEvent>,
    pub overwrites: Vec<OverwriteRecord>,
    pub segments: usize,
    pub out_of_order: usize,
    pub retransmissions: usize,
    pub conflicts: usize,
}

#[derive(Debug, Clone)]
struct DirState {
    is_client: bool,
    syn_seq: Option<u32>,
    saw_synack: bool,
    anchor_seq: Option<u32>,
    first_data_seq: Option<u32>,
    seq_first: Option<u32>,
    seq_last: Option<u32>,
    fin_seq: Option<u32>,
    rst_seq: Option<u32>,
    expected: i64,
    space: ByteSpace,
    events: Vec<SegmentEvent>,
    segments: usize,
    out_of_order: usize,
    retransmissions: usize,
    conflicts: usize,
}

impl DirState {
    fn new(is_client: bool) -> Self {
        DirState {
            is_client,
            syn_seq: None,
            saw_synack: false,
            anchor_seq: None,
            first_data_seq: None,
            seq_first: None,
            seq_last: None,
            fin_seq: None,
            rst_seq: None,
            expected: 0,
            space: ByteSpace::new(),
            events: Vec::new(),
            segments: 0,
            out_of_order: 0,
            retransmissions: 0,
            conflicts: 0,
        }
    }

    /// 把 32 位环绕序号投影到 64 位线性值。anchor 是数据 0 字节对应的原始序号。
    fn project(&self, raw: u32) -> i64 {
        let anchor = self.anchor_seq.unwrap_or(raw);
        let diff = raw.wrapping_sub(anchor) as i32 as i64;
        diff
    }

    fn process(
        &mut self,
        event_idx_base: usize,
        frame_no: u64,
        frame_nos: &[u64],
        ts_ns: i64,
        seg: &TcpSegment,
        fragmented: bool,
        policy: OverlapPolicy,
    ) {
        let is_syn = seg.flags & TCP_SYN != 0;
        let is_fin = seg.flags & TCP_FIN != 0;
        let is_rst = seg.flags & TCP_RST != 0;
        let is_ack = seg.flags & TCP_ACK != 0;
        let data_len = seg.payload.len() as i64;
        let end_raw = seg.seq.wrapping_add(data_len as u32);

        if self.seq_first.is_none() {
            self.seq_first = Some(seg.seq);
        }
        self.seq_last = Some(seg.seq);
        self.segments += 1;

        if is_syn && self.syn_seq.is_none() {
            self.syn_seq = Some(seg.seq);
            if is_ack {
                self.saw_synack = true;
            }
            if self.anchor_seq.is_none() {
                self.anchor_seq = Some(seg.seq.wrapping_add(1));
                self.expected = 0;
            }
        } else if !is_syn && self.anchor_seq.is_none() && data_len > 0 {
            // 抓包在会话中间开始：以首个数据段为锚，partial，不伪造握手。
            self.anchor_seq = Some(seg.seq);
            self.expected = 0;
        }

        // SYN 重传（带 ACK 的重复 SYN/SYN-ACK）。
        if is_syn && self.syn_seq == Some(seg.seq) && self.events.iter().any(|e| e.flags & TCP_SYN != 0) {
            self.events.push(SegmentEvent {
                frame_no,
                frame_nos: frame_nos.to_vec(),
                ts_ns,
                seq: seg.seq,
                end_seq: end_raw,
                payload_len: seg.payload.len(),
                flags: seg.flags,
                kind: "syn-retransmit".into(),
                note: "重复 SYN（可能为握手重传）".into(),
                rel_start: None,
                rel_end: None,
                filled_gap: false,
                new_bytes: 0,
                fragmented,
            });
            if is_ack {
                self.saw_synack = true;
            }
            self.retransmissions += 1;
            return;
        }

        if is_rst {
            self.rst_seq = Some(seg.seq);
            self.events.push(SegmentEvent {
                frame_no,
                frame_nos: frame_nos.to_vec(),
                ts_ns,
                seq: seg.seq,
                end_seq: end_raw,
                payload_len: seg.payload.len(),
                flags: seg.flags,
                kind: "rst".into(),
                note: "RST 复位".into(),
                rel_start: self.anchor_seq.map(|a| seg.seq.wrapping_sub(a) as i32 as i64),
                rel_end: None,
                filled_gap: false,
                new_bytes: 0,
                fragmented,
            });
            return;
        }

        if is_fin {
            self.fin_seq = Some(end_raw.wrapping_add(1));
        }

        if data_len == 0 {
            let kind = if is_syn {
                "syn".into()
            } else if is_fin {
                "fin".into()
            } else {
                "ack".into()
            };
            self.events.push(SegmentEvent {
                frame_no,
                frame_nos: frame_nos.to_vec(),
                ts_ns,
                seq: seg.seq,
                end_seq: end_raw.wrapping_add(if is_fin { 1 } else { 0 }),
                payload_len: 0,
                flags: seg.flags,
                kind,
                note: String::new(),
                rel_start: self.anchor_seq.map(|a| seg.seq.wrapping_sub(a) as i32 as i64),
                rel_end: None,
                filled_gap: false,
                new_bytes: 0,
                fragmented,
            });
            return;
        }

        if self.first_data_seq.is_none() {
            self.first_data_seq = Some(seg.seq);
        }

        let start = self.project(seg.seq);
        let end = start + data_len;
        let gaps_before: std::collections::HashSet<(i64, i64)> = self.space.gaps().into_iter().collect();
        let contig_before = self.contiguous_upto();
        let (overlapped, pure_duplicate) =
            self.space.insert(event_idx_base + self.events.len(), frame_no, start, &seg.payload, policy);
        let gaps_after: std::collections::HashSet<(i64, i64)> = self.space.gaps().into_iter().collect();
        let contig_after = self.contiguous_upto();
        let filled_gap = gaps_after.len() < gaps_before.len() || contig_after > contig_before;

        let mut new_bytes = 0i64;
        for pos in start..end {
            if self.space.owner_frame(pos) == frame_no {
                new_bytes += 1;
            }
        }

        let gap_before = start > self.expected;
        let kind;
        let mut note = String::new();
        if pure_duplicate {
            kind = "retransmit";
            note = "完全重复的已确认数据".into();
            self.retransmissions += 1;
        } else if overlapped > 0 {
            if gap_before {
                kind = "overlap-out-of-order";
                note = "乱序到达且与既有片段重叠".into();
                self.out_of_order += 1;
            } else {
                kind = "overlap-conflict-or-partial";
                note = "与既有片段部分重叠".into();
            }
            self.conflicts += 1;
        } else if gap_before {
            kind = "out-of-order";
            note = format!("数据早到或缺失前段：期望相对序号 {}，实际 {}", self.expected, start);
            self.out_of_order += 1;
        } else if new_bytes == 0 {
            kind = "retransmit";
            self.retransmissions += 1;
        } else {
            kind = "in-order";
        }

        self.expected = self.contiguous_upto();

        self.events.push(SegmentEvent {
            frame_no,
            frame_nos: frame_nos.to_vec(),
            ts_ns,
            seq: seg.seq,
            end_seq: end_raw,
            payload_len: seg.payload.len(),
            flags: seg.flags,
            kind: kind.into(),
            note,
            rel_start: Some(start),
            rel_end: Some(end),
            filled_gap,
            new_bytes: new_bytes as usize,
            fragmented,
        });
    }

    fn contiguous_upto(&self) -> i64 {
        let min = match self.space.min_pos() {
            Some(m) if m <= 0 => m,
            Some(_) => 0,
            None => return 0,
        };
        let mut pos = min.max(0);
        while self.space.byte_at(pos).is_some() {
            pos += 1;
        }
        pos
    }

    fn finish(self, endpoint: String) -> DirSummary {
        let total_data_bytes = self.space.max_pos().unwrap_or(0) - self.space.min_pos().unwrap_or(0).min(0);
        let contiguous = self.space.contiguous();
        let rel_first = self.space.min_pos();
        let rel_last = self.space.max_pos();
        let expected_len = self.fin_seq.map(|f| {
            let anchor = self.anchor_seq.unwrap_or(f);
            f.wrapping_sub(anchor) as i32 as i64
        });
        DirSummary {
            is_client: self.is_client,
            endpoint,
            saw_syn: self.syn_seq.is_some(),
            saw_synack: self.saw_synack,
            syn_seq: self.syn_seq,
            anchor_seq: self.anchor_seq,
            first_data_seq: self.first_data_seq,
            seq_first: self.seq_first,
            seq_last: self.seq_last,
            rel_data_first: rel_first,
            rel_data_last: rel_last,
            fin_seq: self.fin_seq,
            rst_seq: self.rst_seq,
            expected_len,
            contiguous_len: contiguous.len(),
            gaps: self.space.gaps(),
            total_data_bytes,
            events: self.events,
            overwrites: self.space.overwrites,
            segments: self.segments,
            out_of_order: self.out_of_order,
            retransmissions: self.retransmissions,
            conflicts: self.conflicts,
        }
    }

    fn take_contiguous(&self) -> Vec<u8> {
        self.space.contiguous()
    }
}

#[derive(Debug, Clone)]
pub struct SessionOut {
    pub id: String,
    pub canonical_key: String,
    pub generation: u32,
    pub client: String,
    pub server: String,
    pub client_port: u16,
    pub server_port: u16,
    pub first_frame_no: u64,
    pub last_frame_no: u64,
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    pub status: String,
    pub close_reason: Option<String>,
    pub handshake: String,
    pub partial_start: bool,
    pub c2s: DirSummary,
    pub s2c: DirSummary,
    pub c2s_bytes: Vec<u8>,
    pub s2c_bytes: Vec<u8>,
}

struct Generation {
    gen_no: u32,
    client: IpAddr,
    server: IpAddr,
    client_port: u16,
    server_port: u16,
    first_frame_no: u64,
    first_ts_ns: i64,
    last_ts_ns: i64,
    last_frame_no: u64,
    c2s: DirState,
    s2c: DirState,
    open: bool,
    client_fin: bool,
    server_fin: bool,
    client_rst: bool,
    server_rst: bool,
    close_reason: Option<String>,
    handshake: String,
    partial_start: bool,
}

impl Generation {
    fn new(
        gen_no: u32,
        client: IpAddr,
        server: IpAddr,
        client_port: u16,
        server_port: u16,
        frame_no: u64,
        ts_ns: i64,
        syn_seen: bool,
    ) -> Self {
        Generation {
            gen_no,
            client,
            server,
            client_port,
            server_port,
            first_frame_no: frame_no,
            first_ts_ns: ts_ns,
            last_ts_ns: ts_ns,
            last_frame_no: frame_no,
            c2s: DirState::new(true),
            s2c: DirState::new(false),
            open: true,
            client_fin: false,
            server_fin: false,
            client_rst: false,
            server_rst: false,
            close_reason: None,
            handshake: if syn_seen { "unknown".into() } else { "partial".into() },
            partial_start: !syn_seen,
        }
    }

    fn touch(&mut self, frame_no: u64, ts_ns: i64) {
        self.last_ts_ns = ts_ns;
        self.last_frame_no = frame_no;
    }

    fn evaluate_close(&mut self, c_flags: u8, s_flags: u8) {
        // FIN 与 RST 竞态：同一批次/相邻时间若两者都出现，RST 优先作为关闭原因。
        let c_rst = self.client_rst || c_flags & TCP_RST != 0;
        let s_rst = self.server_rst || s_flags & TCP_RST != 0;
        let c_fin = self.client_fin || c_flags & TCP_FIN != 0;
        let s_fin = self.server_fin || s_flags & TCP_FIN != 0;
        self.client_rst = c_rst;
        self.server_rst = s_rst;
        self.client_fin = c_fin;
        self.server_fin = s_fin;

        if c_rst || s_rst {
            self.open = false;
            self.close_reason = Some("rst".into());
        } else if c_fin && s_fin {
            self.open = false;
            self.close_reason = Some("fin-fin".into());
        } else if c_fin || s_fin {
            // 单向 FIN：仍保持开放等待对端（可能在后续帧到来）。
        }
    }

    fn classify_handshake(&mut self) {
        if self.partial_start {
            self.handshake = "partial".into();
            return;
        }
        let client_syn = self.c2s.syn_seq.is_some();
        let synack = self.s2c.saw_synack;
        let server_syn = self.s2c.syn_seq.is_some();
        let client_ack = self
            .c2s
            .events
            .iter()
            .any(|e| e.flags & TCP_ACK != 0 && e.flags & TCP_SYN == 0);
        self.handshake = if client_syn && synack && client_ack {
            "full".into()
        } else if client_syn && server_syn {
            "syn-syn".into()
        } else if client_syn {
            "syn-only".into()
        } else {
            "partial".into()
        };
    }
}

struct Session {
    canonical: String,
    gens: Vec<Generation>,
}

fn canonical_key(a: IpAddr, ap: u16, b: IpAddr, bp: u16) -> (String, IpAddr, u16, IpAddr, u16) {
    let ta = (a.to_string(), ap);
    let tb = (b.to_string(), bp);
    if ta <= tb {
        (format!("{}:{}<->{}:{}", a, ap, b, bp), a, ap, b, bp)
    } else {
        (format!("{}:{}<->{}:{}", b, bp, a, ap), b, bp, a, ap)
    }
}

fn is_new_syn_attempt(existing: &Generation, seg: &TcpSegment, from_client: bool) -> bool {
    if seg.flags & TCP_SYN == 0 {
        return false;
    }
    let dir = if from_client { &existing.c2s } else { &existing.s2c };
    match dir.syn_seq {
        Some(known) => known != seg.seq,
        None => false,
    }
}

pub struct Engine {
    sessions: Vec<Session>,
    policy: OverlapPolicy,
    timeout_ns: i64,
}

impl Engine {
    pub fn new(policy: OverlapPolicy, timeout_ns: i64) -> Self {
        Engine { sessions: Vec::new(), policy, timeout_ns }
    }

    pub fn run(mut self, datagrams: &[Datagram]) -> Vec<SessionOut> {
        for dg in datagrams {
            let seg = match &dg.l4 {
                L4::Tcp(s) => s,
                L4::Other(_) => continue,
            };
            let (key, ea, ep, eb, eport) = canonical_key(dg.src, seg.sport, dg.dst, seg.dport);
            let from_a = dg.src == ea && seg.sport == ep;

            let session = match self.sessions.iter_mut().position(|s| s.canonical == key) {
                Some(i) => &mut self.sessions[i],
                None => {
                    self.sessions.push(Session { canonical: key.clone(), gens: Vec::new() });
                    self.sessions.last_mut().unwrap()
                }
            };

            // 超时关闭开放代次。
            if let Some(g) = session.gens.last_mut() {
                if g.open && dg.ts_ns - g.last_ts_ns > self.timeout_ns {
                    g.open = false;
                    g.close_reason = Some("timeout".into());
                }
            }

            let is_syn = seg.flags & TCP_SYN != 0;
            let data_or_ctl = !seg.payload.is_empty()
                || seg.flags & (TCP_SYN | TCP_FIN | TCP_RST) != 0;
            let open_last = session.gens.last().map(|g| g.open).unwrap_or(false);
            let mut create_new = session.gens.is_empty();
            if !create_new {
                if open_last {
                    // 开放代次上出现不同 ISN 的 SYN：四元组复用（RST/SYN 竞态后的新连接）。
                    if is_syn {
                        let last = session.gens.last().unwrap();
                        create_new = is_new_syn_attempt(last, seg, from_a);
                    }
                } else {
                    // 上一代次已结束：新 SYN 开新代次；无握手数据按 partial 新代次。
                    create_new = data_or_ctl;
                }
            }

            if create_new {
                let next = session.gens.len() as u32 + 1;
                if from_a {
                    session.gens.push(Generation::new(next, ea, eb, ep, eport, dg.first_frame_no, dg.ts_ns, is_syn));
                } else {
                    session.gens.push(Generation::new(next, eb, ea, eport, ep, dg.first_frame_no, dg.ts_ns, is_syn));
                }
            }

            let g = session.gens.last_mut().unwrap();
            g.touch(dg.first_frame_no, dg.ts_ns);
            let from_client = dg.src == g.client && seg.sport == g.client_port;
            let event_base = if from_client { g.c2s.events.len() } else { g.s2c.events.len() };
            if from_client {
                g.c2s.process(event_base, dg.first_frame_no, &dg.frame_nos, dg.ts_ns, seg, dg.fragmented, self.policy);
            } else {
                g.s2c.process(event_base, dg.first_frame_no, &dg.frame_nos, dg.ts_ns, seg, dg.fragmented, self.policy);
            }

            let c_flags = g.c2s.events.last().map(|e| e.flags).unwrap_or(0);
            let s_flags = g.s2c.events.last().map(|e| e.flags).unwrap_or(0);
            if from_client {
                g.evaluate_close(c_flags, 0);
            } else {
                g.evaluate_close(0, s_flags);
            }
        }

        let mut out = Vec::new();
        for s in &self.sessions {
            for g in &s.gens {
                let mut gg = g.clone();
                if gg.open {
                    gg.open = false;
                    gg.close_reason = Some("capture-end".into());
                }
                gg.classify_handshake();
                let c_bytes = gg.c2s.take_contiguous();
                let s_bytes = gg.s2c.take_contiguous();
                let c2s = clone_dir_finish(&mut gg.c2s, format!("{}:{}", gg.client, gg.client_port));
                let s2c = clone_dir_finish(&mut gg.s2c, format!("{}:{}", gg.server, gg.server_port));
                let status = match gg.close_reason.as_deref() {
                    Some("rst") => "reset",
                    Some("fin-fin") => "closed",
                    Some("timeout") => "timeout",
                    _ => "partial-capture",
                };
                out.push(SessionOut {
                    id: format!("{}#g{}", s.canonical, gg.gen_no),
                    canonical_key: s.canonical.clone(),
                    generation: gg.gen_no,
                    client: gg.client.to_string(),
                    server: gg.server.to_string(),
                    client_port: gg.client_port,
                    server_port: gg.server_port,
                    first_frame_no: gg.first_frame_no,
                    last_frame_no: gg.last_frame_no,
                    first_ts_ns: gg.first_ts_ns,
                    last_ts_ns: gg.last_ts_ns,
                    status: status.into(),
                    close_reason: gg.close_reason.clone(),
                    handshake: gg.handshake.clone(),
                    partial_start: gg.partial_start,
                    c2s,
                    s2c,
                    c2s_bytes: c_bytes,
                    s2c_bytes: s_bytes,
                });
            }
        }
        out.sort_by(|a, b| a.first_frame_no.cmp(&b.first_frame_no).then(a.generation.cmp(&b.generation)));
        out
    }
}

fn clone_dir_finish(dir: &mut DirState, endpoint: String) -> DirSummary {
    let d = dir.clone();
    d.finish(endpoint)
}
