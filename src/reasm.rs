//! 帧 -> IP 数据报 -> TCP 段 -> 会话（含代次）-> 重组结果 的主分析流水线。

use crate::frag::{FragConfig, FragEmit, FragTable, QuarantineEvent};
use crate::json::Value;
use crate::seq::{OverlapPolicy, Seq32, SeqSpace};
use crate::wire::{
    parse_frame, CompleteDatagram, FrameOutcome, IpMeta, TcpFlags, TcpMeta, LINK_ETHERNET,
};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct AnalyzeConfig {
    pub overlap: OverlapPolicy,
    /// 空闲超时（微秒）：同四元组间隔超过该值视为新代次。
    pub idle_timeout_us: i64,
    pub frag: FragConfig,
}

impl Default for AnalyzeConfig {
    fn default() -> Self {
        AnalyzeConfig {
            overlap: OverlapPolicy::FirstSeen,
            idle_timeout_us: 120_000_000,
            frag: FragConfig::default(),
        }
    }
}

/// 输入给分析器的一帧。
#[derive(Debug, Clone)]
pub struct InputFrame {
    pub order: usize,
    pub ts_us: i64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Segment {
    /// 原始帧序号（输入中的位置）。
    pub frame_index: usize,
    /// 该 TCP 段所在 IP 数据报的交付序号。
    pub delivery: usize,
    pub ts_us: i64,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub payload: Vec<u8>,
    pub ip_checksum_ok: bool,
    pub tcp_checksum_ok: bool,
    /// 若由 IP 分片重组而来，记录参与帧。
    pub fragment_frames: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct FrameNote {
    pub frame_index: usize,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct Analysis {
    pub config_json: Value,
    pub result: Value,
    pub frame_count: usize,
    pub tcp_segment_count: usize,
    pub session_count: usize,
    pub streams: Vec<StreamBlob>,
}

/// 端点（IP + 端口）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Endpoint { ip, port }
    }
    fn key(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

/// 规范化四元组键（方向无关，含 IP 版本以避免 v4/v6 同字面量碰撞）。
fn four_tuple_key(a: Endpoint, b: Endpoint) -> String {
    fn tag(e: Endpoint) -> String {
        match e.ip {
            std::net::IpAddr::V4(_) => format!("4:{}", e.key()),
            std::net::IpAddr::V6(_) => format!("6:{}", e.key()),
        }
    }
    let (x, y) = (tag(a), tag(b));
    if x <= y {
        format!("{}<>{}", x, y)
    } else {
        format!("{}<>{}", y, x)
    }
}

// ---------------------------------------------------------------------------
// 每个方向的重组
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DirSegment {
    frame_index: usize,
    delivery: usize,
    ts_us: i64,
    seq: u32,
    flags: TcpFlags,
    data_len: u64,
    // 相对空间信息在插入后填
    rel_start: Option<u64>,
    rel_end: Option<u64>,
    retransmit: bool,
    partial_overlap: bool,
    out_of_order: bool,
    new_bytes: usize,
    collisions: Vec<crate::seq::Collision>,
    checksum_ok: bool,
    bytes_hex: Option<String>,
}

#[derive(Debug, Clone)]
struct DirState {
    #[allow(dead_code)]
    endpoint: Endpoint,
    #[allow(dead_code)]
    peer: Endpoint,
    space: SeqSpace,
    base: Option<Seq32>,
    base_frame: Option<usize>,
    /// 观察到的最小/最大原始序号区间（含 SYN/FIN 占用位）。
    min_seq: Option<Seq32>,
    max_next: Option<Seq32>,
    syn_seen: bool,
    fin_seen: bool,
    rst_seen: bool,
    segments: Vec<DirSegment>,
}

impl DirState {
    fn new(endpoint: Endpoint, peer: Endpoint) -> Self {
        DirState {
            endpoint,
            peer,
            space: SeqSpace::new(),
            base: None,
            base_frame: None,
            min_seq: None,
            max_next: None,
            syn_seen: false,
            fin_seen: false,
            rst_seen: false,
            segments: Vec::new(),
        }
    }

    fn init_base(&mut self, seq: Seq32, syn: bool, frame_index: usize) {
        if self.base.is_none() {
            self.base = Some(if syn { seq.add(1) } else { seq });
            self.base_frame = Some(frame_index);
        }
    }

    fn feed(&mut self, seg: &Segment, policy: OverlapPolicy) {
        let seq = Seq32(seg.seq);
        let syn = seg.flags.syn;
        self.init_base(seq, syn, seg.frame_index);
        let base = self.base.unwrap();

        // 原始序号观察区间。
        self.min_seq = Some(match self.min_seq {
            Some(m) => {
                if seq.lt(m) {
                    seq
                } else {
                    m
                }
            }
            None => seq,
        });
        let seq_len =
            seg.payload.len() as u64 + if seg.flags.fin { 1 } else { 0 } + if syn { 1 } else { 0 };
        let next = seq.add(seq_len);
        self.max_next = Some(match self.max_next {
            Some(m) => {
                if m.lt(next) {
                    next
                } else {
                    m
                }
            }
            None => next,
        });
        if syn {
            self.syn_seen = true;
        }
        if seg.flags.fin {
            self.fin_seen = true;
        }
        if seg.flags.rst {
            self.rst_seen = true;
        }

        // 数据字节的相对偏移：SYN 本身不携带数据，data 从 seq+1 起。
        let data_start_seq = if syn { seq.add(1) } else { seq };
        let rel_start = data_start_seq.offset_from(base);
        let out_of_order = !seg.payload.is_empty() && rel_start > self.space.contiguous_prefix();
        let report = self
            .space
            .insert(rel_start, &seg.payload, seg.frame_index, policy);
        // 纯重传：有负载但没有带来任何新字节（字节不同的碰撞仍留在证据中）。
        let retransmit = !seg.payload.is_empty() && report.new_cells.is_empty();
        // 部分重叠：既补了新字节，又与已有字节相交。
        let partial_overlap = !report.overlap_cells.is_empty() && !report.new_cells.is_empty();

        self.segments.push(DirSegment {
            frame_index: seg.frame_index,
            delivery: seg.delivery,
            ts_us: seg.ts_us,
            seq: seg.seq,
            flags: seg.flags,
            data_len: seg.payload.len() as u64,
            rel_start: if seg.payload.is_empty() && !syn && !seg.flags.fin {
                None
            } else {
                Some(rel_start)
            },
            rel_end: Some(rel_start + seg.payload.len() as u64),
            retransmit,
            partial_overlap,
            out_of_order,
            new_bytes: report.new_cells.len(),
            collisions: report.collisions,
            checksum_ok: seg.ip_checksum_ok && seg.tcp_checksum_ok,
            bytes_hex: if seg.payload.is_empty() {
                None
            } else {
                Some(to_hex(&seg.payload))
            },
        });
    }
}

// ---------------------------------------------------------------------------
// 会话与代次
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum CloseReason {
    Rst,
    Fin,
    Timeout,
    /// 旧连接仍活跃时同四元组出现新 SYN（复用抢占）。
    Reused,
}

impl CloseReason {
    fn as_str(&self) -> &'static str {
        match self {
            CloseReason::Rst => "rst",
            CloseReason::Fin => "fin",
            CloseReason::Timeout => "timeout",
            CloseReason::Reused => "reused",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirKey {
    /// 规范化后较小的端点
    A,
    B,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SideState {
    /// 未见 FIN/RST
    Open,
    /// 已发 FIN，等待对端确认
    FinWait,
    /// FIN 已被对端 ACK
    FinAcked,
    /// 已发 RST
    Rst,
}

#[derive(Debug, Clone)]
struct Generation {
    index: u32,
    started_us: Option<i64>,
    last_us: Option<i64>,
    /// 发起 SYN 的端点（partial 时为 None）。
    initiator: Option<Endpoint>,
    /// 见到纯 SYN（发起方）。
    saw_initial_syn: bool,
    /// 见到 SYN-ACK（响应方）。
    saw_synack: bool,
    handshake: String,
    dirs: HashMap<Endpoint, (DirKey, DirState)>,
    /// 每个端点的关闭状态。
    side: HashMap<Endpoint, SideState>,
    closed: bool,
    close_reason: Option<CloseReason>,
    /// 关单事件（FIN/RST 竞态用，保留帧顺序）。
    events: Vec<CloseEvent>,
}

#[derive(Debug, Clone)]
struct CloseEvent {
    frame_index: usize,
    endpoint: Endpoint,
    rst: bool,
    fin: bool,
    ack: u32,
}

impl Generation {
    fn new(index: u32) -> Self {
        Generation {
            index,
            started_us: None,
            last_us: None,
            initiator: None,
            saw_initial_syn: false,
            saw_synack: false,
            handshake: "partial".to_string(),
            dirs: HashMap::new(),
            side: HashMap::new(),
            closed: false,
            close_reason: None,
            events: Vec::new(),
        }
    }

    fn dir_key_for(&mut self, ep: Endpoint, peer: Endpoint) -> DirKey {
        if let Some((k, _)) = self.dirs.get(&ep) {
            return *k;
        }
        // 第一个出现的端点若 <= 对端为 A，否则 B；以规范化端点大小为准。
        let key = if ep <= peer { DirKey::A } else { DirKey::B };
        self.dirs.insert(ep, (key, DirState::new(ep, peer)));
        self.side.insert(ep, SideState::Open);
        key
    }

    fn dir_mut(&mut self, ep: Endpoint) -> &mut DirState {
        &mut self.dirs.get_mut(&ep).unwrap().1
    }
}

#[derive(Debug)]
struct SessionAggregate {
    key: String,
    endpoint_a: Option<Endpoint>,
    endpoint_b: Option<Endpoint>,
    generations: Vec<Generation>,
}

impl SessionAggregate {
    fn new(key: String) -> Self {
        SessionAggregate {
            key,
            endpoint_a: None,
            endpoint_b: None,
            generations: Vec::new(),
        }
    }

    fn remember(&mut self, x: Endpoint, y: Endpoint) {
        if x <= y {
            self.endpoint_a = Some(x);
            self.endpoint_b = Some(y);
        } else {
            self.endpoint_a = Some(y);
            self.endpoint_b = Some(x);
        }
    }

    fn active(&mut self) -> &mut Generation {
        if self.generations.last().map(|g| g.closed).unwrap_or(true) {
            let idx = self.generations.len() as u32;
            self.generations.push(Generation::new(idx));
        }
        self.generations.last_mut().unwrap()
    }

    fn close_active(&mut self, reason: CloseReason) {
        if let Some(g) = self.generations.last_mut() {
            if !g.closed {
                g.closed = true;
                g.close_reason = Some(reason);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 分析器
// ---------------------------------------------------------------------------

pub struct Analyzer {
    pub config: AnalyzeConfig,
    sessions: HashMap<String, SessionAggregate>,
    /// 会话键首次出现顺序，用于稳定编号。
    session_order: Vec<String>,
    notes: Vec<FrameNote>,
    quarantines: Vec<QuarantineEvent>,
    incomplete_frags: Vec<crate::frag::IncompleteGroup>,
    tcp_segments: Vec<Segment>,
    frame_count: usize,
}

impl Analyzer {
    pub fn new(config: AnalyzeConfig) -> Self {
        Analyzer {
            config,
            sessions: HashMap::new(),
            session_order: Vec::new(),
            notes: Vec::new(),
            quarantines: Vec::new(),
            incomplete_frags: Vec::new(),
            tcp_segments: Vec::new(),
            frame_count: 0,
        }
    }

    pub fn run(mut self, frames: &[InputFrame], link_type: u32) -> Analysis {
        // 全时间排序：(时间戳, 原始帧序号)。原始顺序来自输入位置。
        let mut ordered: Vec<&InputFrame> = frames.iter().collect();
        ordered.sort_by(|a, b| a.ts_us.cmp(&b.ts_us).then_with(|| a.order.cmp(&b.order)));

        let mut frag = FragTable::new();
        // delivery：数据报可交付给 TCP 引擎的单调序号（相同时间戳按帧序号）。
        let mut deliverable: Vec<Delivered> = Vec::new();

        for fr in ordered.iter() {
            self.frame_count += 1;
            match parse_frame(&fr.data, link_type, fr.order) {
                Ok(FrameOutcome::Ignored) => {}
                Ok(FrameOutcome::Complete(dg)) => {
                    deliverable.push(Delivered {
                        frame_index: fr.order,
                        ts_us: fr.ts_us,
                        datagram: dg,
                        fragment_frames: vec![fr.order],
                    });
                }
                Ok(FrameOutcome::Fragment(piece)) => {
                    match frag.add(piece, fr.order, &self.config.frag) {
                        FragEmit::Complete(re) => {
                            let frame_index = *re.piece_frames.last().unwrap_or(&fr.order);
                            let dg = decode_reassembled(&re);
                            match dg {
                                Ok(dg) => deliverable.push(Delivered {
                                    frame_index,
                                    ts_us: fr.ts_us,
                                    datagram: dg,
                                    fragment_frames: re.piece_frames,
                                }),
                                Err(e) => self.notes.push(FrameNote {
                                    frame_index: fr.order,
                                    kind: "reassembled-tcp-parse".into(),
                                    detail: e,
                                }),
                            }
                        }
                        FragEmit::Quarantined(q) => self.quarantines.push(q),
                        FragEmit::None => {}
                    }
                }
                Err(e) => self.notes.push(FrameNote {
                    frame_index: fr.order,
                    kind: "frame-parse-error".into(),
                    detail: e,
                }),
            }
        }
        self.incomplete_frags = frag.incomplete_groups();

        deliverable.sort_by(|a, b| {
            a.ts_us
                .cmp(&b.ts_us)
                .then_with(|| a.frame_index.cmp(&b.frame_index))
        });

        for (delivery, d) in deliverable.iter().enumerate() {
            let dg = &d.datagram;
            let Some(tcp) = &dg.tcp else { continue };
            let seg = Segment {
                frame_index: d.frame_index,
                delivery,
                ts_us: d.ts_us,
                src: dg.ip.src,
                dst: dg.ip.dst,
                src_port: tcp.src_port,
                dst_port: tcp.dst_port,
                seq: tcp.seq,
                ack: tcp.ack,
                flags: tcp.flags,
                payload: dg.payload.clone(),
                ip_checksum_ok: dg.ip.header_checksum_ok,
                tcp_checksum_ok: tcp.checksum_ok,
                fragment_frames: d.fragment_frames.clone(),
            };
            self.tcp_segments.push(seg);
        }

        self.process_segments();
        let tcp_segment_count = self.tcp_segments.len();

        let (root, n, streams) = self.build_json(link_type);
        Analysis {
            config_json: self.config_json(),
            result: root,
            frame_count: self.frame_count,
            tcp_segment_count,
            session_count: n,
            streams,
        }
    }

    fn process_segments(&mut self) {
        let segments = std::mem::take(&mut self.tcp_segments);
        for seg in segments {
            self.dispatch(seg);
        }
    }

    fn config_json(&self) -> Value {
        Value::obj(vec![
            ("overlap", Value::Str(self.config.overlap.as_str().into())),
            ("idle_timeout_us", Value::Int(self.config.idle_timeout_us)),
            (
                "frag_max_bytes",
                Value::Int(self.config.frag.max_bytes as i64),
            ),
            (
                "frag_max_pieces",
                Value::Int(self.config.frag.max_pieces as i64),
            ),
        ])
    }
}

struct Delivered {
    frame_index: usize,
    ts_us: i64,
    datagram: CompleteDatagram,
    fragment_frames: Vec<usize>,
}

fn decode_reassembled(re: &crate::frag::ReassembledDatagram) -> Result<CompleteDatagram, String> {
    if re.ip.protocol != crate::wire::IPPROTO_TCP {
        return Ok(CompleteDatagram {
            ip: re.ip.clone(),
            tcp: None,
            payload: re.segment.clone(),
        });
    }
    // 复用公开入口：手动重走 TCP 解析。
    let tcp = parse_tcp_from_segment(&re.segment, &re.ip)?;
    let doff = (tcp.data_offset as usize) * 4;
    let payload = re.segment.get(doff..).unwrap_or(&[]).to_vec();
    Ok(CompleteDatagram {
        ip: re.ip.clone(),
        tcp: Some(tcp),
        payload,
    })
}

pub fn parse_tcp_from_segment(segment: &[u8], ip: &IpMeta) -> Result<TcpMeta, String> {
    if segment.len() < 20 {
        return Err("tcp: 重组报文段短于 20 字节".into());
    }
    let src_port = u16::from_be_bytes([segment[0], segment[1]]);
    let dst_port = u16::from_be_bytes([segment[2], segment[3]]);
    let seq = u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]);
    let ack = u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]);
    let data_offset = segment[12] >> 4;
    if (data_offset as usize) * 4 > segment.len() || data_offset < 5 {
        return Err("tcp: 非法数据偏移".into());
    }
    let flags = TcpFlags::from_byte(segment[13]);
    let window = u16::from_be_bytes([segment[14], segment[15]]);
    let checksum_ok = crate::wire::verify_tcp_checksum(ip, segment);
    Ok(TcpMeta {
        src_port,
        dst_port,
        seq,
        ack,
        data_offset,
        flags,
        window,
        checksum_ok,
    })
}

fn to_hex(b: &[u8]) -> String {
    crate::hash::hex(b)
}

impl Analyzer {
    fn dispatch(&mut self, seg: Segment) {
        let src = Endpoint::new(seg.src, seg.src_port);
        let dst = Endpoint::new(seg.dst, seg.dst_port);
        let key = four_tuple_key(src, dst);

        if !self.sessions.contains_key(&key) {
            self.session_order.push(key.clone());
            self.sessions
                .insert(key.clone(), SessionAggregate::new(key.clone()));
        }
        let session = self.sessions.get_mut(&key).unwrap();
        session.remember(src, dst);

        // 1) 空闲超时：上一代与本段时间差超过阈值则关闭。
        if let Some(last) = session
            .generations
            .last()
            .and_then(|g| g.last_us)
            .filter(|_| !session.generations.last().map(|g| g.closed).unwrap_or(true))
        {
            if seg.ts_us.saturating_sub(last) > self.config.idle_timeout_us {
                session.close_active(CloseReason::Timeout);
            }
        }

        // 2) 关闭/复用判定。
        let need_new = {
            let gen = session.active();
            if gen.started_us.is_none() {
                false
            } else if seg.flags.syn {
                // SYN 重传（同发起方、序号一致、代次内已有相同 SYN）不换代。
                let is_retransmitted_syn = gen.initiator == Some(src)
                    && gen.dirs.get(&src).map_or(false, |(_, d)| {
                        d.segments.iter().any(|s| s.flags.syn && s.seq == seg.seq)
                    });
                // 对端的 SYN+ACK：若本代次已见到发起 SYN，属于同一三次握手。
                let is_handshake_synack = seg.flags.syn
                    && seg.flags.ack
                    && gen.initiator == Some(dst)
                    && gen.dirs.get(&dst).map_or(false, |(_, d)| d.syn_seen);
                if is_retransmitted_syn || is_handshake_synack {
                    false
                } else {
                    // 同四元组的新 SYN：无论旧连接是否优雅结束，都是新一代；
                    // 旧连接仍开着时记为 reused 抢占。
                    if !gen.closed {
                        gen.closed = true;
                        gen.close_reason = Some(CloseReason::Reused);
                    }
                    true
                }
            } else {
                gen.closed
            }
        };
        if need_new {
            let idx = session.generations.len() as u32;
            session.generations.push(Generation::new(idx));
        }

        // 3) 写入代次。
        let gen = session.active();
        gen.started_us = Some(gen.started_us.unwrap_or(seg.ts_us));
        gen.last_us = Some(seg.ts_us);
        if seg.flags.syn && !seg.flags.ack && gen.initiator.is_none() {
            gen.initiator = Some(src);
            gen.saw_initial_syn = true;
        } else if seg.flags.syn && seg.flags.ack && gen.initiator == Some(dst) {
            gen.saw_synack = true;
        }
        // 方向注册并喂入数据。
        gen.dir_key_for(src, dst);
        gen.dir_key_for(dst, src);
        gen.side.entry(src).or_insert(SideState::Open);
        gen.side.entry(dst).or_insert(SideState::Open);
        gen.dir_mut(src).feed(&seg, self.config.overlap);

        // 第三次握手 ACK：由发起方发出、无 SYN、ACK 号 = 对端 SYNACK.seq+1。
        // 注意必须在本段写入 DirState 之后判定，以便查得到对端 SYNACK。
        if seg.flags.syn && seg.flags.ack && gen.initiator == Some(dst) {
            gen.saw_synack = true;
        }
        let peer_synack_seq = gen
            .dirs
            .get(&dst)
            .and_then(|(_, d)| {
                d.segments
                    .iter()
                    .rev()
                    .find(|sg| sg.flags.syn && sg.flags.ack)
            })
            .map(|sa| sa.seq);
        let third_ack = gen.saw_initial_syn
            && gen.saw_synack
            && seg.flags.ack
            && !seg.flags.syn
            && gen.initiator == Some(src)
            && peer_synack_seq.map_or(false, |sq| seg.ack == sq.wrapping_add(1));
        if third_ack {
            gen.handshake = "full".to_string();
        } else if gen.handshake != "full"
            && (gen.saw_initial_syn || gen.saw_synack || seg.flags.syn)
        {
            gen.handshake = "syn-observed".to_string();
        } else if gen.handshake.is_empty() {
            gen.handshake = "partial".to_string();
        }

        // 4) FIN/RST/ACK 关闭状态机（相同时间戳靠帧序号排序天然有序）。
        let src_state = *gen.side.get(&src).unwrap_or(&SideState::Open);
        if seg.flags.rst {
            gen.events.push(CloseEvent {
                frame_index: seg.frame_index,
                endpoint: src,
                rst: true,
                fin: seg.flags.fin,
                ack: seg.ack,
            });
            gen.side.insert(src, SideState::Rst);
            // RST 立即结束整个代次；FIN+RST 同段时 RST 优先（竞态按帧序呈现于事件中）。
            gen.closed = true;
            gen.close_reason = Some(CloseReason::Rst);
            return;
        }

        if seg.flags.fin && src_state != SideState::FinWait && src_state != SideState::FinAcked {
            gen.side.insert(src, SideState::FinWait);
            gen.events.push(CloseEvent {
                frame_index: seg.frame_index,
                endpoint: src,
                rst: false,
                fin: true,
                ack: seg.ack,
            });
        }

        // ACK 是否确认了对端的 FIN：对端 FIN 的序列号 = fin_seq，数据末字节之后一位。
        if seg.flags.ack {
            let peer = dst;
            if let Some((_, dstate)) = gen.dirs.get(&peer) {
                if dstate.fin_seen {
                    // FIN 占用序号 = max_next - 1（仅当 FIN 属于最新观察段）。
                    if let Some(fin_abs) = fin_seq_of(dstate) {
                        let want = fin_abs.add(1).raw();
                        if seg.ack == want {
                            gen.side.insert(peer, SideState::FinAcked);
                        }
                    }
                }
            }
        }

        // 双向 FIN 均被确认 -> 优雅关闭。
        let fin_done = gen.side.values().all(|s| matches!(s, SideState::FinAcked))
            && gen.side.len() == 2
            && gen.dirs.values().all(|(_, d)| d.fin_seen);
        if fin_done {
            gen.closed = true;
            gen.close_reason = Some(CloseReason::Fin);
        }
    }
}

/// 找到首个携带 FIN 的段，返回其 FIN 字节占用的绝对序号。
fn fin_seq_of(d: &DirState) -> Option<Seq32> {
    let seg = d.segments.iter().find(|s| s.flags.fin)?;
    Some(Seq32(seg.seq).add(seg.data_len))
}

// ---------------------------------------------------------------------------
// 结果 JSON 与重组字节
// ---------------------------------------------------------------------------

use crate::json::Value as J;

impl Analyzer {
    fn build_json(&self, link_type: u32) -> (Value, usize, Vec<StreamBlob>) {
        let mut sessions_json = Vec::new();
        let mut streams = Vec::new();

        for (sess_no, key) in self.session_order.iter().enumerate() {
            let agg = &self.sessions[key];
            let session_id = format!("s{:03}", sess_no + 1);
            let mut generations_json = Vec::new();

            for gen in &agg.generations {
                let gen_id = format!("{}.g{:02}", session_id, gen.index + 1);
                let (a_ep, b_ep) = (agg.endpoint_a.unwrap(), agg.endpoint_b.unwrap());

                // 找出 a/b 各自的 DirState。
                let dir_view =
                    |ep: Endpoint| -> Option<&DirState> { gen.dirs.get(&ep).map(|(_, d)| d) };
                let (da, db) = (dir_view(a_ep), dir_view(b_ep));

                let initiator_label = gen.initiator.map(|ep| if ep == a_ep { "A" } else { "B" });

                let mut dirs_obj = Vec::new();
                for (label, ep, opt_d) in [("A", a_ep, da), ("B", b_ep, db)] {
                    let Some(d) = opt_d else {
                        dirs_obj.push((
                            label,
                            J::obj(vec![
                                ("endpoint", J::Str(ep.key())),
                                ("present", J::Bool(false)),
                            ]),
                        ));
                        continue;
                    };
                    let prefix = d.space.prefix_bytes();
                    let gaps = d.space.gaps();
                    let runs = d.space.covered_runs();
                    if label == "A" {
                        streams.push(StreamBlob {
                            session: gen_id.clone(),
                            dir_key: label.to_string(),
                            bytes: prefix.clone(),
                        });
                    } else {
                        streams.push(StreamBlob {
                            session: gen_id.clone(),
                            dir_key: label.to_string(),
                            bytes: prefix.clone(),
                        });
                    }
                    let base = d.base.map(|b| J::Int(b.raw() as i64)).unwrap_or(J::Null);
                    let base_frame = d.base_frame.map(|f| J::Int(f as i64)).unwrap_or(J::Null);
                    let observed = match (d.min_seq, d.max_next) {
                        (Some(lo), Some(hi)) => J::obj(vec![
                            ("seq_min", J::Int(lo.raw() as i64)),
                            ("next_max", J::Int(hi.raw() as i64)),
                            ("length_span", J::Int(hi.offset_from(lo) as i64)),
                        ]),
                        _ => J::Null,
                    };
                    dirs_obj.push((
                        label,
                        J::obj(vec![
                            ("present", J::Bool(true)),
                            ("endpoint", J::Str(ep.key())),
                            ("base_seq", base),
                            ("base_frame", base_frame),
                            ("syn_seen", J::Bool(d.syn_seen)),
                            ("fin_seen", J::Bool(d.fin_seen)),
                            ("rst_seen", J::Bool(d.rst_seen)),
                            ("observed", observed),
                            (
                                "delivered_length",
                                J::Int(d.space.contiguous_prefix() as i64),
                            ),
                            ("total_seen_bytes", J::Int(d.space.len() as i64)),
                            ("gaps", gaps_json(&gaps)),
                            ("covered_runs", runs_json(&runs)),
                            ("segments", segments_json(d)),
                            (
                                "checksum_bad_frames",
                                J::Array(
                                    d.segments
                                        .iter()
                                        .filter(|s| !s.checksum_ok)
                                        .map(|s| J::Int(s.frame_index as i64))
                                        .collect(),
                                ),
                            ),
                        ]),
                    ));
                }

                let close = match (&gen.closed, &gen.close_reason) {
                    (true, Some(r)) => Value::Object(vec![
                        ("state".to_string(), J::Str("closed".to_string())),
                        ("reason".to_string(), J::Str(r.as_str().to_string())),
                    ]),
                    _ => Value::Object(vec![("state".to_string(), J::Str("open".to_string()))]),
                };

                generations_json.push(J::obj(vec![
                    ("generation_id", J::Str(gen_id)),
                    ("index", J::Int(gen.index as i64 + 1)),
                    ("handshake", J::Str(gen.handshake.clone())),
                    (
                        "initiator",
                        match initiator_label {
                            Some(l) => J::Str(l.into()),
                            None => J::Null,
                        },
                    ),
                    ("start_ts_us", J::Int(gen.started_us.unwrap_or(0))),
                    ("last_ts_us", J::Int(gen.last_us.unwrap_or(0))),
                    ("close", close),
                    (
                        "close_events",
                        J::Array(
                            gen.events
                                .iter()
                                .map(|e| {
                                    J::obj(vec![
                                        ("frame", J::Int(e.frame_index as i64)),
                                        (
                                            "endpoint",
                                            J::Str(if e.endpoint == a_ep {
                                                "A".to_string()
                                            } else {
                                                "B".to_string()
                                            }),
                                        ),
                                        ("fin", J::Bool(e.fin)),
                                        ("rst", J::Bool(e.rst)),
                                        ("ack", J::Int(e.ack as i64)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                    (
                        "directions",
                        J::Object(
                            dirs_obj
                                .into_iter()
                                .map(|(k, v)| (k.to_string(), v))
                                .collect(),
                        ),
                    ),
                ]));
            }

            sessions_json.push(J::obj(vec![
                ("session_id", J::Str(session_id)),
                ("four_tuple", J::Str(agg.key.clone())),
                ("endpoint_a", J::Str(agg.endpoint_a.unwrap().key())),
                ("endpoint_b", J::Str(agg.endpoint_b.unwrap().key())),
                ("generations", J::Array(generations_json)),
            ]));
        }

        let root = J::obj(vec![
            ("analyzer", J::Str(crate::ANALYZER_VERSION.into())),
            ("link_type", J::Int(link_type as i64)),
            ("frame_count", J::Int(self.frame_count as i64)),
            ("tcp_segment_count", J::Int(self.tcp_segments.len() as i64)),
            ("config", self.config_json()),
            ("sessions", J::Array(sessions_json)),
            (
                "quarantined_datagrams",
                J::Array(
                    self.quarantines
                        .iter()
                        .map(|q| {
                            J::obj(vec![
                                ("frame", J::Int(q.frame_index as i64)),
                                ("key", J::Str(q.key.clone())),
                                ("src", J::Str(q.src.to_string())),
                                ("dst", J::Str(q.dst.to_string())),
                                ("ip_id", J::Int(q.ip_id as i64)),
                                ("reason", J::Str(q.reason.as_str().to_string())),
                                ("detail", J::Str(q.detail.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "incomplete_fragment_groups",
                J::Array(
                    self.incomplete_frags
                        .iter()
                        .map(|g| {
                            J::obj(vec![
                                ("piece_count", J::Int(g.piece_count as i64)),
                                (
                                    "frames",
                                    J::Array(g.frames.iter().map(|f| J::Int(*f as i64)).collect()),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "parse_notes",
                J::Array(
                    self.notes
                        .iter()
                        .map(|n| {
                            J::obj(vec![
                                ("frame", J::Int(n.frame_index as i64)),
                                ("kind", J::Str(n.kind.clone())),
                                ("detail", J::Str(n.detail.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]);

        let n = self.session_order.len();
        (root, n, streams)
    }
}

#[derive(Debug, Clone)]
pub struct StreamBlob {
    pub session: String,
    pub dir_key: String,
    pub bytes: Vec<u8>,
}

fn gaps_json(gaps: &[(u64, u64)]) -> Value {
    J::Array(
        gaps.iter()
            .map(|(s, e)| {
                J::obj(vec![
                    ("start", J::Int(*s as i64)),
                    ("end", J::Int(*e as i64)),
                    ("length", J::Int((e - s) as i64)),
                ])
            })
            .collect(),
    )
}

fn runs_json(runs: &[(u64, u64)]) -> Value {
    J::Array(
        runs.iter()
            .map(|(s, e)| {
                J::obj(vec![
                    ("start", J::Int(*s as i64)),
                    ("end", J::Int(*e as i64)),
                ])
            })
            .collect(),
    )
}

fn segments_json(d: &DirState) -> Value {
    // 段展示按交付（帧）顺序。
    let mut segs: Vec<&DirSegment> = d.segments.iter().collect();
    segs.sort_by(|a, b| {
        a.ts_us
            .cmp(&b.ts_us)
            .then_with(|| a.frame_index.cmp(&b.frame_index))
    });
    J::Array(
        segs.iter()
            .map(|s| {
                let mut flags = Vec::new();
                if s.flags.syn {
                    flags.push("SYN");
                }
                if s.flags.ack {
                    flags.push("ACK");
                }
                if s.flags.fin {
                    flags.push("FIN");
                }
                if s.flags.rst {
                    flags.push("RST");
                }
                if s.flags.psh {
                    flags.push("PSH");
                }
                J::obj(vec![
                    ("frame", J::Int(s.frame_index as i64)),
                    ("delivery", J::Int(s.delivery as i64)),
                    ("ts_us", J::Int(s.ts_us as i64)),
                    ("seq", J::Int(s.seq as i64)),
                    ("data_len", J::Int(s.data_len as i64)),
                    (
                        "rel_start",
                        match s.rel_start {
                            Some(v) => J::Int(v as i64),
                            None => J::Null,
                        },
                    ),
                    (
                        "rel_end",
                        match s.rel_end {
                            Some(v) => J::Int(v as i64),
                            None => J::Null,
                        },
                    ),
                    ("flags", J::Str(flags.join("|"))),
                    ("new_bytes", J::Int(s.new_bytes as i64)),
                    ("retransmit", J::Bool(s.retransmit)),
                    ("partial_overlap", J::Bool(s.partial_overlap)),
                    ("out_of_order", J::Bool(s.out_of_order)),
                    ("checksum_ok", J::Bool(s.checksum_ok)),
                    ("collisions", collisions_json(s)),
                    (
                        "bytes_hex",
                        s.bytes_hex.clone().map(J::Str).unwrap_or(J::Null),
                    ),
                ])
            })
            .collect(),
    )
}

fn collisions_json(s: &DirSegment) -> Value {
    J::Array(
        s.collisions
            .iter()
            .map(|c| {
                J::obj(vec![
                    ("offset", J::Int(c.offset as i64)),
                    ("old_byte", J::Int(c.old_byte as i64)),
                    ("new_byte", J::Int(c.new_byte as i64)),
                    ("old_frame", J::Int(c.old_frame as i64)),
                    ("new_frame", J::Int(c.new_frame as i64)),
                    ("replaced", J::Bool(c.replaced)),
                ])
            })
            .collect(),
    )
}

#[allow(dead_code)]
fn ensure_link_used() -> u32 {
    LINK_ETHERNET
}
