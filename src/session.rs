//! TCP 会话跟踪与字节流重组。
//!
//! - 连接识别：归一化四元组 + 代次（generation）。SYN、FIN、RST 与超时共同决定代次；
//!   旧连接结束后同一四元组的新 SYN 开启新一代。
//! - 抓包从会话中间开始时建立 partial 会话，不伪造缺失的握手。
//! - 序号按 32 位环绕比较；重叠片段按 first-seen / last-seen 策略裁决，
//!   被覆盖字节保留在证据中。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::model::{TcpSegment, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use crate::util::sha256_hex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

/// 方向无关的四元组键：a <= b。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub a: Endpoint,
    pub b: Endpoint,
}

impl FlowKey {
    pub fn new(x: Endpoint, y: Endpoint) -> Self {
        if x <= y {
            Self { a: x, b: y }
        } else {
            Self { a: y, b: x }
        }
    }
    /// 0 = a->b，1 = b->a。
    pub fn dir_of(&self, src: Endpoint) -> usize {
        if src == self.a {
            0
        } else {
            1
        }
    }
}

#[derive(Clone, Debug)]
pub struct TcpPacket {
    pub ts_ns: i64,
    pub frame: u32,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl TcpPacket {
    pub fn from_segment(
        ts_ns: i64,
        frame: u32,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        seg: TcpSegment,
    ) -> Self {
        Self {
            ts_ns,
            frame,
            src: Endpoint {
                ip: src_ip,
                port: seg.src_port,
            },
            dst: Endpoint {
                ip: dst_ip,
                port: seg.dst_port,
            },
            seq: seg.seq,
            ack: seg.ack,
            flags: seg.flags,
            payload: seg.payload,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub ts_ns: i64,
    pub frame: u32,
    pub seq: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Direction {
    pub syn_seen: bool,
    pub isn: Option<u32>,
    pub fin_seen: bool,
    /// 序号解环绕基准：SYN 会话为 ISN+1，partial 会话为首个观察到的序号。
    pub base: Option<u32>,
    pub segments: Vec<Segment>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseReason {
    Fin,
    Rst,
    Timeout,
    SynRestart,
}

impl CloseReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            CloseReason::Fin => "fin",
            CloseReason::Rst => "rst",
            CloseReason::Timeout => "timeout",
            CloseReason::SynRestart => "syn_restart",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Open,
    Closed(CloseReason),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostClosePacket {
    pub ts_ns: i64,
    pub frame: u32,
    pub dir: usize,
    pub seq: u32,
    pub flags: String,
    pub payload_len: usize,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub id: usize,
    pub key: FlowKey,
    pub generation: u32,
    pub partial: bool,
    pub state: SessionState,
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    pub dirs: [Direction; 2],
    pub post_close: Vec<PostClosePacket>,
}

pub struct SessionTracker {
    pub timeout_ns: i64,
    pub sessions: Vec<Session>,
    active: HashMap<FlowKey, usize>,
    last_closed: HashMap<FlowKey, usize>,
    gen_counter: HashMap<FlowKey, u32>,
}

impl SessionTracker {
    pub fn new(timeout_ns: i64) -> Self {
        Self {
            timeout_ns,
            sessions: Vec::new(),
            active: HashMap::new(),
            last_closed: HashMap::new(),
            gen_counter: HashMap::new(),
        }
    }

    fn new_session(&mut self, key: FlowKey, ts_ns: i64, partial: bool) -> usize {
        let gen = self.gen_counter.entry(key).or_insert(0);
        *gen += 1;
        let generation = *gen;
        let id = self.sessions.len();
        self.sessions.push(Session {
            id,
            key,
            generation,
            partial,
            state: SessionState::Open,
            first_ts_ns: ts_ns,
            last_ts_ns: ts_ns,
            dirs: Default::default(),
            post_close: Vec::new(),
        });
        self.active.insert(key, id);
        id
    }

    fn close_session(&mut self, idx: usize, reason: CloseReason) {
        self.sessions[idx].state = SessionState::Closed(reason);
        let key = self.sessions[idx].key;
        self.active.remove(&key);
        self.last_closed.insert(key, idx);
    }

    pub fn process(&mut self, pkt: &TcpPacket) {
        let key = FlowKey::new(pkt.src, pkt.dst);
        let dir = key.dir_of(pkt.src);
        let is_syn = pkt.flags & TCP_SYN != 0;
        let is_ack = pkt.flags & TCP_ACK != 0;
        let is_rst = pkt.flags & TCP_RST != 0;
        let is_fin = pkt.flags & TCP_FIN != 0;
        let bare_syn = is_syn && !is_ack;

        // 活动会话超时 → 关闭，后续报文开启新一代。
        if let Some(&idx) = self.active.get(&key) {
            if pkt.ts_ns - self.sessions[idx].last_ts_ns > self.timeout_ns {
                self.close_session(idx, CloseReason::Timeout);
            }
        }

        let mut idx_opt = self.active.get(&key).copied();

        if bare_syn {
            if let Some(idx) = idx_opt {
                let s = &self.sessions[idx];
                let same_isn = s.dirs[dir].syn_seen && s.dirs[dir].isn == Some(pkt.seq);
                if !same_isn {
                    // 旧连接尚未显式结束，但出现新 ISN 的 SYN：四元组复用。
                    self.close_session(idx, CloseReason::SynRestart);
                    idx_opt = None;
                }
                // 相同 ISN 的 SYN 视为重传，归属当前代。
            }
            if idx_opt.is_none() {
                idx_opt = Some(self.new_session(key, pkt.ts_ns, false));
            }
        } else if idx_opt.is_none() {
            // 非 SYN 报文：若在超时窗口内存在刚关闭的会话，作为关闭后证据归属之，
            // 否则建立 partial 会话（中途抓取，不伪造握手）。
            let recent = self.last_closed.get(&key).copied().filter(|&ci| {
                pkt.ts_ns - self.sessions[ci].last_ts_ns <= self.timeout_ns
            });
            match recent {
                Some(ci) => {
                    self.sessions[ci].post_close.push(PostClosePacket {
                        ts_ns: pkt.ts_ns,
                        frame: pkt.frame,
                        dir,
                        seq: pkt.seq,
                        flags: crate::model::flags_str(pkt.flags),
                        payload_len: pkt.payload.len(),
                    });
                    return;
                }
                None => {
                    idx_opt = Some(self.new_session(key, pkt.ts_ns, true));
                }
            }
        }

        let idx = idx_opt.unwrap();
        {
            let s = &mut self.sessions[idx];
            s.last_ts_ns = pkt.ts_ns;
            let d = &mut s.dirs[dir];
            if is_syn && !d.syn_seen {
                d.syn_seen = true;
                d.isn = Some(pkt.seq);
            }
            if d.base.is_none() {
                d.base = Some(if is_syn {
                    pkt.seq.wrapping_add(1)
                } else {
                    pkt.seq
                });
            }
            d.segments.push(Segment {
                ts_ns: pkt.ts_ns,
                frame: pkt.frame,
                seq: pkt.seq,
                flags: pkt.flags,
                payload: pkt.payload.clone(),
            });
            if is_fin {
                d.fin_seen = true;
            }
        }
        if is_rst {
            self.close_session(idx, CloseReason::Rst);
        } else if is_fin {
            let both = self.sessions[idx].dirs[0].fin_seen && self.sessions[idx].dirs[1].fin_seen;
            if both {
                self.close_session(idx, CloseReason::Fin);
            }
        }
    }
}

// ---------------- 字节流重组 ----------------

/// 解环绕基准：所有序号映射到以 2^32 为锚点的 i64 空间。
pub const UNWRAP_BASE: i64 = 1 << 32;

pub fn unwrap(base: u32, seq: u32) -> i64 {
    UNWRAP_BASE + (seq.wrapping_sub(base) as i32 as i64)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapPolicy {
    FirstSeen,
    LastSeen,
}

#[derive(Clone, Debug)]
pub struct Chunk {
    pub start: i64,
    pub end: i64,
    pub data: Vec<u8>,
    pub frame: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverwriteRec {
    pub start: i64,
    pub end: i64,
    pub kept_frame: u32,
    pub dropped_frame: u32,
    pub kept_sha256: String,
    pub dropped_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegKind {
    Normal,
    Retransmit,
    OutOfOrder,
    Overlap,
}

#[derive(Clone, Debug)]
pub struct SegEvent {
    pub frame: u32,
    pub ts_ns: i64,
    pub start: i64,
    pub end: i64,
    pub kind: SegKind,
}

#[derive(Clone, Debug, Default)]
pub struct DirReassembly {
    pub chunks: Vec<Chunk>,
    pub events: Vec<SegEvent>,
    pub overwritten: Vec<OverwriteRec>,
}

fn fully_covered(chunks: &[Chunk], s: i64, e: i64) -> bool {
    let mut cur = s;
    for c in chunks {
        if c.end <= cur {
            continue;
        }
        if c.start > cur {
            return false;
        }
        cur = c.end;
        if cur >= e {
            return true;
        }
    }
    cur >= e
}

fn apply_segment(
    chunks: &mut Vec<Chunk>,
    overwritten: &mut Vec<OverwriteRec>,
    s: i64,
    e: i64,
    data: &[u8],
    frame: u32,
    policy: OverlapPolicy,
) {
    match policy {
        OverlapPolicy::FirstSeen => {
            let mut pieces: Vec<(i64, i64)> = vec![(s, e)];
            for c in chunks.iter() {
                let mut next = Vec::new();
                for (ps, pe) in pieces {
                    if c.end <= ps || c.start >= pe {
                        next.push((ps, pe));
                        continue;
                    }
                    if ps < c.start {
                        next.push((ps, c.start));
                    }
                    if c.end < pe {
                        next.push((c.end, pe));
                    }
                    let ds = ps.max(c.start);
                    let de = pe.min(c.end);
                    let new_slice = &data[(ds - s) as usize..(de - s) as usize];
                    let old_slice = &c.data[(ds - c.start) as usize..(de - c.start) as usize];
                    if old_slice != new_slice {
                        overwritten.push(OverwriteRec {
                            start: ds,
                            end: de,
                            kept_frame: c.frame,
                            dropped_frame: frame,
                            kept_sha256: sha256_hex(old_slice),
                            dropped_sha256: sha256_hex(new_slice),
                        });
                    }
                }
                pieces = next;
            }
            for (ps, pe) in pieces {
                chunks.push(Chunk {
                    start: ps,
                    end: pe,
                    data: data[(ps - s) as usize..(pe - s) as usize].to_vec(),
                    frame,
                });
            }
        }
        OverlapPolicy::LastSeen => {
            let mut kept: Vec<Chunk> = Vec::new();
            for c in chunks.drain(..) {
                if c.end <= s || c.start >= e {
                    kept.push(c);
                    continue;
                }
                let ds = c.start.max(s);
                let de = c.end.min(e);
                let old_slice = &c.data[(ds - c.start) as usize..(de - c.start) as usize];
                let new_slice = &data[(ds - s) as usize..(de - s) as usize];
                if old_slice != new_slice {
                    overwritten.push(OverwriteRec {
                        start: ds,
                        end: de,
                        kept_frame: frame,
                        dropped_frame: c.frame,
                        kept_sha256: sha256_hex(new_slice),
                        dropped_sha256: sha256_hex(old_slice),
                    });
                }
                if c.start < ds {
                    kept.push(Chunk {
                        start: c.start,
                        end: ds,
                        data: c.data[..(ds - c.start) as usize].to_vec(),
                        frame: c.frame,
                    });
                }
                if de < c.end {
                    kept.push(Chunk {
                        start: de,
                        end: c.end,
                        data: c.data[(de - c.start) as usize..].to_vec(),
                        frame: c.frame,
                    });
                }
            }
            kept.push(Chunk {
                start: s,
                end: e,
                data: data.to_vec(),
                frame,
            });
            *chunks = kept;
        }
    }
    chunks.sort_by_key(|c| c.start);
}

/// 按到达顺序（调用方已按 (ts, frame) 排序）重组一个方向的有效载荷。
pub fn reassemble(dir: &Direction, policy: OverlapPolicy) -> DirReassembly {
    let base = dir.base.unwrap_or(0);
    let mut out = DirReassembly::default();
    let mut max_end: Option<i64> = None;
    for seg in &dir.segments {
        if seg.payload.is_empty() {
            continue;
        }
        let s = unwrap(base, seg.seq);
        let e = s + seg.payload.len() as i64;
        let kind = if fully_covered(&out.chunks, s, e) {
            SegKind::Retransmit
        } else if out.chunks.iter().any(|c| c.start < e && s < c.end) {
            SegKind::Overlap
        } else if max_end.map_or(false, |m| s < m) {
            SegKind::OutOfOrder
        } else {
            SegKind::Normal
        };
        out.events.push(SegEvent {
            frame: seg.frame,
            ts_ns: seg.ts_ns,
            start: s,
            end: e,
            kind,
        });
        max_end = Some(max_end.map_or(e, |m| m.max(e)));
        apply_segment(
            &mut out.chunks,
            &mut out.overwritten,
            s,
            e,
            &seg.payload,
            seg.frame,
            policy,
        );
    }
    out
}

pub fn coverage_and_gaps(chunks: &[Chunk]) -> (Vec<(i64, i64)>, Vec<(i64, i64)>) {
    let cov: Vec<(i64, i64)> = chunks.iter().map(|c| (c.start, c.end)).collect();
    let mut gaps = Vec::new();
    for w in chunks.windows(2) {
        if w[0].end < w[1].start {
            gaps.push((w[0].end, w[1].start));
        }
    }
    (cov, gaps)
}

/// 从 base 位置开始的连续字节（遇第一个缺口停止）。
pub fn contiguous_from(chunks: &[Chunk], base_pos: i64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cur = base_pos;
    for c in chunks {
        if c.end <= cur {
            continue;
        }
        if c.start > cur {
            break;
        }
        let skip = (cur - c.start) as usize;
        out.extend_from_slice(&c.data[skip..]);
        cur = c.end;
    }
    out
}
