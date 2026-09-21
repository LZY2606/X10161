//! 分析引擎：帧序列 → 解析 → IP 分片重组 → TCP 会话代次 → 字节流重组 → 证据与指纹。
//! 同一输入 + 同一策略必然产生同一指纹；策略变化产生新分析版本。

use serde::{Deserialize, Serialize};

use crate::fragment::{FragReassembler, FragResult, IsolatedDatagram};
use crate::model::{parse_frame, parse_tcp, Frame, PROTO_TCP};
use crate::session::{
    contiguous_from, coverage_and_gaps, reassemble, unwrap, Endpoint, FlowKey, OverlapPolicy,
    PostClosePacket, SegKind, SessionState, SessionTracker, TcpPacket, UNWRAP_BASE,
};
use crate::util::sha256_hex;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub overlap: OverlapPolicy,
    pub timeout_ns: i64,
    pub frag_per_datagram_budget: usize,
    pub frag_total_budget: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            overlap: OverlapPolicy::FirstSeen,
            timeout_ns: 120_000_000_000, // 120s
            frag_per_datagram_budget: 64 * 1024,
            frag_total_budget: 4 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SegEvidence {
    pub frame: u32,
    pub ts_ns: i64,
    pub seq: u32,
    pub start: i64,
    pub end: i64,
    pub len: usize,
    pub flags: String,
    /// 仅对携带载荷的段分类：normal / retransmit / out_of_order / overlap。
    pub kind: Option<SegKind>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirEvidence {
    pub name: String,
    pub isn: Option<u32>,
    pub base: Option<u32>,
    pub segments: Vec<SegEvidence>,
    pub coverage: Vec<(i64, i64)>,
    pub gaps: Vec<(i64, i64)>,
    pub overwritten: Vec<crate::session::OverwriteRec>,
    pub retransmissions: usize,
    pub out_of_order: usize,
    pub overlaps: usize,
    pub reassembled_len: usize,
    pub reassembled_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionEvidence {
    pub id: usize,
    pub generation: u32,
    pub partial: bool,
    pub state: String,
    pub endpoints: [Endpoint; 2],
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    pub directions: Vec<DirEvidence>,
    pub post_close: Vec<PostClosePacket>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub input_hash: String,
    pub policy: Policy,
    pub sessions: Vec<SessionEvidence>,
    pub isolated_datagrams: Vec<IsolatedDatagram>,
}

#[derive(Clone, Debug)]
pub struct ReassembledOutput {
    pub session: usize,
    pub dir: usize,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Analysis {
    pub evidence: Evidence,
    pub fingerprint: String,
    pub reassembled: Vec<ReassembledOutput>,
}

/// 确定性分析：帧先按 (ts_ns, index) 排序，相同时间戳以原始帧序号为准。
pub fn analyze(frames: &[Frame], input_hash: &str, policy: &Policy) -> Analysis {
    let mut ordered: Vec<&Frame> = frames.iter().collect();
    ordered.sort_by_key(|f| (f.ts_ns, f.index));

    let mut frags = FragReassembler::new(
        policy.frag_per_datagram_budget,
        policy.frag_total_budget,
        policy.timeout_ns,
    );
    let mut tracker = SessionTracker::new(policy.timeout_ns);

    for f in ordered {
        let Some(parsed) = parse_frame(&f.data) else {
            continue;
        };
        let transport = match &parsed.frag {
            Some(info) => match frags.feed(
                parsed.src,
                parsed.dst,
                parsed.protocol,
                parsed.ip_version,
                *info,
                &parsed.transport,
                f.ts_ns,
                f.index,
            ) {
                FragResult::Complete(t) => t,
                _ => continue,
            },
            None => parsed.transport.clone(),
        };
        if parsed.protocol != PROTO_TCP {
            continue;
        }
        let Some(seg) = parse_tcp(&transport) else {
            continue;
        };
        tracker.process(&TcpPacket::from_segment(
            f.ts_ns, f.index, parsed.src, parsed.dst, seg,
        ));
    }

    let mut sessions_ev = Vec::new();
    let mut reassembled = Vec::new();
    for s in &tracker.sessions {
        let mut dirs_ev = Vec::new();
        for (d, dir) in s.dirs.iter().enumerate() {
            let r = reassemble(dir, policy.overlap);
            let base = dir.base.unwrap_or(0);
            let base_pos = unwrap(base, base);
            let bytes = contiguous_from(&r.chunks, base_pos);
            let (coverage, gaps) = coverage_and_gaps(&r.chunks);
            let retransmissions =
                r.events.iter().filter(|e| e.kind == SegKind::Retransmit).count();
            let out_of_order =
                r.events.iter().filter(|e| e.kind == SegKind::OutOfOrder).count();
            let overlaps = r.events.iter().filter(|e| e.kind == SegKind::Overlap).count();
            let segments = dir
                .segments
                .iter()
                .map(|seg| {
                    let start = unwrap(base, seg.seq);
                    let kind = r.events.iter().find(|e| e.frame == seg.frame).map(|e| e.kind);
                    SegEvidence {
                        frame: seg.frame,
                        ts_ns: seg.ts_ns,
                        seq: seg.seq,
                        start,
                        end: start + seg.payload.len() as i64,
                        len: seg.payload.len(),
                        flags: crate::model::flags_str(seg.flags),
                        kind,
                    }
                })
                .collect();
            dirs_ev.push(DirEvidence {
                name: if d == 0 { "a->b" } else { "b->a" }.to_string(),
                isn: dir.isn,
                base: dir.base,
                segments,
                coverage,
                gaps,
                overwritten: r.overwritten,
                retransmissions,
                out_of_order,
                overlaps,
                reassembled_len: bytes.len(),
                reassembled_sha256: sha256_hex(&bytes),
            });
            reassembled.push(ReassembledOutput {
                session: s.id,
                dir: d,
                bytes,
            });
        }
        let state = match s.state {
            SessionState::Open => "open".to_string(),
            SessionState::Closed(r) => format!("closed:{}", r.as_str()),
        };
        sessions_ev.push(SessionEvidence {
            id: s.id,
            generation: s.generation,
            partial: s.partial,
            state,
            endpoints: [s.key.a, s.key.b],
            first_ts_ns: s.first_ts_ns,
            last_ts_ns: s.last_ts_ns,
            directions: dirs_ev,
            post_close: s.post_close.clone(),
        });
    }

    let evidence = Evidence {
        input_hash: input_hash.to_string(),
        policy: policy.clone(),
        sessions: sessions_ev,
        isolated_datagrams: frags.isolated.clone(),
    };
    let fingerprint = sha256_hex(serde_json::to_string(&evidence).unwrap().as_bytes());
    Analysis {
        evidence,
        fingerprint,
        reassembled,
    }
}

/// 输入指纹：仅由帧内容（时间戳、序号、字节）决定。
pub fn input_hash(frames: &[Frame]) -> String {
    let mut canonical = String::new();
    for f in frames {
        canonical.push_str(&format!("{}:{}:{}\n", f.index, f.ts_ns, sha256_hex(&f.data)));
    }
    sha256_hex(canonical.as_bytes())
}

pub const _: () = {
    // 保证 UNWRAP_BASE 语义被使用（防止误删）。
    let _ = UNWRAP_BASE;
};
