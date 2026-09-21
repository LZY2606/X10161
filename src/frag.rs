//! IP 分片按自身边界重组；重叠或超预算的数据报被整体隔离，不影响其他会话。

use crate::wire::{FragmentPiece, IpMeta, IpVersion};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineReason {
    Overlap,
    Oversize,
    TooManyPieces,
    ProtocolMismatch,
    Malformed,
}

impl QuarantineReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            QuarantineReason::Overlap => "overlap",
            QuarantineReason::Oversize => "oversize",
            QuarantineReason::TooManyPieces => "too-many-pieces",
            QuarantineReason::ProtocolMismatch => "protocol-mismatch",
            QuarantineReason::Malformed => "malformed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuarantineEvent {
    pub key: String,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ip_id: u32,
    pub reason: QuarantineReason,
    pub detail: String,
    pub frame_index: usize,
}

#[derive(Debug, Clone)]
pub struct ReassembledDatagram {
    pub ip: IpMeta,
    /// 重组后的传输层（TCP）完整字节，含 TCP 首部。
    pub segment: Vec<u8>,
    pub piece_frames: Vec<usize>,
}

#[derive(Debug, Clone)]
pub enum FragEmit {
    Complete(ReassembledDatagram),
    Quarantined(QuarantineEvent),
    None,
}

#[derive(Clone)]
struct Piece {
    offset: usize,
    data: Vec<u8>,
    frame_index: usize,
    more: bool,
}

#[derive(Default)]
struct Group {
    pieces: Vec<Piece>,
    protocol: u8,
    /// 一旦隔离，保留键以便丢弃后续片。
    quarantined: bool,
    reason: Option<QuarantineReason>,
}

#[derive(Debug, Clone)]
pub struct FragConfig {
    pub max_bytes: usize,
    pub max_pieces: usize,
}

impl Default for FragConfig {
    fn default() -> Self {
        FragConfig {
            max_bytes: 65_535,
            max_pieces: 256,
        }
    }
}

#[derive(Default)]
pub struct FragTable {
    groups: HashMap<String, Group>,
}

impl FragTable {
    pub fn new() -> Self {
        FragTable::default()
    }

    pub fn add(&mut self, piece: FragmentPiece, frame_index: usize, cfg: &FragConfig) -> FragEmit {
        let key = group_key(&piece.ip);
        let FragInfoParts { offset, more } = FragInfoParts {
            offset: piece.ip.fragment.offset as usize,
            more: piece.ip.fragment.more_fragments,
        };
        let protocol = piece.ip.protocol;

        // 偏移必须 8 字节对齐（IPv4）；IPv6 扩展天然 8 对齐，这里统一防御。
        if offset % 8 != 0 {
            return FragEmit::Quarantined(QuarantineEvent {
                detail: format!("分片偏移 {} 不是 8 字节对齐", offset),
                reason: QuarantineReason::Malformed,
                ip_id: piece.ip.id,
                src: piece.ip.src,
                dst: piece.ip.dst,
                frame_index,
                key,
            });
        }

        let group = self
            .groups
            .entry(key.clone())
            .or_insert_with(Group::default);
        if group.quarantined {
            return FragEmit::None;
        }
        if group.pieces.is_empty() {
            group.protocol = protocol;
        } else if group.protocol != protocol {
            group.quarantined = true;
            group.reason = Some(QuarantineReason::ProtocolMismatch);
        } else if group.pieces.len() >= cfg.max_pieces {
            group.quarantined = true;
            group.reason = Some(QuarantineReason::TooManyPieces);
        } else {
            // 重叠检测（任一字节相交即隔离）。
            let end = offset + piece.data.len();
            for p in &group.pieces {
                let p_end = p.offset + p.data.len();
                if offset < p_end && p.offset < end {
                    group.quarantined = true;
                    group.reason = Some(QuarantineReason::Overlap);
                    break;
                }
            }
        }

        if group.quarantined {
            let reason = group.reason.clone().unwrap_or(QuarantineReason::Malformed);
            let detail = match &reason {
                QuarantineReason::Overlap => format!(
                    "帧 {} 的分片 [{},{}) 与已有分片重叠",
                    frame_index,
                    offset,
                    offset + piece.data.len()
                ),
                QuarantineReason::TooManyPieces => format!("分片数超过上限 {}", cfg.max_pieces),
                QuarantineReason::ProtocolMismatch => "分片间协议字段不一致".to_string(),
                _ => "畸形分片".to_string(),
            };
            let ev = QuarantineEvent {
                key,
                src: piece.ip.src,
                dst: piece.ip.dst,
                ip_id: piece.ip.id,
                reason,
                detail,
                frame_index,
            };
            return FragEmit::Quarantined(ev);
        }

        group.pieces.push(Piece {
            offset,
            data: piece.data.clone(),
            frame_index,
            more,
        });

        // 超预算检测。
        let max_end = group
            .pieces
            .iter()
            .map(|p| p.offset + p.data.len())
            .max()
            .unwrap_or(0);
        if max_end > cfg.max_bytes {
            self.groups.remove(&key);
            return FragEmit::Quarantined(QuarantineEvent {
                key,
                src: piece.ip.src,
                dst: piece.ip.dst,
                ip_id: piece.ip.id,
                reason: QuarantineReason::Oversize,
                detail: format!("重组边界 {} 超过预算 {}", max_end, cfg.max_bytes),
                frame_index,
            });
        }

        // 完整性：必须存在 more=false 的末片，且 [0,end) 无缝覆盖。
        let has_last = group.pieces.iter().any(|p| !p.more);
        if !has_last {
            return FragEmit::None;
        }
        let total = group
            .pieces
            .iter()
            .filter(|p| !p.more)
            .map(|p| p.offset + p.data.len())
            .max()
            .unwrap_or(0);

        let mut covered = vec![false; total];
        let mut order: Vec<usize> = group.pieces.iter().map(|p| p.frame_index).collect();
        for p in &group.pieces {
            if p.offset + p.data.len() > total {
                // 末片之外还有越界片：隔离。
                self.groups.remove(&key);
                return FragEmit::Quarantined(QuarantineEvent {
                    key,
                    src: piece.ip.src,
                    dst: piece.ip.dst,
                    ip_id: piece.ip.id,
                    reason: QuarantineReason::Oversize,
                    detail: "分片越过末片边界".to_string(),
                    frame_index,
                });
            }
            for slot in covered.iter_mut().skip(p.offset).take(p.data.len()) {
                *slot = true;
            }
        }
        if covered.iter().all(|x| *x) {
            let mut assembled = vec![0u8; total];
            for p in &group.pieces {
                assembled[p.offset..p.offset + p.data.len()].copy_from_slice(&p.data);
            }
            order.sort_unstable();
            self.groups.remove(&key);
            let mut ip = piece.ip;
            ip.fragment = Default::default();
            return FragEmit::Complete(ReassembledDatagram {
                ip,
                segment: assembled,
                piece_frames: order,
            });
        }
        FragEmit::None
    }

    /// 未完成（末片缺失或仍有缺口）的分组，用于证据展示。
    pub fn incomplete_groups(&self) -> Vec<IncompleteGroup> {
        self.groups
            .values()
            .filter(|g| !g.quarantined)
            .map(|g| IncompleteGroup {
                piece_count: g.pieces.len(),
                frames: g.pieces.iter().map(|p| p.frame_index).collect(),
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct IncompleteGroup {
    pub piece_count: usize,
    pub frames: Vec<usize>,
}

struct FragInfoParts {
    offset: usize,
    more: bool,
}

fn group_key(ip: &IpMeta) -> String {
    // IPv4 用 (src,dst,protocol,id)；IPv6 用 (src,dst,next,id)。
    format!(
        "{}|{}|{}|{}|{}",
        match ip.version {
            IpVersion::V4 => "4",
            IpVersion::V6 => "6",
        },
        ip.src,
        ip.dst,
        ip.protocol,
        ip.id
    )
}
