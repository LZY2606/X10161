//! IP-level fragment reassembly.
//!
//! Overlapping fragments (other than exact duplicates) or datagrams exceeding
//! the per-datagram budget are quarantined: the whole datagram is withheld and
//! other fragment groups / sessions are unaffected.

use crate::frame::IpFrame;
use crate::types::Ip;
use serde::Serialize;
use std::collections::BTreeMap;

pub const MAX_DATAGRAM: usize = 65_535;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct FragKey {
    pub src: Ip,
    pub dst: Ip,
    pub protocol: u8,
    pub id: u32,
}

#[derive(Clone, Serialize)]
pub struct Quarantine {
    pub key: String,
    pub reason: String,
    pub fragment_indices: Vec<usize>,
}

#[derive(Clone)]
pub struct Assembled {
    pub key: FragKey,
    pub src: Ip,
    pub dst: Ip,
    pub protocol: u8,
    pub bytes: Vec<u8>,
    pub frame_indices: Vec<usize>,
}

struct Piece {
    offset: usize,
    data: Vec<u8>,
    frame_index: usize,
}

struct Group {
    pieces: Vec<Piece>,
    total: Option<usize>,
    quarantined: bool,
    reason: Option<String>,
}

/// Result of feeding one fragment.
pub enum FragOutcome {
    /// Nothing deliverable yet (awaiting more fragments).
    Pending,
    /// Whole datagram is now available.
    Complete(Assembled),
    /// Datagram is quarantined; no complete datagram will ever be emitted.
    Isolated(Quarantine),
}

#[derive(Default)]
pub struct IpReassembler {
    groups: BTreeMap<FragKey, Group>,
}

fn key_string(k: &FragKey) -> String {
    format!("{} -> {} proto {} id {}", k.src, k.dst, k.protocol, k.id)
}

impl IpReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(
        &mut self,
        frame_index: usize,
        frag: &IpFrame,
    ) -> FragOutcome {
        let (src, dst, protocol, id, offset, more, data) = match frag {
            IpFrame::Fragment {
                src,
                dst,
                protocol,
                frag_id,
                offset,
                more,
                data,
            } => (src.clone(), dst.clone(), *protocol, *frag_id, *offset, *more, data.clone()),
            IpFrame::Complete(_) => panic!("complete datagram must not enter IP reassembly"),
        };
        let key = FragKey { src, dst, protocol, id };
        let end = offset + data.len();
        if end > MAX_DATAGRAM {
            self.groups.remove(&key);
            return FragOutcome::Isolated(Quarantine {
                key: key_string(&key),
                reason: format!("fragment end {end} exceeds budget {MAX_DATAGRAM}"),
                fragment_indices: vec![frame_index],
            });
        }

        let group = self.groups.entry(key.clone()).or_insert_with(|| Group {
            pieces: Vec::new(),
            total: None,
            quarantined: false,
            reason: None,
        });

        if group.quarantined {
            return FragOutcome::Pending;
        }

        // Detect non-exact overlap against existing pieces.
        for p in &group.pieces {
            let p_end = p.offset + p.data.len();
            if offset < p_end && p.offset < end {
                let same_span = p.offset == offset && p.data.len() == data.len() && p.data == data;
                if !same_span {
                    let mut indices: Vec<usize> =
                        group.pieces.iter().map(|x| x.frame_index).collect();
                    indices.push(frame_index);
                    indices.sort_unstable();
                    let reason = format!(
                        "overlapping fragments at offsets {} and {} (differing content/span)",
                        p.offset, offset
                    );
                    self.groups.remove(&key);
                    return FragOutcome::Isolated(Quarantine {
                        key: key_string(&key),
                        reason,
                        fragment_indices: indices,
                    });
                }
                // Exact duplicate: ignore but keep waiting for the rest.
                return FragOutcome::Pending;
            }
        }

        if !more {
            group.total = Some(end);
        }
        group.pieces.push(Piece {
            offset,
            data,
            frame_index,
        });

        // Attempt assembly only once the final fragment is present and coverage
        // is contiguous.
        if let Some(total) = group.total {
            let mut covered = vec![false; total];
            for p in &group.pieces {
                let e = (p.offset + p.data.len()).min(total);
                if p.offset >= total {
                    continue;
                }
                for c in covered.iter_mut().take(e).skip(p.offset) {
                    *c = true;
                }
            }
            if covered.iter().all(|x| *x) {
                let mut buf = vec![0u8; total];
                let mut indices = Vec::new();
                let mut pieces = std::mem::take(&mut group.pieces);
                pieces.sort_by_key(|p| p.offset);
                for p in pieces {
                    indices.push(p.frame_index);
                    let e = (p.offset + p.data.len()).min(total);
                    buf[p.offset..e].copy_from_slice(&p.data[..e - p.offset]);
                }
                indices.sort_unstable();
                self.groups.remove(&key);
                return FragOutcome::Complete(Assembled {
                    key: key.clone(),
                    src: key.src.clone(),
                    dst: key.dst.clone(),
                    protocol: key.protocol,
                    bytes: buf,
                    frame_indices: indices,
                });
            }
        }
        FragOutcome::Pending
    }

    /// Outstanding (never-completed, never-isolated) groups at end of capture.
    pub fn leftovers(&self) -> Vec<String> {
        self.groups.keys().map(key_string).collect()
    }
}
