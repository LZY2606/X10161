//! IP fragment reassembly. Fragments are reassembled strictly within their
//! own datagram boundaries; any overlap or budget breach isolates (poisons)
//! that datagram without affecting any other session.

use crate::packet::FragKey;
use std::collections::{HashMap, HashSet};

pub const MAX_DATAGRAM_BYTES: usize = 65535;
pub const MAX_FRAGMENTS_PER_DATAGRAM: usize = 64;
pub const MAX_GLOBAL_BUFFER_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolateReason {
    Overlap,
    DatagramTooLarge,
    TooManyFragments,
    GlobalBudget,
    Incomplete,
}

impl IsolateReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            IsolateReason::Overlap => "overlap",
            IsolateReason::DatagramTooLarge => "datagram-too-large",
            IsolateReason::TooManyFragments => "too-many-fragments",
            IsolateReason::GlobalBudget => "global-budget-exceeded",
            IsolateReason::Incomplete => "incomplete-at-end-of-capture",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Isolated {
    pub key: FragKey,
    pub reason: IsolateReason,
    pub frames: Vec<u32>,
    pub received_bytes: usize,
}

#[derive(Default)]
struct FragBuf {
    offsets: Vec<u32>, // absolute byte offset of each piece
    pieces: Vec<(u32, u32)>, // (offset into data, len)
    data: Vec<u8>,
    total: Option<usize>,
    frames: Vec<u32>,
}

#[derive(Default)]
pub struct Defrag {
    bufs: HashMap<FragKey, FragBuf>,
    isolated_keys: HashSet<FragKey>,
    pub isolated: Vec<Isolated>,
    buffered_bytes: usize,
}

impl Defrag {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one fragment. On completion returns the reassembled IP payload.
    pub fn add(&mut self, key: FragKey, offset: u32, more: bool, payload: &[u8], frame: u32) -> Option<Vec<u8>> {
        if self.isolated_keys.contains(&key) {
            return None;
        }
        let end = offset as usize + payload.len();
        if end > MAX_DATAGRAM_BYTES {
            self.isolate(key, IsolateReason::DatagramTooLarge);
            return None;
        }
        if self.buffered_bytes + payload.len() > MAX_GLOBAL_BUFFER_BYTES {
            self.isolate(key, IsolateReason::GlobalBudget);
            return None;
        }
        {
            let buf = self.bufs.entry(key).or_default();
            if buf.pieces.len() >= MAX_FRAGMENTS_PER_DATAGRAM {
                self.isolate(key, IsolateReason::TooManyFragments);
                return None;
            }
            // Strict overlap check against every buffered piece.
            let (s1, e1) = (offset as usize, end);
            for (&o, &(_, l)) in buf.offsets.iter().zip(buf.pieces.iter()) {
                let (s2, e2) = (o as usize, (o + l) as usize);
                if s1 < e2 && s2 < e1 {
                    self.isolate(key, IsolateReason::Overlap);
                    return None;
                }
            }
        }
        let buf = self.bufs.get_mut(&key).unwrap();
        let base = buf.data.len() as u32;
        buf.data.extend_from_slice(payload);
        buf.pieces.push((base, payload.len() as u32));
        buf.offsets.push(offset);
        buf.frames.push(frame);
        self.buffered_bytes += payload.len();
        if !more {
            buf.total = Some(end);
        }
        if let Some(total) = buf.total {
            let mut covered = vec![false; total];
            for (&o, &(_, l)) in buf.offsets.iter().zip(buf.pieces.iter()) {
                for p in o as usize..(o + l) as usize {
                    if p < total {
                        covered[p] = true;
                    }
                }
            }
            if covered.iter().all(|&c| c) {
                let mut out = vec![0u8; total];
                for (&o, &(d, l)) in buf.offsets.iter().zip(buf.pieces.iter()) {
                    out[o as usize..(o + l) as usize]
                        .copy_from_slice(&buf.data[d as usize..(d + l) as usize]);
                }
                self.buffered_bytes -= buf.data.len();
                self.bufs.remove(&key);
                return Some(out);
            }
        }
        None
    }

    fn isolate(&mut self, key: FragKey, reason: IsolateReason) {
        if let Some(buf) = self.bufs.remove(&key) {
            self.buffered_bytes -= buf.data.len();
            self.isolated.push(Isolated {
                key,
                reason,
                frames: buf.frames,
                received_bytes: buf.data.len(),
            });
        } else {
            self.isolated.push(Isolated { key, reason, frames: Vec::new(), received_bytes: 0 });
        }
        self.isolated_keys.insert(key);
    }

    /// End of capture: anything still buffered is incomplete and isolated.
    pub fn finish(&mut self) {
        let keys: Vec<FragKey> = self.bufs.keys().cloned().collect();
        for k in keys {
            self.isolate(k, IsolateReason::Incomplete);
        }
    }
}
