//! IP fragment reassembly (IPv4 + IPv6 fragment headers).
//!
//! Fragments are reassembled strictly within their own datagram boundaries.
//! Overlapping fragments or budget overruns isolate the offending datagram
//! (it is dropped and recorded as evidence) without affecting other
//! datagrams or sessions.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FragKey {
    pub src: String,
    pub dst: String,
    pub ident: u32,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub struct Frag {
    /// Byte offset of this fragment within the datagram.
    pub offset: usize,
    /// More-fragments flag.
    pub more: bool,
    pub data: Vec<u8>,
    pub frame: u64,
    pub ts: f64,
}

#[derive(Debug, Clone)]
pub struct FragSet {
    pub frags: Vec<Frag>,
    pub first_frame: u64,
    pub last_ts: f64,
}

#[derive(Debug, Clone)]
pub enum FragResult {
    /// Buffered, datagram not yet complete.
    Pending,
    /// Datagram complete: (reassembled payload, protocol).
    Complete(Vec<u8>),
    /// Datagram isolated due to overlap or budget overrun.
    Isolated(String),
}

pub struct FragmentReassembler {
    pending: HashMap<FragKey, FragSet>,
    /// Max bytes buffered across all pending datagrams.
    pub budget_bytes: usize,
    /// Max size of a single reassembled datagram.
    pub max_datagram: usize,
    /// Seconds after which an incomplete datagram is expired.
    pub timeout: f64,
    buffered: usize,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        FragmentReassembler {
            pending: HashMap::new(),
            budget_bytes: 4 * 1024 * 1024,
            max_datagram: 128 * 1024,
            timeout: 30.0,
            buffered: 0,
        }
    }
}

impl FragmentReassembler {
    /// Expire incomplete datagrams older than `timeout` relative to `now`.
    /// Returns (key, reason) evidence for each expired datagram.
    pub fn expire(&mut self, now: f64) -> Vec<(FragKey, String)> {
        let keys: Vec<FragKey> = self
            .pending
            .iter()
            .filter(|(_, s)| now - s.last_ts > self.timeout)
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = Vec::new();
        for k in keys {
            if let Some(s) = self.pending.remove(&k) {
                self.buffered -= s.frags.iter().map(|f| f.data.len()).sum::<usize>();
                out.push((k, "fragment timeout".to_string()));
            }
        }
        out
    }

    pub fn add(&mut self, key: FragKey, frag: Frag) -> FragResult {
        // Budget check (datagram isolation, other sessions unaffected).
        if frag.data.len() + self.buffered > self.budget_bytes
            || frag.offset + frag.data.len() > self.max_datagram
        {
            if let Some(s) = self.pending.remove(&key) {
                self.buffered -= s.frags.iter().map(|f| f.data.len()).sum::<usize>();
            }
            return FragResult::Isolated("fragment budget exceeded".to_string());
        }

        let set = self.pending.entry(key.clone()).or_insert_with(|| FragSet {
            frags: Vec::new(),
            first_frame: frag.frame,
            last_ts: frag.ts,
        });
        set.last_ts = set.last_ts.max(frag.ts);

        // Overlap check against already-buffered fragments of this datagram.
        let new_start = frag.offset;
        let new_end = frag.offset + frag.data.len();
        for f in &set.frags {
            let s = f.offset;
            let e = f.offset + f.data.len();
            if new_start < e && s < new_end {
                // Overlap: isolate the whole datagram.
                let buffered_here: usize = set.frags.iter().map(|f| f.data.len()).sum();
                self.buffered -= buffered_here;
                self.pending.remove(&key);
                return FragResult::Isolated(format!(
                    "overlapping fragments at datagram offset {}..{}",
                    new_start, new_end
                ));
            }
        }

        self.buffered += frag.data.len();
        set.frags.push(frag);

        // Completeness: contiguous from 0 to a known final end.
        let mut end: Option<usize> = None;
        for f in &set.frags {
            if !f.more {
                end = Some(f.offset + f.data.len());
            }
        }
        if let Some(end) = end {
            let mut covered = vec![false; end];
            for f in &set.frags {
                for (i, _) in f.data.iter().enumerate() {
                    if f.offset + i < end {
                        covered[f.offset + i] = true;
                    }
                }
            }
            if covered.iter().all(|&c| c) {
                let mut buf = vec![0u8; end];
                let set = self.pending.remove(&key).unwrap();
                for f in &set.frags {
                    buf[f.offset..f.offset + f.data.len()].copy_from_slice(&f.data);
                }
                self.buffered -= set.frags.iter().map(|f| f.data.len()).sum::<usize>();
                return FragResult::Complete(buf);
            }
        }
        FragResult::Pending
    }
}
