//! IP fragment reassembly. Overlapping or over-budget fragments quarantine
//! only their own datagram; every other datagram/session is unaffected.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FragKey {
    pub src: String,
    pub dst: String,
    pub ident: u32,
    pub ip_version: u8,
}

#[derive(Clone, Debug, Serialize)]
pub struct DefragEvent {
    pub kind: String, // "completed" | "quarantine" | "incomplete"
    pub reason: Option<String>,
    pub src: String,
    pub dst: String,
    pub ip_version: u8,
    pub ident: u32,
    pub frames: Vec<u64>,
    pub bytes: usize,
}

pub enum DefragOutcome {
    /// Datagram completed; payload is the reassembled IP payload.
    Completed(Vec<u8>),
    /// Fragment buffered, datagram not yet complete.
    Buffered,
    /// Datagram quarantined (overlap / budget). It is poisoned from now on.
    Quarantined,
    /// Key was already quarantined; fragment dropped silently.
    Poisoned,
}

struct Datagram {
    pieces: BTreeMap<u32, Vec<u8>>, // offset_bytes -> data
    total: Option<u32>,             // known once the !more fragment arrives
    frames: Vec<u64>,
    bytes: usize,
}

pub struct Defragmenter {
    max_datagram_bytes: usize,
    max_datagrams: usize,
    pending: HashMap<FragKey, Datagram>,
    poisoned: HashSet<FragKey>,
    pub events: Vec<DefragEvent>,
}

impl Defragmenter {
    pub fn new(max_datagram_bytes: usize, max_datagrams: usize) -> Self {
        Defragmenter {
            max_datagram_bytes,
            max_datagrams,
            pending: HashMap::new(),
            poisoned: HashSet::new(),
            events: Vec::new(),
        }
    }

    fn event(&mut self, kind: &str, reason: Option<String>, key: &FragKey, frames: Vec<u64>, bytes: usize) {
        self.events.push(DefragEvent {
            kind: kind.to_string(),
            reason,
            src: key.src.clone(),
            dst: key.dst.clone(),
            ip_version: key.ip_version,
            ident: key.ident,
            frames,
            bytes,
        });
    }

    fn quarantine(&mut self, key: &FragKey, reason: &str) {
        let (frames, bytes) = match self.pending.remove(key) {
            Some(dg) => (dg.frames, dg.bytes),
            None => (Vec::new(), 0),
        };
        self.poisoned.insert(key.clone());
        self.event("quarantine", Some(reason.to_string()), key, frames, bytes);
    }

    pub fn add_fragment(
        &mut self,
        key: FragKey,
        offset_bytes: u32,
        more: bool,
        data: &[u8],
        frame_index: u64,
    ) -> DefragOutcome {
        if self.poisoned.contains(&key) {
            return DefragOutcome::Poisoned;
        }
        if !self.pending.contains_key(&key) {
            if self.pending.len() >= self.max_datagrams {
                self.quarantine(&key, "datagram count budget exceeded");
                return DefragOutcome::Quarantined;
            }
            self.pending.insert(
                key.clone(),
                Datagram { pieces: BTreeMap::new(), total: None, frames: Vec::new(), bytes: 0 },
            );
        }
        // Overlap check against existing pieces: any intersection quarantines
        // this datagram only.
        let start = offset_bytes;
        let end = offset_bytes.saturating_add(data.len() as u32);
        {
            let dg = self.pending.get(&key).unwrap();
            for (&ps, pdata) in dg.pieces.iter() {
                let pe = ps + pdata.len() as u32;
                if start < pe && ps < end {
                    self.quarantine(&key, "overlapping fragments");
                    return DefragOutcome::Quarantined;
                }
            }
        }
        let dg = self.pending.get_mut(&key).unwrap();
        dg.frames.push(frame_index);
        dg.bytes += data.len();
        if !more {
            dg.total = Some(end);
        }
        if dg.bytes > self.max_datagram_bytes || dg.total.map_or(false, |t| t as usize > self.max_datagram_bytes) {
            self.quarantine(&key, "datagram byte budget exceeded");
            return DefragOutcome::Quarantined;
        }
        dg.pieces.insert(start, data.to_vec());

        let dg = self.pending.get(&key).unwrap();
        if let Some(total) = dg.total {
            // complete coverage of [0, total)?
            let mut cursor = 0u32;
            let mut complete = true;
            for (&ps, pdata) in dg.pieces.iter() {
                if ps > cursor {
                    complete = false;
                    break;
                }
                cursor = cursor.max(ps + pdata.len() as u32);
            }
            if complete && cursor >= total {
                let dg = self.pending.remove(&key).unwrap();
                let mut out = Vec::with_capacity(total as usize);
                for (_, pdata) in dg.pieces.iter() {
                    out.extend_from_slice(pdata);
                }
                out.truncate(total as usize);
                let bytes = out.len();
                self.event("completed", None, &key, dg.frames.clone(), bytes);
                return DefragOutcome::Completed(out);
            }
        }
        DefragOutcome::Buffered
    }

    /// Drain still-incomplete datagrams as evidence events.
    pub fn finish(&mut self) {
        let keys: Vec<FragKey> = self.pending.keys().cloned().collect();
        for key in keys {
            let dg = self.pending.remove(&key).unwrap();
            self.event("incomplete", Some("capture ended before reassembly".into()), &key, dg.frames, dg.bytes);
        }
    }
}
