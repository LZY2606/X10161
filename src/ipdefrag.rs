use crate::packet::FragRef;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct DefragConfig {
    /// Maximum reassembled datagram size in bytes.
    pub max_datagram_bytes: usize,
    /// Maximum number of fragments per datagram.
    pub max_fragments: usize,
    /// Fragments spanning more than this many ns are isolated.
    pub timeout_ns: u64,
}

impl Default for DefragConfig {
    fn default() -> Self {
        Self {
            max_datagram_bytes: 256 * 1024,
            max_fragments: 64,
            timeout_ns: 30_000_000_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FragKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub ident: u32,
}

#[derive(Clone, Debug)]
pub struct OwnedDatagram {
    pub key: FragKey,
    pub payload: Vec<u8>,
    pub frames: Vec<u64>,
}

#[derive(Clone, Debug)]
struct Frag {
    start: usize,
    end: usize,
    frame: u64,
    ts_ns: u64,
    data: Vec<u8>,
}

#[derive(Default)]
struct Datagram {
    frags: Vec<Frag>,
    total: Option<usize>,
    first_ts: u64,
    frames: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DatagramEvidence {
    pub src: String,
    pub dst: String,
    pub proto: u8,
    pub ident: u32,
    pub status: String,
    pub reason: String,
    pub frames: Vec<u64>,
}

pub enum DefragOutcome {
    /// Fragment buffered; datagram not complete yet.
    Buffered,
    /// Datagram reassembled; payload is the transport-layer bytes.
    Complete(OwnedDatagram),
    /// Datagram isolated (overlap / budget / timeout); does not affect sessions.
    Isolated(DatagramEvidence),
}

pub struct Defragmenter {
    cfg: DefragConfig,
    pending: HashMap<FragKey, Datagram>,
    poisoned: HashMap<FragKey, String>,
    pub evidence: Vec<DatagramEvidence>,
}

impl Defragmenter {
    pub fn new(cfg: DefragConfig) -> Self {
        Self {
            cfg,
            pending: HashMap::new(),
            poisoned: HashMap::new(),
            evidence: Vec::new(),
        }
    }

    fn isolate(&mut self, key: &FragKey, reason: &str, frames: Vec<u64>) -> DefragOutcome {
        self.pending.remove(key);
        self.poisoned.insert(key.clone(), reason.to_string());
        let ev = DatagramEvidence {
            src: key.src.to_string(),
            dst: key.dst.to_string(),
            proto: key.proto,
            ident: key.ident,
            status: "isolated".into(),
            reason: reason.to_string(),
            frames,
        };
        self.evidence.push(ev.clone());
        DefragOutcome::Isolated(ev)
    }

    pub fn handle(&mut self, frag: &FragRef<'_>, frame: u64, ts_ns: u64) -> DefragOutcome {
        let key = FragKey {
            src: frag.src,
            dst: frag.dst,
            proto: frag.proto,
            ident: frag.ident,
        };
        if let Some(reason) = self.poisoned.get(&key) {
            let reason = format!("fragment of previously isolated datagram ({reason})");
            let ev = DatagramEvidence {
                src: key.src.to_string(),
                dst: key.dst.to_string(),
                proto: key.proto,
                ident: key.ident,
                status: "isolated".into(),
                reason,
                frames: vec![frame],
            };
            self.evidence.push(ev.clone());
            return DefragOutcome::Isolated(ev);
        }

        let start = frag.offset_bytes;
        let end = start + frag.payload.len();
        if end > self.cfg.max_datagram_bytes {
            return self.isolate(&key, "datagram exceeds byte budget", vec![frame]);
        }

        let dat = self.pending.entry(key.clone()).or_insert(Datagram {
            frags: Vec::new(),
            total: None,
            first_ts: ts_ns,
            frames: Vec::new(),
        });

        if ts_ns.saturating_sub(dat.first_ts) > self.cfg.timeout_ns {
            let mut frames = dat.frames.clone();
            frames.push(frame);
            return self.isolate(&key, "fragment timeout exceeded", frames);
        }

        // Overlap check against already-buffered fragments.
        for f in &dat.frags {
            if start < f.end && f.start < end {
                let mut frames = dat.frames.clone();
                frames.push(frame);
                return self.isolate(&key, "overlapping fragments", frames);
            }
        }

        if dat.frags.len() + 1 > self.cfg.max_fragments {
            let mut frames = dat.frames.clone();
            frames.push(frame);
            return self.isolate(&key, "fragment count exceeds budget", frames);
        }

        if !frag.more_fragments {
            dat.total = Some(end);
        }
        dat.frags.push(Frag {
            start,
            end,
            frame,
            ts_ns,
            data: frag.payload.to_vec(),
        });
        dat.frames.push(frame);

        let complete = match dat.total {
            Some(total) => {
                let mut covered = 0usize;
                let mut frags: Vec<&Frag> = dat.frags.iter().collect();
                frags.sort_by_key(|f| f.start);
                let mut ok = true;
                for f in frags {
                    if f.start > covered {
                        ok = false;
                        break;
                    }
                    covered = covered.max(f.end);
                }
                ok && covered == total
            }
            None => false,
        };

        if !complete {
            return DefragOutcome::Buffered;
        }

        let dat = self.pending.remove(&key).expect("present");
        let total = dat.total.expect("complete implies total");
        let mut payload = vec![0u8; total];
        for f in &dat.frags {
            payload[f.start..f.end].copy_from_slice(&f.data);
        }
        self.evidence.push(DatagramEvidence {
            src: key.src.to_string(),
            dst: key.dst.to_string(),
            proto: key.proto,
            ident: key.ident,
            status: "reassembled".into(),
            reason: String::new(),
            frames: dat.frames.clone(),
        });
        DefragOutcome::Complete(OwnedDatagram {
            key,
            payload,
            frames: dat.frames,
        })
    }

    /// Flush incomplete datagrams at end of capture; they are isolated as evidence.
    pub fn finish(&mut self) {
        let keys: Vec<FragKey> = self.pending.keys().cloned().collect();
        for key in keys {
            let dat = self.pending.remove(&key).expect("present");
            self.evidence.push(DatagramEvidence {
                src: key.src.to_string(),
                dst: key.dst.to_string(),
                proto: key.proto,
                ident: key.ident,
                status: "isolated".into(),
                reason: "incomplete datagram at end of capture".into(),
                frames: dat.frames,
            });
        }
    }
}
