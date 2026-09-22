use crate::parse::Ipv4Packet;
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;

pub const MAX_DATAGRAM_LEN: usize = 65535;
pub const MAX_FRAGMENTS_PER_DATAGRAM: usize = 64;
pub const MAX_BUFFERED_BYTES: usize = 1 << 20;
pub const FRAG_TIMEOUT_MICROS: i64 = 30_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FragKey {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ident: u16,
    protocol: u8,
}

#[derive(Debug, Clone)]
struct FragPiece {
    start: usize,
    end: usize,
    frame_index: u64,
    data: Vec<u8>,
}

#[derive(Debug, Default)]
struct FragDatagram {
    pieces: Vec<FragPiece>,
    total_len: Option<usize>,
    first_ts: i64,
    last_ts: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IsolatedDatagram {
    pub src: String,
    pub dst: String,
    pub ident: u16,
    pub protocol: u8,
    pub reason: String,
    pub fragment_frames: Vec<u64>,
    pub bytes_buffered: usize,
}

#[derive(Debug)]
pub enum FragOutcome {
    /// A complete datagram was reassembled; payload is the full IP payload.
    Completed { payload: Vec<u8>, fragment_frames: Vec<u64> },
    /// Fragment buffered, datagram still incomplete.
    Buffered,
    /// The datagram was isolated (overlap / budget exceeded).
    Isolated(IsolatedDatagram),
}

#[derive(Default)]
pub struct FragReassembler {
    datagrams: HashMap<FragKey, FragDatagram>,
    poisoned: HashMap<FragKey, String>,
    buffered_bytes: usize,
}

impl FragReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Expire datagrams that have been incomplete for too long; they are
    /// isolated without affecting anything else.
    pub fn sweep(&mut self, now_micros: i64) -> Vec<IsolatedDatagram> {
        let mut expired_keys = Vec::new();
        for (key, dg) in &self.datagrams {
            if now_micros - dg.last_ts > FRAG_TIMEOUT_MICROS {
                expired_keys.push(key.clone());
            }
        }
        let mut out = Vec::new();
        for key in expired_keys {
            if let Some(dg) = self.datagrams.remove(&key) {
                out.push(self.isolate(key, dg, "fragment timeout".to_string()));
            }
        }
        out
    }

    /// Flush everything still buffered at end of capture.
    pub fn finish(&mut self) -> Vec<IsolatedDatagram> {
        let keys: Vec<FragKey> = self.datagrams.keys().cloned().collect();
        let mut out = Vec::new();
        for key in keys {
            if let Some(dg) = self.datagrams.remove(&key) {
                out.push(self.isolate(key, dg, "incomplete at end of capture".to_string()));
            }
        }
        out
    }

    fn isolate(&mut self, key: FragKey, dg: FragDatagram, reason: String) -> IsolatedDatagram {
        let bytes: usize = dg.pieces.iter().map(|p| p.data.len()).sum();
        self.buffered_bytes = self.buffered_bytes.saturating_sub(bytes);
        self.poisoned.insert(key.clone(), reason.clone());
        IsolatedDatagram {
            src: key.src.to_string(),
            dst: key.dst.to_string(),
            ident: key.ident,
            protocol: key.protocol,
            reason,
            fragment_frames: dg.pieces.iter().map(|p| p.frame_index).collect(),
            bytes_buffered: bytes,
        }
    }

    pub fn push(&mut self, pkt: &Ipv4Packet, frame_index: u64, ts_micros: i64) -> FragOutcome {
        let key = FragKey {
            src: pkt.src,
            dst: pkt.dst,
            ident: pkt.ident,
            protocol: pkt.protocol,
        };
        if let Some(reason) = self.poisoned.get(&key) {
            return FragOutcome::Isolated(IsolatedDatagram {
                src: key.src.to_string(),
                dst: key.dst.to_string(),
                ident: key.ident,
                protocol: key.protocol,
                reason: format!("datagram already isolated: {}", reason),
                fragment_frames: vec![frame_index],
                bytes_buffered: pkt.payload.len(),
            });
        }
        let start = pkt.frag_offset_bytes as usize;
        let end = start + pkt.payload.len();
        if end > MAX_DATAGRAM_LEN {
            let dg = self.datagrams.remove(&key).unwrap_or_default();
            return FragOutcome::Isolated(self.isolate(
                key,
                dg,
                format!("fragment exceeds {} byte datagram budget", MAX_DATAGRAM_LEN),
            ));
        }
        let mut dg = self.datagrams.remove(&key).unwrap_or(FragDatagram {
            first_ts: ts_micros,
            ..FragDatagram::default()
        });
        dg.last_ts = ts_micros.max(dg.last_ts);
        if dg.first_ts == 0 {
            dg.first_ts = ts_micros;
        }
        // Overlap with any existing piece isolates the whole datagram.
        for piece in &dg.pieces {
            if start < piece.end && end > piece.start {
                return FragOutcome::Isolated(self.isolate(
                    key,
                    dg,
                    format!(
                        "overlapping fragments at byte range {}..{} (frame {})",
                        start, end, frame_index
                    ),
                ));
            }
        }
        if dg.pieces.len() + 1 > MAX_FRAGMENTS_PER_DATAGRAM {
            return FragOutcome::Isolated(self.isolate(
                key,
                dg,
                format!("more than {} fragments", MAX_FRAGMENTS_PER_DATAGRAM),
            ));
        }
        if self.buffered_bytes + pkt.payload.len() > MAX_BUFFERED_BYTES {
            return FragOutcome::Isolated(self.isolate(
                key,
                dg,
                format!("global fragment buffer budget {} exceeded", MAX_BUFFERED_BYTES),
            ));
        }
        if !pkt.more_fragments {
            dg.total_len = Some(end);
        }
        self.buffered_bytes += pkt.payload.len();
        dg.pieces.push(FragPiece {
            start,
            end,
            frame_index,
            data: pkt.payload.clone(),
        });
        // Completeness check.
        if let Some(total) = dg.total_len {
            let mut pieces: Vec<&FragPiece> = dg.pieces.iter().collect();
            pieces.sort_by_key(|p| (p.start, p.frame_index));
            let mut cursor = 0usize;
            let mut complete = true;
            for p in &pieces {
                if p.start > cursor {
                    complete = false;
                    break;
                }
                cursor = cursor.max(p.end);
            }
            if complete && cursor == total {
                let mut payload = vec![0u8; total];
                let mut frames: Vec<u64> = pieces.iter().map(|p| p.frame_index).collect();
                for p in &pieces {
                    payload[p.start..p.end].copy_from_slice(&p.data);
                }
                frames.sort_unstable();
                self.buffered_bytes = self.buffered_bytes.saturating_sub(total);
                self.datagrams.remove(&key);
                return FragOutcome::Completed { payload, fragment_frames: frames };
            }
        }
        self.datagrams.insert(key, dg);
        FragOutcome::Buffered
    }
}
