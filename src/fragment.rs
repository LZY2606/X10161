//! IP-level fragment reassembly.
//!
//! Rules (deterministic):
//! * fragments are grouped by (src, dst, id, protocol);
//! * any overlap between fragments, or a reassembled datagram larger than
//!   `max_datagram_bytes`, quarantines that single datagram only;
//! * incomplete groups at end of input are reported as incomplete;
//! * non-fragmented datagrams pass straight through.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::wire::{parse_tcp, Datagram, IpFragment, ParsedFrame};

#[derive(Debug, Clone)]
pub struct FragmentEvent {
    pub kind: String,
    pub src: String,
    pub dst: String,
    pub id: u32,
    pub protocol: u8,
    pub detail: String,
    pub frame_seq: u64,
}

#[derive(Debug, Clone)]
pub struct QuarantinedDatagram {
    pub src: String,
    pub dst: String,
    pub id: u32,
    pub protocol: u8,
    pub reason: String,
    pub total_bytes: usize,
    pub fragments: Vec<u64>,
}

#[derive(Debug, Clone)]
struct Pending {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    id: u32,
    pieces: Vec<(u16, bool, Vec<u8>, u64)>,
    reason: Option<String>,
}

impl Pending {
    fn key(&self) -> String {
        frag_key(self.src, self.dst, self.id, self.protocol)
    }
}

pub fn frag_key(src: IpAddr, dst: IpAddr, id: u32, protocol: u8) -> String {
    format!("{src}|{dst}|{id}|{protocol}")
}

pub struct FragmentReassembler {
    max_datagram_bytes: usize,
    pending: HashMap<String, Pending>,
    pub events: Vec<FragmentEvent>,
    pub quarantined: Vec<QuarantinedDatagram>,
    pub incomplete: Vec<QuarantinedDatagram>,
    pub completed: u64,
}

impl FragmentReassembler {
    pub fn new(max_datagram_bytes: usize) -> Self {
        FragmentReassembler {
            max_datagram_bytes,
            pending: HashMap::new(),
            events: Vec::new(),
            quarantined: Vec::new(),
            incomplete: Vec::new(),
            completed: 0,
        }
    }

    /// Feed a parsed L3 result. Complete datagrams (including unfragmented ones)
    /// are returned immediately; fragmented groups complete later.
    pub fn feed(&mut self, parsed: ParsedFrame) -> Option<Datagram> {
        match parsed {
            ParsedFrame::Datagram(d) => Some(d),
            ParsedFrame::Fragment(mut f) => {
                f.frame_seq = f.frame_seq.max(0);
                self.feed_fragment(f);
                None
            }
            ParsedFrame::Other(_) => None,
        }
    }

    fn feed_fragment(&mut self, f: IpFragment) {
        let key = frag_key(f.src, f.dst, f.id, f.protocol);
        let group = self.pending.entry(key).or_insert_with(|| Pending {
            src: f.src,
            dst: f.dst,
            protocol: f.protocol,
            id: f.id,
            pieces: Vec::new(),
            reason: None,
        });

        // Detect overlap against previously accepted pieces deterministically.
        let start = f.offset as usize;
        let end = start + f.data.len();
        for (off, _, data, _) in &group.pieces {
            let existing_end = *off as usize + data.len();
            if start < existing_end && *off as usize < end {
                group.reason = Some(format!(
                    "overlap: fragment [{},{}) collides with [{},{})",
                    start, end, off, existing_end
                ));
            }
        }
        group.pieces.push((f.offset, f.more_fragments, f.data, f.frame_seq));
    }

    /// Attempt to finalize any group whose last fragment (MF=0) is present and
    /// whose pieces form a gapless, non-overlapping cover starting at zero.
    pub fn try_finish(&mut self) -> Vec<Datagram> {
        let mut out = Vec::new();
        let mut finish_keys = Vec::new();
        for (k, g) in self.pending.iter() {
            if g.reason.is_some() || g.pieces.iter().any(|(_, mf, _, _)| !mf) {
                finish_keys.push(k.clone());
            }
        }
        for key in finish_keys {
            let mut g = self.pending.remove(&key).unwrap();
            // Arrival order must follow original frame numbering.
            g.pieces.sort_by_key(|(_, _, _, seq)| *seq);
            let frame_seqs: Vec<u64> = g.pieces.iter().map(|(_, _, _, s)| *s).collect();

            if let Some(reason) = g.reason.clone() {
                self.events.push(FragmentEvent {
                    kind: "quarantine-overlap".into(),
                    src: g.src.to_string(),
                    dst: g.dst.to_string(),
                    id: g.id,
                    protocol: g.protocol,
                    detail: reason.clone(),
                    frame_seq: *frame_seqs.last().unwrap_or(&0),
                });
                self.quarantined.push(QuarantinedDatagram {
                    src: g.src.to_string(),
                    dst: g.dst.to_string(),
                    id: g.id,
                    protocol: g.protocol,
                    reason,
                    total_bytes: g.pieces.iter().map(|(_, _, d, _)| d.len()).sum(),
                    fragments: frame_seqs,
                });
                continue;
            }

            match assemble(&g, self.max_datagram_bytes) {
                Ok(bytes) => {
                    self.completed += 1;
                    out.push(Datagram {
                        src: g.src,
                        dst: g.dst,
                        next_proto: g.protocol,
                        payload: bytes,
                    });
                }
                Err(reason) => {
                    self.events.push(FragmentEvent {
                        kind: "quarantine-gap-or-budget".into(),
                        src: g.src.to_string(),
                        dst: g.dst.to_string(),
                        id: g.id,
                        protocol: g.protocol,
                        detail: reason.clone(),
                        frame_seq: *frame_seqs.last().unwrap_or(&0),
                    });
                    self.quarantined.push(QuarantinedDatagram {
                        src: g.src.to_string(),
                        dst: g.dst.to_string(),
                        id: g.id,
                        protocol: g.protocol,
                        reason,
                        total_bytes: g.pieces.iter().map(|(_, _, d, _)| d.len()).sum(),
                        fragments: frame_seqs,
                    });
                }
            }
        }
        out
    }

    /// Drain whatever can complete. Groups still missing fragments are reported
    /// as incomplete (and therefore isolated, never partially handed to TCP).
    pub fn flush(mut self) -> Vec<Datagram> {
        let mut out = self.try_finish();
        for (_, g) in self.pending.drain() {
            let frame_seqs: Vec<u64> = g.pieces.iter().map(|(_, _, _, s)| *s).collect();
            let reason = "capture ended before all fragments arrived".to_string();
            self.incomplete.push(QuarantinedDatagram {
                src: g.src.to_string(),
                dst: g.dst.to_string(),
                id: g.id,
                protocol: g.protocol,
                reason,
                total_bytes: g.pieces.iter().map(|(_, _, d, _)| d.len()).sum(),
                fragments: frame_seqs,
            });
        }
        out
    }
}

fn assemble(g: &Pending, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut pieces: Vec<&(u16, bool, Vec<u8>, u64)> = g.pieces.iter().collect();
    pieces.sort_by_key(|(off, _, _, seq)| (*off, *seq));

    let mut buf = Vec::new();
    let mut expect = 0usize;
    for (off, _mf, data, _seq) in pieces {
        let start = *off as usize;
        if start != expect {
            return Err(format!("gap at offset {expect}, next starts at {start}"));
        }
        if data.is_empty() {
            // Empty final fragments carry no bytes; they only terminate.
            continue;
        }
        buf.extend_from_slice(data);
        expect = start + data.len();
        if buf.len() > max_bytes {
            return Err(format!(
                "reassembled datagram exceeds budget ({buf} > {max_bytes} bytes)",
                buf = buf.len(),
                max_bytes = max_bytes
            ));
        }
    }
    Ok(buf)
}

/// Convenience used in tests: extract a single complete TCP segment from a
/// stream of parsed L3 frames.
pub fn datagrams_to_tcp(ds: Vec<Datagram>) -> Vec<crate::wire::TcpSegment> {
    ds.into_iter()
        .filter(|d| d.next_proto == crate::wire::IP_PROTO_TCP)
        .filter_map(|d| parse_tcp(&d).ok())
        .collect()
}
