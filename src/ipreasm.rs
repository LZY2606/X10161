use std::collections::BTreeMap;

use crate::model::IpPacket;

pub struct FragNote {
    pub reason: &'static str,
    pub frame_idx: usize,
    pub key: String,
}

pub struct IpReassembly {
    pub datagrams: Vec<IpPacket>,
    pub notes: Vec<FragNote>,
}

#[derive(Default)]
struct Bucket {
    src: String,
    dst: String,
    version: u8,
    id: u32,
    proto: u8,
    pieces: Vec<Piece>,
    saw_last: bool,
    total: Option<usize>,
    first_frame: usize,
    last_frame: usize,
    quarantined: bool,
}

#[derive(Clone)]
struct Piece {
    off: usize,
    data: Vec<u8>,
    frame_idx: usize,
}

const BUDGET: usize = 65_535;

pub fn reassemble(packets: Vec<IpPacket>, ts: &[i128]) -> IpReassembly {
    let _ = ts;
    let mut groups: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut datagrams = Vec::new();
    let mut notes = Vec::new();

    for pkt in packets {
        if !pkt.mf && pkt.frag_off == 0 {
            datagrams.push(pkt);
            continue;
        }
        // Both IPv4 and IPv6 fragment offsets are measured from the start of
        // the original transport-layer datagram (the TCP header rides only in
        // the first fragment). Reassemble in that coordinate so the recovered
        // buffer begins with the TCP header and parses directly.
        let l4_off = pkt.frag_off;
        let key = format!(
            "v{}-{}-{}-id{}-p{}",
            pkt.ip_version, pkt.src, pkt.dst, pkt.ip_id, pkt.proto
        );
        let end = l4_off + pkt.l4.len();
        let b = groups.entry(key.clone()).or_insert_with(|| Bucket {
            src: pkt.src.clone(),
            dst: pkt.dst.clone(),
            version: pkt.ip_version,
            id: pkt.ip_id,
            proto: pkt.proto,
            first_frame: pkt.frame_idx,
            ..Default::default()
        });
        b.last_frame = pkt.frame_idx;

        if !pkt.mf {
            b.saw_last = true;
            b.total = Some(end);
        }

        let overlaps = b.pieces.iter().any(|p| {
            let pe = p.off + p.data.len();
            pkt.frag_off < pe && p.off < end
        });
        if overlaps {
            b.quarantined = true;
            notes.push(FragNote {
                reason: "overlapping IP fragments; datagram quarantined",
                frame_idx: pkt.frame_idx,
                key: key.clone(),
            });
        }
        if end > BUDGET || b.total.map(|t| end > t).unwrap_or(false) {
            b.quarantined = true;
            notes.push(FragNote {
                reason: "fragment exceeds budget/declared length; datagram quarantined",
                frame_idx: pkt.frame_idx,
                key: key.clone(),
            });
        }

        b.pieces.push(Piece {
            off: l4_off,
            data: pkt.l4,
            frame_idx: pkt.frame_idx,
        });

        if b.quarantined {
            // Keep collecting so all offending fragments are evidenced,
            // but the datagram is never emitted.
            continue;
        }
        if b.saw_last {
            if let Some(dg) = try_flush(b) {
                datagrams.push(dg);
                groups.remove(&key);
            }
        }
    }

    for (key, b) in groups {
        let reason = if b.quarantined {
            "fragmented datagram quarantined; not delivered to TCP"
        } else {
            "incomplete fragmented datagram (missing tail or gap)"
        };
        notes.push(FragNote {
            reason,
            frame_idx: b.last_frame,
            key,
        });
    }

    datagrams.sort_by_key(|d| d.frame_idx);
    IpReassembly { datagrams, notes }
}

fn try_flush(b: &Bucket) -> Option<IpPacket> {
    let total = b.total?;
    let mut buf = vec![0u8; total];
    let mut cover = vec![false; total];
    let mut head = None;
    for p in &b.pieces {
        if p.off == 0 {
            head = Some(p.frame_idx);
        }
        for (i, x) in p.data.iter().enumerate() {
            let pos = p.off + i;
            if pos >= total || cover[pos] {
                return None;
            }
            cover[pos] = true;
            buf[pos] = *x;
        }
    }
    if cover.iter().any(|c| !*c) {
        return None;
    }
    let tcp = if b.proto == 6 {
        crate::model::parse_tcp_pub(&buf)
    } else {
        None
    };
    Some(IpPacket {
        frame_idx: head.unwrap_or(b.first_frame),
        ip_version: b.version,
        src: b.src.clone(),
        dst: b.dst.clone(),
        ip_id: b.id,
        proto: b.proto,
        frag_off: 0,
        mf: false,
        l4: buf,
        tcp,
    })
}
