//! IPv4/IPv6 分片重组器。
//!
//! 规则：分片按自身边界重组；一旦发现分片字节区间重叠、分片数量超预算或
//! 数据报尺寸超预算，整个数据报被“隔离”：后续分片只记入证据，不产生任何
//! TCP 包，且隔离只影响该数据报本身。

use std::collections::HashMap;

use crate::parse::FragPiece;

#[derive(Clone, Copy, Debug)]
pub struct FragParams {
    pub max_datagram: usize,
    pub max_fragments: usize,
    pub max_buffered: usize,
}

impl Default for FragParams {
    fn default() -> Self {
        FragParams {
            max_datagram: 65_535,
            max_fragments: 64,
            max_buffered: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FragKey {
    ip_version: u8,
    src: [u8; 16],
    dst: [u8; 16],
    proto: u8,
    ident: u32,
}

#[derive(Clone, Debug)]
pub struct Isolation {
    pub frame_index: u32,
    pub ts_ns: u64,
    pub key: String,
    pub reason: String,
}

struct Piece {
    offset: u32,
    len: u32,
    frame_index: u32,
    data: Vec<u8>,
}

struct Datagram {
    pieces: Vec<Piece>,
    total: Option<u32>,
    isolated: bool,
    isolation_reason: Option<String>,
    first_ts: u64,
    key_desc: String,
}

pub struct FragReassembler {
    params: FragParams,
    buffered: usize,
    dats: HashMap<FragKey, Datagram>,
}

pub enum FragOut {
    Pending,
    Complete(Vec<u8>, FragPieceMeta),
    Isolated(Isolation),
}

#[derive(Clone, Debug)]
pub struct FragPieceMeta {
    pub ip_version: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub proto: u8,
    pub frame_index: u32,
    pub ts_ns: u64,
    pub key: String,
}

impl FragReassembler {
    pub fn new(params: FragParams) -> Self {
        FragReassembler {
            params,
            buffered: 0,
            dats: HashMap::new(),
        }
    }

    fn key_desc(k: &FragKey) -> String {
        format!(
            "v{}/id={}/proto={}/{}->{}",
            k.ip_version,
            k.ident,
            k.proto,
            crate::model::fmt_ip(&k.src),
            crate::model::fmt_ip(&k.dst)
        )
    }

    pub fn add(&mut self, piece: FragPiece) -> FragOut {
        let key = FragKey {
            ip_version: piece.ip_version,
            src: piece.src,
            dst: piece.dst,
            proto: piece.proto,
            ident: piece.ident,
        };
        let end = match piece.offset_bytes.checked_add(piece.data.len() as u32) {
            Some(e) => e,
            None => {
                return self.isolate(
                    &key,
                    piece.frame_index,
                    piece.ts_ns,
                    "fragment offset overflow".into(),
                )
            }
        };
        if end as usize > self.params.max_datagram {
            return self.isolate(
                &key,
                piece.frame_index,
                piece.ts_ns,
                "fragment makes datagram exceed size budget".into(),
            );
        }

        let exists = self.dats.contains_key(&key);
        if !exists {
            self.dats.insert(
                key,
                Datagram {
                    pieces: Vec::new(),
                    total: None,
                    isolated: false,
                    isolation_reason: None,
                    first_ts: piece.ts_ns,
                    key_desc: Self::key_desc(&key),
                },
            );
        }
        {
            let dat = self.dats.get(&key).unwrap();
            if dat.isolated {
                return FragOut::Isolated(Isolation {
                    frame_index: piece.frame_index,
                    ts_ns: piece.ts_ns,
                    key: dat.key_desc.clone(),
                    reason: dat
                        .isolation_reason
                        .clone()
                        .unwrap_or_else(|| "datagram isolated".into()),
                });
            }
            if dat.pieces.len() + 1 > self.params.max_fragments {
                return self.isolate(
                    &key,
                    piece.frame_index,
                    piece.ts_ns,
                    "fragment count budget exceeded".into(),
                );
            }
            if self.buffered + piece.data.len() > self.params.max_buffered {
                return self.isolate(
                    &key,
                    piece.frame_index,
                    piece.ts_ns,
                    "global fragment buffer budget exceeded".into(),
                );
            }
            let collision = dat.pieces.iter().find_map(|existing| {
                let e_end = existing.offset + existing.len;
                if piece.offset_bytes < e_end && existing.offset < end {
                    Some(format!(
                        "overlapping fragments: [{},{}) overlaps [{},{})",
                        piece.offset_bytes, end, existing.offset, e_end
                    ))
                } else {
                    None
                }
            });
            if let Some(reason) = collision {
                return self.isolate(&key, piece.frame_index, piece.ts_ns, reason);
            }
            if !piece.more {
                if let Some(t) = dat.total {
                    if t != end {
                        return self.isolate(
                            &key,
                            piece.frame_index,
                            piece.ts_ns,
                            "inconsistent final fragment length".into(),
                        );
                    }
                }
            }
        }
        {
            let dat = self.dats.get_mut(&key).unwrap();
            if !piece.more && dat.total.is_none() {
                dat.total = Some(end);
            }
        }

        let plen = piece.data.len();
        self.dats.get_mut(&key).unwrap().pieces.push(Piece {
            offset: piece.offset_bytes,
            len: plen as u32,
            frame_index: piece.frame_index,
            data: piece.data,
        });
        self.buffered += plen;

        // 完成检测：total 已知且 [0,total) 被无重叠覆盖。
        let total = match self.dats.get(&key).unwrap().total {
            Some(t) => t,
            None => return FragOut::Pending,
        };
        let covered: u32 = self
            .dats
            .get(&key)
            .unwrap()
            .pieces
            .iter()
            .map(|p| p.len)
            .sum();
        if covered != total {
            return FragOut::Pending;
        }
        let mut ordered: Vec<(u32, u32, u32, Vec<u8>)> = self
            .dats
            .get(&key)
            .unwrap()
            .pieces
            .iter()
            .map(|p| (p.offset, p.len, p.frame_index, p.data.clone()))
            .collect();
        ordered.sort_by_key(|p| p.0);
        let mut cursor = 0u32;
        let mut buf = vec![0u8; total as usize];
        for (off, len, _frame, data) in &ordered {
            if *off != cursor {
                return FragOut::Pending;
            }
            buf[cursor as usize..(cursor + len) as usize].copy_from_slice(data);
            cursor += len;
        }
        if cursor != total {
            return FragOut::Pending;
        }
        let first_frame = ordered.iter().map(|p| p.2).min().unwrap_or(0);
        let (first_ts, key_desc) = {
            let dat = self.dats.get(&key).unwrap();
            (dat.first_ts, dat.key_desc.clone())
        };
        self.dats.remove(&key);
        self.buffered = self.buffered.saturating_sub(total as usize);
        FragOut::Complete(
            buf,
            FragPieceMeta {
                ip_version: key.ip_version,
                src: key.src,
                dst: key.dst,
                proto: key.proto,
                frame_index: first_frame,
                ts_ns: first_ts,
                key: key_desc,
            },
        )
    }

    fn isolate(
        &mut self,
        key: &FragKey,
        frame_index: u32,
        ts_ns: u64,
        reason: String,
    ) -> FragOut {
        if let Some(dat) = self.dats.get_mut(key) {
            dat.isolated = true;
            dat.isolation_reason = Some(reason.clone());
        }
        FragOut::Isolated(Isolation {
            frame_index,
            ts_ns,
            key: Self::key_desc(key),
            reason,
        })
    }
}
