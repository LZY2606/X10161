//! IP 分片重组：按数据报自身边界重组；重叠或超预算的数据报被隔离，
//! 不影响其他数据报与会话。相同时间戳以原始帧序号排序。

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::model::FragInfo;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FragKey {
    src: IpAddr,
    dst: IpAddr,
    id: u32,
    protocol: u8,
    ip_version: u8,
}

#[derive(Clone, Debug)]
struct Piece {
    start: u32,
    end: u32,
    frame: u32,
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
struct FragBuf {
    first_ts_ns: i64,
    bytes: usize,
    pieces: Vec<Piece>,
    last_end: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsolatedDatagram {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ip_version: u8,
    pub ident: u32,
    pub reason: String,
    pub frames: Vec<u32>,
}

pub enum FragResult {
    Pending,
    Complete(Vec<u8>),
    Isolated,
}

pub struct FragReassembler {
    per_datagram_budget: usize,
    total_budget: usize,
    timeout_ns: i64,
    pending: HashMap<FragKey, FragBuf>,
    isolated_keys: HashSet<FragKey>,
    buffered: usize,
    pub isolated: Vec<IsolatedDatagram>,
}

impl FragReassembler {
    pub fn new(per_datagram_budget: usize, total_budget: usize, timeout_ns: i64) -> Self {
        Self {
            per_datagram_budget,
            total_budget,
            timeout_ns,
            pending: HashMap::new(),
            isolated_keys: HashSet::new(),
            buffered: 0,
            isolated: Vec::new(),
        }
    }

    fn isolate(&mut self, key: &FragKey, reason: &str, extra_frame: Option<u32>) {
        let mut frames: Vec<u32> = Vec::new();
        if let Some(buf) = self.pending.remove(key) {
            self.buffered -= buf.bytes;
            frames = buf.pieces.iter().map(|p| p.frame).collect();
        }
        if let Some(f) = extra_frame {
            frames.push(f);
        }
        frames.sort_unstable();
        self.isolated_keys.insert(*key);
        self.isolated.push(IsolatedDatagram {
            src: key.src,
            dst: key.dst,
            ip_version: key.ip_version,
            ident: key.id,
            reason: reason.to_string(),
            frames,
        });
    }

    pub fn feed(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        protocol: u8,
        ip_version: u8,
        info: FragInfo,
        payload: &[u8],
        ts_ns: i64,
        frame: u32,
    ) -> FragResult {
        let key = FragKey {
            src,
            dst,
            id: info.id,
            protocol,
            ip_version,
        };
        if self.isolated_keys.contains(&key) {
            if let Some(rec) = self.isolated.iter_mut().find(|r| {
                r.src == src && r.dst == dst && r.ident == info.id && r.ip_version == ip_version
            }) {
                rec.frames.push(frame);
                rec.frames.sort_unstable();
            }
            return FragResult::Isolated;
        }

        // 超时数据报隔离。
        let expired: Vec<FragKey> = self
            .pending
            .iter()
            .filter(|(_, b)| ts_ns - b.first_ts_ns > self.timeout_ns)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            self.isolate(&k, "timeout", None);
        }

        let end = info.offset_bytes + payload.len() as u32;

        // 重叠检查（不可变借用，避免与 isolate 冲突）。
        let overlaps = self
            .pending
            .get(&key)
            .map(|b| {
                b.pieces
                    .iter()
                    .any(|p| info.offset_bytes < p.end && p.start < end)
            })
            .unwrap_or(false);
        if overlaps {
            self.isolate(&key, "overlap", Some(frame));
            return FragResult::Isolated;
        }

        let cur_bytes = self.pending.get(&key).map(|b| b.bytes).unwrap_or(0);
        if cur_bytes + payload.len() > self.per_datagram_budget
            || self.buffered + payload.len() > self.total_budget
        {
            self.isolate(&key, "budget", Some(frame));
            return FragResult::Isolated;
        }

        let buf = self.pending.entry(key).or_insert_with(|| FragBuf {
            first_ts_ns: ts_ns,
            bytes: 0,
            pieces: Vec::new(),
            last_end: None,
        });
        buf.pieces.push(Piece {
            start: info.offset_bytes,
            end,
            frame,
            data: payload.to_vec(),
        });
        buf.bytes += payload.len();
        self.buffered += payload.len();
        if !info.more {
            buf.last_end = Some(end);
        }

        let complete = {
            let buf = self.pending.get(&key).unwrap();
            buf.last_end.map_or(false, |last| {
                let mut cur = 0u32;
                let mut pieces: Vec<&Piece> = buf.pieces.iter().collect();
                pieces.sort_by_key(|p| (p.start, p.frame));
                for p in pieces {
                    if p.start > cur {
                        return false;
                    }
                    cur = cur.max(p.end);
                }
                cur >= last
            })
        };
        if complete {
            let buf = self.pending.remove(&key).unwrap();
            self.buffered -= buf.bytes;
            let mut pieces = buf.pieces;
            pieces.sort_by_key(|p| (p.start, p.frame));
            let mut out = Vec::new();
            let mut cur = 0u32;
            for p in pieces {
                if p.end > cur {
                    out.extend_from_slice(&p.data[(cur - p.start) as usize..]);
                    cur = p.end;
                }
            }
            return FragResult::Complete(out);
        }
        FragResult::Pending
    }
}
