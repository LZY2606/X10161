//! IP 分片重组：按数据报自身边界重组；重叠或超预算的分片使对应数据报被隔离，
//! 不影响其他数据报与会话。

use crate::packet::NetAddr;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct FragKey {
    pub src: NetAddr,
    pub dst: NetAddr,
    pub proto: u8,
    pub id: u32,
}

impl FragKey {
    pub fn describe(&self) -> String {
        format!(
            "{} -> {} proto={} id={}",
            self.src, self.dst, self.proto, self.id
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuarantineReason {
    OverlappingFragments,
    DatagramTooLarge,
    BudgetExceeded,
}

#[derive(Clone, Debug, Serialize)]
pub struct QuarantineEvent {
    pub frame: u64,
    pub datagram: String,
    pub reason: QuarantineReason,
}

pub enum FragOutcome {
    /// 已缓存，等待更多分片。
    Buffered,
    /// 数据报完整重组，输出其载荷。
    Complete(Vec<u8>),
    /// 分片属于已隔离的数据报，被忽略。
    Ignored,
}

struct FragPart {
    offset: usize,
    data: Vec<u8>,
    more: bool,
}

#[derive(Default)]
struct FragBuf {
    parts: Vec<FragPart>,
    buffered: usize,
}

pub struct Fragmenter {
    /// 单个数据报最大字节数。
    pub max_datagram: usize,
    /// 全部分片缓存的总预算。
    pub budget_bytes: usize,
    dgrams: BTreeMap<FragKey, FragBuf>,
    quarantined: HashSet<FragKey>,
    used: usize,
    pub events: Vec<QuarantineEvent>,
}

impl Fragmenter {
    pub fn new(max_datagram: usize, budget_bytes: usize) -> Self {
        Fragmenter {
            max_datagram,
            budget_bytes,
            dgrams: BTreeMap::new(),
            quarantined: HashSet::new(),
            used: 0,
            events: Vec::new(),
        }
    }

    fn quarantine(&mut self, key: &FragKey, frame: u64, reason: QuarantineReason) {
        if let Some(buf) = self.dgrams.remove(key) {
            self.used = self.used.saturating_sub(buf.buffered);
        }
        self.quarantined.insert(key.clone());
        self.events.push(QuarantineEvent {
            frame,
            datagram: key.describe(),
            reason,
        });
    }

    /// 处理一个分片。`offset`/`len` 以字节计。
    pub fn process(
        &mut self,
        key: FragKey,
        offset: usize,
        more: bool,
        data: &[u8],
        frame: u64,
    ) -> FragOutcome {
        if self.quarantined.contains(&key) {
            return FragOutcome::Ignored;
        }
        let end = offset.saturating_add(data.len());
        if end > self.max_datagram {
            self.quarantine(&key, frame, QuarantineReason::DatagramTooLarge);
            return FragOutcome::Ignored;
        }
        if self.used + data.len() > self.budget_bytes {
            self.quarantine(&key, frame, QuarantineReason::BudgetExceeded);
            return FragOutcome::Ignored;
        }
        let buf = self.dgrams.entry(key.clone()).or_default();
        // 重叠检查：新分片与任何已缓存分片的字节区间相交即隔离整个数据报。
        for part in &buf.parts {
            let p_end = part.offset + part.data.len();
            if offset < p_end && end > part.offset {
                self.quarantine(&key, frame, QuarantineReason::OverlappingFragments);
                return FragOutcome::Ignored;
            }
        }
        buf.buffered += data.len();
        self.used += data.len();
        buf.parts.push(FragPart {
            offset,
            data: data.to_vec(),
            more,
        });
        // 完整性检查：存在末片（more=false），且 [0, total) 被连续覆盖。
        let buf = self.dgrams.get(&key).unwrap();
        let total = buf
            .parts
            .iter()
            .find(|p| !p.more)
            .map(|p| p.offset + p.data.len());
        if let Some(total) = total {
            let mut parts: Vec<&FragPart> = buf.parts.iter().collect();
            parts.sort_by_key(|p| p.offset);
            let mut cursor = 0usize;
            let mut complete = true;
            for p in &parts {
                if p.offset > cursor {
                    complete = false;
                    break;
                }
                cursor = cursor.max(p.offset + p.data.len());
            }
            if complete && cursor >= total {
                let mut out = Vec::with_capacity(total);
                let mut cursor = 0usize;
                for p in parts {
                    if p.offset + p.data.len() <= cursor {
                        continue;
                    }
                    let start = cursor.saturating_sub(p.offset);
                    out.extend_from_slice(&p.data[start..]);
                    cursor = p.offset + p.data.len();
                }
                out.truncate(total);
                let buf = self.dgrams.remove(&key).unwrap();
                self.used = self.used.saturating_sub(buf.buffered);
                return FragOutcome::Complete(out);
            }
        }
        FragOutcome::Buffered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: u32) -> FragKey {
        FragKey {
            src: NetAddr::V4([1, 1, 1, 1]),
            dst: NetAddr::V4([2, 2, 2, 2]),
            proto: 6,
            id,
        }
    }

    #[test]
    fn reassemble_in_order() {
        let mut f = Fragmenter::new(65535, 1 << 20);
        assert!(matches!(
            f.process(key(1), 0, true, b"aaaaaaaa", 0),
            FragOutcome::Buffered
        ));
        match f.process(key(1), 8, false, b"bbbb", 1) {
            FragOutcome::Complete(d) => assert_eq!(d, b"aaaaaaaabbbb"),
            _ => panic!("expected complete"),
        }
    }

    #[test]
    fn overlap_quarantines_only_that_datagram() {
        let mut f = Fragmenter::new(65535, 1 << 20);
        assert!(matches!(
            f.process(key(1), 0, true, b"aaaaaaaa", 0),
            FragOutcome::Buffered
        ));
        assert!(matches!(
            f.process(key(1), 4, false, b"XXXX", 1),
            FragOutcome::Ignored
        ));
        assert_eq!(f.events.len(), 1);
        assert!(matches!(
            f.process(key(1), 8, false, b"zz", 2),
            FragOutcome::Ignored
        ));
        assert!(matches!(
            f.process(key(2), 0, false, b"ok", 3),
            FragOutcome::Complete(_)
        ));
    }

    #[test]
    fn budget_quarantine() {
        let mut f = Fragmenter::new(65535, 10);
        assert!(matches!(
            f.process(key(1), 0, true, b"aaaaaaaa", 0),
            FragOutcome::Buffered
        ));
        assert!(matches!(
            f.process(key(2), 0, true, b"bbbbbbbb", 1),
            FragOutcome::Ignored
        ));
        assert_eq!(f.events[0].reason, QuarantineReason::BudgetExceeded);
    }
}
