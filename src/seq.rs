//! TCP 32 位序号的环绕比较，以及带“证据来源”的相对字节覆盖空间。

use std::cmp::Ordering;

/// 32 位 TCP 序号，比较按 RFC 1982 串行算术（窗口 2^31）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seq32(pub u32);

impl Seq32 {
    pub fn new(v: u32) -> Self {
        Seq32(v)
    }

    pub fn raw(self) -> u32 {
        self.0
    }

    /// `self < other`，按环绕语义。
    pub fn lt(self, other: Seq32) -> bool {
        self.cmp_wrap(other) == Ordering::Less
    }

    pub fn le(self, other: Seq32) -> bool {
        self == other || self.lt(other)
    }

    pub fn gt(self, other: Seq32) -> bool {
        other.lt(self)
    }

    pub fn ge(self, other: Seq32) -> bool {
        self == other || other.lt(self)
    }

    /// RFC 1982 比较。距离超过 2^31 时认为对方更早（环绕）。
    pub fn cmp_wrap(self, other: Seq32) -> Ordering {
        let diff = other.0.wrapping_sub(self.0);
        if diff == 0 {
            Ordering::Equal
        } else if diff < 0x8000_0000 {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }

    /// 环绕减法：`self - base`，得到相对偏移（0..=2^32-1，以 u64 表示）。
    pub fn offset_from(self, base: Seq32) -> u64 {
        self.0.wrapping_sub(base.0) as u32 as u64
    }

    pub fn add(self, delta: u64) -> Seq32 {
        Seq32(self.0.wrapping_add((delta & 0xffff_ffff) as u32))
    }
}

/// 重叠片段解析策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapPolicy {
    /// 先到的字节保留（BSD-style / first-seen）。
    FirstSeen,
    /// 后到的字节覆盖（Linux-style / last-seen）。
    LastSeen,
}

impl OverlapPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            OverlapPolicy::FirstSeen => "first-seen",
            OverlapPolicy::LastSeen => "last-seen",
        }
    }

    pub fn parse(s: &str) -> Option<OverlapPolicy> {
        match s {
            "first-seen" | "first" => Some(OverlapPolicy::FirstSeen),
            "last-seen" | "last" => Some(OverlapPolicy::LastSeen),
            _ => None,
        }
    }
}

/// 单个被覆盖字节的证据：取值、首先见到的帧、最后写入的帧。
#[derive(Debug, Clone, Copy)]
pub struct Cell {
    pub byte: u8,
    pub first_frame: usize,
    pub last_frame: usize,
}

/// 一次插入中发生的碰撞事件（用于证据 JSON）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collision {
    pub offset: u64,
    pub old_byte: u8,
    pub new_byte: u8,
    pub old_frame: usize,
    pub new_frame: usize,
    /// 是否按当前策略实际改写了字节。
    pub replaced: bool,
}

#[derive(Debug, Clone, Default)]
pub struct InsertReport {
    /// 本次新填充（此前缺失）的相对位置。
    pub new_cells: Vec<u64>,
    /// 与已有字节重叠的位置。
    pub overlap_cells: Vec<u64>,
    /// 具体碰撞事件（仅当新字节与旧字节不同）。
    pub collisions: Vec<Collision>,
}

impl InsertReport {
    pub fn is_pure_retransmit(&self) -> bool {
        self.new_cells.is_empty() && self.collisions.is_empty()
    }
}

/// 相对偏移（u64）空间上的稀疏字节表。
#[derive(Debug, Clone, Default)]
pub struct SeqSpace {
    cells: std::collections::BTreeMap<u64, Cell>,
}

impl SeqSpace {
    pub fn new() -> Self {
        SeqSpace {
            cells: std::collections::BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.cells.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    pub fn contains(&self, off: u64) -> bool {
        self.cells.contains_key(&off)
    }

    pub fn get(&self, off: u64) -> Option<&Cell> {
        self.cells.get(&off)
    }

    pub fn min(&self) -> Option<u64> {
        self.cells.keys().next().copied()
    }

    pub fn max(&self) -> Option<u64> {
        self.cells.keys().next_back().copied()
    }

    /// 插入一段数据。
    pub fn insert(
        &mut self,
        start: u64,
        data: &[u8],
        frame_index: usize,
        policy: OverlapPolicy,
    ) -> InsertReport {
        let mut report = InsertReport::default();
        for (i, &new_byte) in data.iter().enumerate() {
            let off = start + i as u64;
            match self.cells.get_mut(&off) {
                None => {
                    report.new_cells.push(off);
                    self.cells.insert(
                        off,
                        Cell {
                            byte: new_byte,
                            first_frame: frame_index,
                            last_frame: frame_index,
                        },
                    );
                }
                Some(cell) => {
                    report.overlap_cells.push(off);
                    let changed = cell.byte != new_byte;
                    if changed {
                        report.collisions.push(Collision {
                            offset: off,
                            old_byte: cell.byte,
                            new_byte,
                            old_frame: cell.first_frame,
                            new_frame: frame_index,
                            replaced: matches!(policy, OverlapPolicy::LastSeen),
                        });
                    }
                    if changed && matches!(policy, OverlapPolicy::LastSeen) {
                        cell.byte = new_byte;
                    }
                    cell.last_frame = frame_index;
                }
            }
        }
        report
    }

    /// 从 0 开始连续可交付的字节数（头部缺口之前的连续前缀）。
    pub fn contiguous_prefix(&self) -> u64 {
        let mut expect = 0u64;
        for &off in self.cells.keys() {
            if off == expect {
                expect += 1;
            } else if off > expect {
                break;
            }
            // off < expect 不可能出现（键唯一）
        }
        expect
    }

    /// 在已知覆盖范围 [min, max] 内的缺失区间。
    pub fn gaps(&self) -> Vec<(u64, u64)> {
        let mut gaps = Vec::new();
        let mut expect = 0u64;
        for &off in self.cells.keys() {
            if off > expect {
                gaps.push((expect, off));
            }
            expect = expect.max(off + 1);
        }
        gaps
    }

    /// 覆盖到的连续/离散区间列表（用于片段覆盖展示）。
    pub fn covered_runs(&self) -> Vec<(u64, u64)> {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for &off in self.cells.keys() {
            if let Some(last) = runs.last_mut() {
                if off == last.1 {
                    last.1 = off + 1;
                    continue;
                }
            }
            runs.push((off, off + 1));
        }
        runs
    }

    /// 连续前缀字节（最终可确定重组的字节）。
    pub fn prefix_bytes(&self) -> Vec<u8> {
        let n = self.contiguous_prefix();
        let mut out = Vec::with_capacity(n as usize);
        for off in 0..n {
            if let Some(c) = self.cells.get(&off) {
                out.push(c.byte);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_compare() {
        assert!(Seq32(10).lt(Seq32(11)));
        assert!(Seq32(0xffff_ffff).lt(Seq32(1)));
        assert!(Seq32(1).gt(Seq32(0xffff_ffff)));
        assert_eq!(Seq32(5).offset_from(Seq32(0xffff_ffff)), 6);
        assert_eq!(Seq32(0).add(0x1_0000_0000), Seq32(0));
    }

    #[test]
    fn overlap_first_and_last() {
        let mut s = SeqSpace::new();
        s.insert(0, b"AAAA", 1, OverlapPolicy::FirstSeen);
        let r = s.insert(2, b"BB", 2, OverlapPolicy::FirstSeen);
        assert_eq!(r.new_cells.len(), 0);
        assert_eq!(r.collisions.len(), 2);
        assert!(r.collisions.iter().all(|c| !c.replaced));
        assert_eq!(s.prefix_bytes(), b"AAAA");

        let mut s2 = SeqSpace::new();
        s2.insert(0, b"AAAA", 1, OverlapPolicy::LastSeen);
        let r2 = s2.insert(2, b"BB", 2, OverlapPolicy::LastSeen);
        assert!(r2.collisions.iter().all(|c| c.replaced));
        assert_eq!(s2.prefix_bytes(), b"AABB");
    }

    #[test]
    fn gaps_and_prefix() {
        let mut s = SeqSpace::new();
        s.insert(5, b"x", 0, OverlapPolicy::FirstSeen);
        s.insert(0, b"ab", 0, OverlapPolicy::FirstSeen);
        assert_eq!(s.contiguous_prefix(), 2);
        assert_eq!(s.gaps(), vec![(2, 5)]);
    }
}
