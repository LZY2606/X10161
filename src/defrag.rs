//! IP 分片先按数据报自身边界重组。
//!
//! 重叠分片（RFC 1858 类异常）或总长度超过预算的数据报被整体隔离，
//! 隔离仅作用于该数据报，不影响其他会话与数据报。

use std::collections::HashMap;

use crate::model::{Datagram, Frame, L4, ParseNote, Quarantine};
use crate::parse::{parse_tcp, IpFragment, ParsedFrame};

struct FragGroup {
    version: u8,
    proto: u8,
    buf: Vec<u8>,
    occupied: Vec<u8>,
    total: usize,
    have_final: bool,
    frame_nos: Vec<u64>,
    ts_ns: i64,
    first_frame_no: u64,
}

impl FragGroup {
    fn new(frag: &IpFragment, frame: &Frame) -> Self {
        FragGroup {
            version: frag.version,
            proto: frag.proto,
            buf: Vec::new(),
            occupied: Vec::new(),
            total: usize::MAX,
            have_final: false,
            frame_nos: vec![frame.frame_no],
            ts_ns: frame.ts_ns,
            first_frame_no: frame.frame_no,
        }
    }

    /// 放入一个片段；返回 Err((reason, observed_len)) 即触发隔离。
    fn insert(&mut self, frag: &IpFragment, frame_no: u64, budget: usize) -> Result<(), (String, usize)> {
        let start = frag.frag_offset;
        let end = start + frag.l4_bytes.len();
        if end > budget {
            return Err(("分片超出数据报长度预算".to_string(), end));
        }
        if end > self.buf.len() {
            self.buf.resize(end, 0);
            self.occupied.resize(end, 0);
        }
        for (i, b) in frag.l4_bytes.iter().enumerate() {
            let pos = start + i;
            if self.occupied[pos] == 1 {
                return Err(("重叠 IP 分片（字节区间与既有片段相交）".to_string(), self.total.saturating_add(i)));
            }
            self.occupied[pos] = 1;
            self.buf[pos] = *b;
        }
        if !frag.mf {
            self.have_final = true;
            self.total = end;
        }
        if !self.frame_nos.contains(&frame_no) {
            self.frame_nos.push(frame_no);
        }
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.have_final && self.occupied.len() >= self.total && self.occupied[..self.total].iter().all(|b| *b == 1)
    }
}

fn frag_key(version: u8, src: std::net::IpAddr, dst: std::net::IpAddr, proto: u8, ident: u32) -> String {
    format!("v{}-{}-{}-p{}-id{}", version, src, dst, proto, ident)
}

pub struct DefragOutput {
    pub datagrams: Vec<Datagram>,
    pub quarantined: Vec<Quarantine>,
}

/// 按帧序处理：单包直通；分片组在完成或异常时出结论。
pub fn defragment(
    frames: &[Frame],
    parsed: &[(Frame, Option<ParsedFrame>)],
    budget: usize,
    notes: &mut Vec<ParseNote>,
) -> DefragOutput {
    let mut groups: HashMap<String, FragGroup> = HashMap::new();
    let mut datagrams = Vec::new();
    let mut quarantined = Vec::new();
    let mut dead: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (frame, maybe) in parsed {
        let parsed_frame = match maybe {
            Some(pf) => pf,
            None => continue,
        };
        match parsed_frame {
            ParsedFrame::Single(dg) => datagrams.push(dg.clone()),
            ParsedFrame::Fragment(frag) => {
                let key = frag_key(frag.version, frag.src, frag.dst, frag.proto, frag.ident);
                if dead.contains(&key) {
                    continue;
                }
                if !groups.contains_key(&key) {
                    groups.insert(key.clone(), FragGroup::new(frag, frame));
                }
                let group = groups.get_mut(&key).unwrap();
                if let Err((reason, observed)) = group.insert(frag, frame.frame_no, budget) {
                    let mut g = groups.remove(&key).unwrap();
                    g.frame_nos.sort_unstable();
                    quarantined.push(Quarantine {
                        key: key.clone(),
                        reason,
                        frame_nos: g.frame_nos,
                        ts_ns: frame.ts_ns,
                        observed_len: observed.max(g.buf.len()),
                        budget,
                    });
                    dead.insert(key);
                    continue;
                }
                if group.is_complete() {
                    let g = groups.remove(&key).unwrap();
                    let l4 = if g.proto == 6 {
                        match parse_tcp(&g.buf[..g.total]) {
                            Ok(seg) => L4::Tcp(seg),
                            Err(e) => {
                                notes.push(ParseNote {
                                    frame_no: g.first_frame_no,
                                    stage: "tcp".into(),
                                    level: "error".into(),
                                    message: e,
                                });
                                continue;
                            }
                        }
                    } else {
                        L4::Other(g.proto)
                    };
                    datagrams.push(Datagram {
                        first_frame_no: g.first_frame_no,
                        frame_nos: g.frame_nos,
                        ts_ns: frame.ts_ns,
                        version: g.version,
                        src: frag.src,
                        dst: frag.dst,
                        proto: g.proto,
                        l4,
                        fragmented: true,
                    });
                }
            }
        }
    }

    // 抓包结束时仍未集齐的分片组隔离，不伪造数据报。
    let mut leftover: Vec<(String, FragGroup)> = groups.into_iter().collect();
    leftover.sort_by(|a, b| a.1.first_frame_no.cmp(&b.1.first_frame_no));
    for (key, mut g) in leftover {
        g.frame_nos.sort_unstable();
        quarantined.push(Quarantine {
            key,
            reason: "分片集不完整（抓包结束仍有缺口或未见末片）".into(),
            frame_nos: g.frame_nos,
            ts_ns: 0,
            observed_len: g.buf.len(),
            budget,
        });
    }

    datagrams.sort_by(|a, b| a.ts_ns.cmp(&b.ts_ns).then(a.first_frame_no.cmp(&b.first_frame_no)));
    quarantined.sort_by(|a, b| a.ts_ns.cmp(&b.ts_ns).then(a.frame_nos.first().cmp(&b.frame_nos.first())));
    DefragOutput { datagrams, quarantined }
}
