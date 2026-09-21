//! End-to-end deterministic analysis of an ordered frame fixture.

use crate::frame::{parse_frame, parse_tcp, IpFrame, ParsedKind, TcpSegment};
use crate::ipfrag::{FragOutcome, IpReassembler};
use crate::reasm::OverlapPolicy;
use crate::session::{SessionManager, SessionReport};
use crate::types::{Endpoint, Ip, LinkKind, RawFrame};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisConfig {
    #[serde(default)]
    pub overlap_policy: OverlapPolicy,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: f64,
}

fn default_timeout() -> f64 {
    120.0
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        AnalysisConfig {
            overlap_policy: OverlapPolicy::default(),
            timeout_seconds: default_timeout(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrameReport {
    pub index: usize,
    pub timestamp: f64,
    pub link: LinkKind,
    pub bytes_sha256: String,
    pub bytes_len: usize,
    pub role: String,
    pub detail: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub seq: Option<u32>,
    pub ack: Option<u32>,
    pub flags: Option<String>,
    pub data_len: Option<usize>,
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpQuarantineReport {
    pub key: String,
    pub reason: String,
    pub fragment_indices: Vec<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub schema: String,
    pub frame_count: usize,
    pub config: AnalysisConfig,
    pub frames: Vec<FrameReport>,
    pub sessions: Vec<SessionReport>,
    pub quarantined_datagrams: Vec<IpQuarantineReport>,
    pub incomplete_fragment_groups: Vec<String>,
    pub fingerprint_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FingerprintEnvelope {
    schema: String,
    frame_count: usize,
    config: AnalysisConfig,
    frames: Vec<FrameReport>,
    sessions: Vec<SessionReport>,
    quarantined_datagrams: Vec<IpQuarantineReport>,
    incomplete_fragment_groups: Vec<String>,
}

impl FingerprintEnvelope {
    fn from_result(result: &AnalysisResult) -> Self {
        FingerprintEnvelope {
            schema: result.schema.clone(),
            frame_count: result.frame_count,
            config: result.config.clone(),
            frames: result.frames.clone(),
            sessions: result.sessions.clone(),
            quarantined_datagrams: result.quarantined_datagrams.clone(),
            incomplete_fragment_groups: result.incomplete_fragment_groups.clone(),
        }
    }

    pub fn fingerprint(result: &AnalysisResult) -> String {
        let env = FingerprintEnvelope::from_result(result);
        crate::hash::sha256_hex(canonical_json(&env).as_bytes())
    }

    pub fn verify(result: &AnalysisResult) -> bool {
        FingerprintEnvelope::fingerprint(result) == result.fingerprint_sha256
    }
}

struct Ordered {
    order: usize,
    frame: RawFrame,
    bytes: Vec<u8>,
}

/// Normalize incoming frames: assign missing indices and establish the total
/// order as (timestamp, original frame index).
fn order_frames(frames: Vec<RawFrame>) -> Vec<Ordered> {
    let mut indexed: Vec<Ordered> = frames
        .into_iter()
        .enumerate()
        .map(|(i, f)| {
            let assigned = f.index.unwrap_or(i);
            let bytes = crate::types::decode_hex(&f.bytes_hex).unwrap_or_default();
            Ordered {
                order: assigned,
                frame: RawFrame {
                    index: Some(assigned),
                    ..f
                },
                bytes,
            }
        })
        .collect();
    indexed.sort_by(|a, b| {
        a.frame
            .timestamp
            .partial_cmp(&b.frame.timestamp)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.order.cmp(&b.order))
    });
    indexed
}

pub fn analyze(frames: Vec<RawFrame>, config: AnalysisConfig) -> AnalysisResult {
    let ordered = order_frames(frames);
    let mut ip = IpReassembler::new();
    let mut sessions = SessionManager::new(config.overlap_policy, config.timeout_seconds);
    let mut reports: Vec<FrameReport> = Vec::new();
    let mut quarantines = Vec::new();

    for item in &ordered {
        let frame_index = item.frame.index.unwrap();
        let ts = item.frame.timestamp;
        let link = item.frame.link;
        let digest = crate::hash::sha256_hex(&item.bytes);
        let mut report = FrameReport {
            index: frame_index,
            timestamp: ts,
            link,
            bytes_sha256: digest,
            bytes_len: item.bytes.len(),
            role: "ignored".to_string(),
            detail: None,
            src: None,
            dst: None,
            seq: None,
            ack: None,
            flags: None,
            data_len: None,
            comment: item.frame.comment.clone(),
        };

        let parsed = parse_frame(&item.bytes, link);
        match parsed {
            Err(err) => {
                report.role = "parse_error".to_string();
                report.detail = Some(err);
            }
            Ok(pf) => match pf.kind {
                ParsedKind::Ignored(why) => {
                    report.role = "ignored".to_string();
                    report.detail = Some(why);
                }
                ParsedKind::NonTcp(why) => {
                    report.role = "non_tcp".to_string();
                    report.detail = Some(why);
                }
                ParsedKind::Ip(IpFrame::Complete(info)) => {
                    fill_endpoints(&mut report, &info.src, &info.dst);
                    if info.protocol == 6 {
                        match parse_tcp(&info.payload) {
                            Ok(seg) => {
                                fill_tcp(&mut report, &seg);
                                sessions.feed(
                                    frame_index,
                                    ts,
                                    Endpoint::new(info.src.clone(), seg.src_port),
                                    Endpoint::new(info.dst.clone(), seg.dst_port),
                                    &seg,
                                );
                            }
                            Err(err) => {
                                report.role = "parse_error".to_string();
                                report.detail = Some(err);
                            }
                        }
                    } else {
                        report.role = "non_tcp".to_string();
                        report.detail = Some(format!("IP protocol {}", info.protocol));
                    }
                }
                ParsedKind::Ip(frag @ IpFrame::Fragment { .. }) => {
                    if let IpFrame::Fragment { src, dst, protocol, .. } = &frag {
                        fill_endpoints(&mut report, src, dst);
                        report.detail = Some(format!("IP fragment (protocol {protocol})"));
                    }
                    report.role = "ip_fragment".to_string();
                    match ip.add(frame_index, &frag) {
                        FragOutcome::Pending => {}
                        FragOutcome::Isolated(q) => {
                            quarantines.push(IpQuarantineReport {
                                key: q.key,
                                reason: q.reason,
                                fragment_indices: q.fragment_indices,
                            });
                        }
                        FragOutcome::Complete(assembled) => {
                            if assembled.protocol == 6 {
                                match parse_tcp(&assembled.bytes) {
                                    Ok(seg) => {
                                        let src = Endpoint::new(assembled.src, seg.src_port);
                                        let dst = Endpoint::new(assembled.dst, seg.dst_port);
                                        sessions.feed(frame_index, ts, src, dst, &seg);
                                        report.role = "ip_fragment_reassembled_tcp".to_string();
                                        report.detail = Some(format!(
                                            "reassembled from frames {:?}",
                                            assembled.frame_indices
                                        ));
                                    }
                                    Err(err) => {
                                        report.role = "parse_error".to_string();
                                        report.detail = Some(err);
                                    }
                                }
                            } else {
                                report.role = "ip_fragment_reassembled_non_tcp".to_string();
                            }
                        }
                    }
                }
            },
        }
        reports.push(report);
    }

    // Restore presentation order = analysis order (already sorted).
    let incomplete = ip.leftovers();
    let session_reports = sessions.finish();

    let fingerprint = {
        let provisional = AnalysisResult {
            schema: "reasm-bench/analysis/v1".to_string(),
            frame_count: ordered.len(),
            config: config.clone(),
            frames: reports.clone(),
            sessions: session_reports.clone(),
            quarantined_datagrams: quarantines.clone(),
            incomplete_fragment_groups: incomplete.clone(),
            fingerprint_sha256: String::new(),
        };
        FingerprintEnvelope::fingerprint(&provisional)
    };

    AnalysisResult {
        schema: "reasm-bench/analysis/v1".to_string(),
        frame_count: ordered.len(),
        config,
        frames: reports,
        sessions: session_reports,
        quarantined_datagrams: quarantines,
        incomplete_fragment_groups: incomplete,
        fingerprint_sha256: fingerprint,
    }
}

fn fill_endpoints(report: &mut FrameReport, src: &Ip, dst: &Ip) {
    report.src = Some(src.to_string());
    report.dst = Some(dst.to_string());
}

fn fill_tcp(report: &mut FrameReport, seg: &TcpSegment) {
    report.role = "tcp".to_string();
    report.seq = Some(seg.seq);
    report.ack = Some(seg.ack);
    let mut flags = String::new();
    if seg.syn() { flags.push('S'); }
    if seg.ack_flag() { flags.push('A'); }
    if seg.fin() { flags.push('F'); }
    if seg.rst() { flags.push('R'); }
    if seg.flags & crate::frame::TCP_PSH != 0 { flags.push('P'); }
    if seg.flags & crate::frame::TCP_URG != 0 { flags.push('U'); }
    report.flags = Some(flags);
    report.data_len = Some(seg.payload.len());
}

/// Deterministic JSON serialization: BTreeMaps already sort keys; serde_json
/// preserves struct field order, which is fixed at compile time.
pub fn canonical_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("analysis result is always serializable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_timestamp_uses_frame_index() {
        // Ordering helper must be stable on (timestamp, index).
        let f = |i: usize| RawFrame {
            index: Some(i),
            timestamp: 1.0,
            link: LinkKind::Ethernet,
            bytes_hex: String::new(),
            comment: None,
        };
        let ordered = order_frames(vec![f(2), f(0), f(1)]);
        let indices: Vec<usize> = ordered.iter().map(|o| o.order).collect();
        assert_eq!(indices, vec![0, 1, 2]);
    }
}
