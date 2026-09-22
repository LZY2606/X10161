use crate::ipdefrag::{DatagramEvidence, DefragConfig, DefragOutcome, Defragmenter};
use crate::packet::{parse_frame, parse_tcp, NetPacket, PROTO_TCP};
use crate::pcap::{to_hex, Frame};
use crate::session::{
    Endpoint, OverlapPolicy, SessionConfig, SessionEngine, SessionEvent, SessionResult,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub overlap: String,
    pub session_timeout_ns: u64,
    pub frag_max_datagram_bytes: u64,
    pub frag_max_fragments: u64,
    pub frag_timeout_ns: u64,
}

impl Default for Config {
    fn default() -> Self {
        let s = SessionConfig::default();
        let d = DefragConfig::default();
        Config {
            overlap: OverlapPolicy::FirstSeen.as_str().to_string(),
            session_timeout_ns: s.timeout_ns,
            frag_max_datagram_bytes: d.max_datagram_bytes as u64,
            frag_max_fragments: d.max_fragments as u64,
            frag_timeout_ns: d.timeout_ns,
        }
    }
}

impl Config {
    pub fn with_overlap(mut self, policy: OverlapPolicy) -> Self {
        self.overlap = policy.as_str().to_string();
        self
    }
    fn session_config(&self) -> SessionConfig {
        SessionConfig {
            timeout_ns: self.session_timeout_ns,
            overlap: OverlapPolicy::parse(&self.overlap).unwrap_or(OverlapPolicy::FirstSeen),
        }
    }
    fn defrag_config(&self) -> DefragConfig {
        DefragConfig {
            max_datagram_bytes: self.frag_max_datagram_bytes as usize,
            max_fragments: self.frag_max_fragments as usize,
            timeout_ns: self.frag_timeout_ns,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FrameEvidence {
    pub index: u64,
    pub ts_ns: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct IgnoredEvidence {
    pub frame: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvidenceDoc {
    pub format: String,
    pub config: Config,
    pub frames: Vec<FrameEvidence>,
    pub ignored: Vec<IgnoredEvidence>,
    pub ip_datagrams: Vec<DatagramEvidence>,
    pub session_events: Vec<SessionEvent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResultDoc {
    pub format: String,
    pub config: Config,
    pub frame_count: usize,
    pub sessions: Vec<SessionResult>,
    pub fingerprint: String,
}

pub struct PayloadOut {
    pub file: String,
    pub data: Vec<u8>,
}

pub struct Analysis {
    pub result: ResultDoc,
    pub evidence: EvidenceDoc,
    pub payloads: Vec<PayloadOut>,
    pub frame_hashes: Vec<String>,
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    to_hex(&h.finalize())
}

/// Deterministic fingerprint of (config, input frames, session results).
fn fingerprint(config: &Config, frame_hashes: &[String], sessions: &[SessionResult]) -> String {
    #[derive(Serialize)]
    struct Fp<'a> {
        config: &'a Config,
        frames: &'a [String],
        sessions: &'a [SessionResult],
    }
    let doc = Fp {
        config,
        frames: frame_hashes,
        sessions,
    };
    let json = serde_json::to_string(&doc).expect("fingerprint serialization");
    sha256_hex(json.as_bytes())
}

pub fn analyze(frames: &[Frame], config: &Config) -> Analysis {
    // All ordering decisions use (timestamp, original frame index).
    let mut ordered: Vec<&Frame> = frames.iter().collect();
    ordered.sort_by_key(|f| (f.ts_ns, f.index));

    let frame_hashes: Vec<String> = frames.iter().map(|f| sha256_hex(&f.data)).collect();
    let frame_evidence: Vec<FrameEvidence> = frames
        .iter()
        .map(|f| FrameEvidence {
            index: f.index,
            ts_ns: f.ts_ns,
            sha256: frame_hashes[f.index as usize].clone(),
        })
        .collect();

    let mut defrag = Defragmenter::new(config.defrag_config());
    let mut engine = SessionEngine::new(config.session_config());
    let mut ignored: Vec<IgnoredEvidence> = Vec::new();

    for f in ordered {
        match parse_frame(&f.data) {
            Some(NetPacket::Direct {
                src,
                dst,
                proto,
                payload,
            }) => {
                if proto == PROTO_TCP {
                    handle_tcp(&mut engine, src, dst, payload, f);
                } else {
                    ignored.push(IgnoredEvidence {
                        frame: f.index,
                        reason: format!("non-TCP protocol {proto}"),
                    });
                }
            }
            Some(NetPacket::Fragment(frag)) => {
                match defrag.handle(&frag, f.index, f.ts_ns) {
                    DefragOutcome::Complete(dg) => {
                        if dg.key.proto == PROTO_TCP {
                            handle_tcp(&mut engine, dg.key.src, dg.key.dst, &dg.payload, f);
                        } else {
                            ignored.push(IgnoredEvidence {
                                frame: f.index,
                                reason: format!("reassembled non-TCP protocol {}", dg.key.proto),
                            });
                        }
                    }
                    DefragOutcome::Buffered | DefragOutcome::Isolated(_) => {}
                }
            }
            None => ignored.push(IgnoredEvidence {
                frame: f.index,
                reason: "unparseable or unsupported link/network layer".into(),
            }),
        }
    }
    defrag.finish();
    let finished = engine.finish();

    let mut sessions = Vec::new();
    let mut session_events = Vec::new();
    let mut payloads = Vec::new();
    for fs in finished {
        for (dir, bytes) in fs.payloads.iter().enumerate() {
            payloads.push(PayloadOut {
                file: format!("payload_s{}_d{}.bin", fs.result.id, dir),
                data: bytes.clone(),
            });
        }
        sessions.push(fs.result);
        session_events.extend(fs.events);
    }

    let fp = fingerprint(config, &frame_hashes, &sessions);
    Analysis {
        result: ResultDoc {
            format: "session-reassembly-result-v1".into(),
            config: config.clone(),
            frame_count: frames.len(),
            sessions,
            fingerprint: fp,
        },
        evidence: EvidenceDoc {
            format: "session-reassembly-evidence-v1".into(),
            config: config.clone(),
            frames: frame_evidence,
            ignored,
            ip_datagrams: defrag.evidence,
            session_events,
        },
        payloads,
        frame_hashes,
    }
}

fn handle_tcp(
    engine: &mut SessionEngine,
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    payload: &[u8],
    frame: &Frame,
) {
    let Some(seg) = parse_tcp(payload) else {
        return;
    };
    engine.process(
        Endpoint {
            ip: src,
            port: seg.src_port,
        },
        Endpoint {
            ip: dst,
            port: seg.dst_port,
        },
        &seg,
        frame.ts_ns,
        frame.index,
    );
}
