//! Analysis pipeline: frames -> defrag -> TCP engine -> reassembly,
//! plus deterministic evidence JSON export and content fingerprinting.

use crate::defrag::{Defrag, Isolated};
use crate::engine::{
    analyze_direction, DirAnalysis, Engine, OverlapPolicy, Session,
};
use crate::fixture::{ordered_frames, Frame};
use crate::json::Json;
use crate::packet::{parse_frame, parse_tcp_datagram, IpPacket};
use crate::sha256::sha256_hex;

pub struct Analysis {
    pub policy: OverlapPolicy,
    pub frame_count: usize,
    pub parse_errors: Vec<String>,
    pub isolated: Vec<Isolated>,
    pub sessions: Vec<Session>,
    pub dir_analyses: Vec<[DirAnalysis; 2]>,
    pub fingerprint: String,
}

pub fn run_analysis(frames: &[Frame], policy: OverlapPolicy) -> Analysis {
    let mut engine = Engine::new();
    let mut defrag = Defrag::new();
    let mut parse_errors = Vec::new();

    for f in ordered_frames(frames) {
        match parse_frame(&f.data) {
            Ok(IpPacket::Tcp(pkt)) => engine.process(&pkt, f.ts_micros, f.index),
            Ok(IpPacket::Fragment { key, offset_bytes, more, payload }) => {
                if let Some(dgram) = defrag.add(key, offset_bytes, more, &payload, f.index) {
                    match parse_tcp_datagram(&dgram, key.src, key.dst) {
                        Ok(pkt) => engine.process(&pkt, f.ts_micros, f.index),
                        Err(e) => parse_errors.push(format!("frame {}: reassembled: {}", f.index, e)),
                    }
                }
            }
            Ok(IpPacket::Other { .. }) => {}
            Err(e) => parse_errors.push(format!("frame {}: {}", f.index, e)),
        }
    }
    defrag.finish();

    let mut dir_analyses = Vec::new();
    for s in &engine.sessions {
        dir_analyses.push([
            analyze_direction(&s.dirs[0], policy),
            analyze_direction(&s.dirs[1], policy),
        ]);
    }

    let mut analysis = Analysis {
        policy,
        frame_count: frames.len(),
        parse_errors,
        isolated: defrag.isolated,
        sessions: engine.sessions,
        dir_analyses,
        fingerprint: String::new(),
    };
    analysis.fingerprint = sha256_hex(analysis.canonical_json().render().as_bytes());
    analysis
}

impl Analysis {
    /// Canonical JSON used for fingerprinting (excludes volatile metadata).
    pub fn canonical_json(&self) -> Json {
        let mut root = Json::obj();
        root.set("format", Json::str("pgsb-analysis-v1"));
        root.set("policy", Json::str(self.policy.as_str()));
        root.set(
            "isolated_datagrams",
            Json::Arr(self.isolated.iter().map(isolated_json).collect()),
        );
        let mut sessions = Vec::new();
        for (i, s) in self.sessions.iter().enumerate() {
            sessions.push(session_json(s, &self.dir_analyses[i]));
        }
        root.set("sessions", Json::Arr(sessions));
        root
    }

    /// Full evidence JSON (canonical content + fingerprint + metadata).
    pub fn evidence_json(&self) -> Json {
        let mut root = self.canonical_json();
        root.set("frame_count", Json::int(self.frame_count as i64));
        root.set(
            "parse_errors",
            Json::Arr(self.parse_errors.iter().map(|e| Json::str(e.clone())).collect()),
        );
        root.set("fingerprint", Json::str(self.fingerprint.clone()));
        root
    }
}

fn isolated_json(iso: &Isolated) -> Json {
    let mut o = Json::obj();
    o.set("src", Json::str(iso.key.src.to_string()));
    o.set("dst", Json::str(iso.key.dst.to_string()));
    o.set("id", Json::int(iso.key.id as i64));
    o.set("proto", Json::int(iso.key.proto as i64));
    o.set("reason", Json::str(iso.reason.as_str()));
    o.set("received_bytes", Json::int(iso.received_bytes as i64));
    o.set(
        "frames",
        Json::Arr(iso.frames.iter().map(|f| Json::int(*f as i64)).collect()),
    );
    o
}

fn session_json(s: &Session, dirs: &[DirAnalysis; 2]) -> Json {
    let mut o = Json::obj();
    o.set("id", Json::int(s.id as i64));
    o.set("key", Json::str(s.key.label()));
    o.set("endpoint_a", Json::str(s.key.a.to_string()));
    o.set("endpoint_b", Json::str(s.key.b.to_string()));
    o.set("generation", Json::int(s.generation as i64));
    o.set("partial", Json::Bool(s.partial));
    o.set("handshake", Json::Bool(s.handshake));
    o.set(
        "closed_by",
        s.closed_by.map(|c| Json::str(c.as_str())).unwrap_or(Json::Null),
    );
    o.set("first_ts", Json::int(s.first_ts));
    o.set("last_ts", Json::int(s.last_ts));
    o.set("first_frame", Json::int(s.first_frame as i64));
    o.set("last_frame", Json::int(s.last_frame as i64));
    o.set(
        "directions",
        Json::Arr(vec![
            dir_json(&s.dirs[0], &dirs[0]),
            dir_json(&s.dirs[1], &dirs[1]),
        ]),
    );
    o
}

fn dir_json(d: &crate::engine::Direction, a: &DirAnalysis) -> Json {
    let mut o = Json::obj();
    o.set(
        "endpoint",
        d.endpoint.map(|e| Json::str(e.to_string())).unwrap_or(Json::Null),
    );
    o.set("isn", d.isn.map(|v| Json::int(v as i64)).unwrap_or(Json::Null));
    o.set(
        "base_seq",
        a.base_seq.map(|v| Json::int(v as i64)).unwrap_or(Json::Null),
    );
    o.set("syn_seen", Json::Bool(d.syn_seen));
    o.set("fin_seen", Json::Bool(d.fin_seen));
    o.set("rst_seen", Json::Bool(d.rst_seen));
    o.set("packet_count", Json::int(d.packet_count as i64));
    o.set("covered_bytes", Json::int(a.covered_bytes as i64));
    o.set("reassembled_len", Json::int(a.reassembled.len() as i64));
    o.set("reassembled_sha256", Json::str(sha256_hex(&a.reassembled)));
    o.set(
        "segments",
        Json::Arr(
            a.segments
                .iter()
                .map(|sv| {
                    let mut s = Json::obj();
                    s.set("seq_start", Json::int(sv.seq_start as i64));
                    s.set("seq_end", Json::int(sv.seq_end as i64));
                    s.set("len", Json::int(sv.len as i64));
                    s.set("frame", Json::int(sv.frame as i64));
                    s.set("ts", Json::int(sv.ts));
                    s.set("status", Json::str(sv.status));
                    s.set("out_of_order", Json::Bool(sv.out_of_order));
                    s
                })
                .collect(),
        ),
    );
    o.set(
        "overlaps",
        Json::Arr(
            a.overlaps
                .iter()
                .map(|ev| {
                    let mut s = Json::obj();
                    s.set("seq_start", Json::int(ev.seq_start as i64));
                    s.set("len", Json::int(ev.len as i64));
                    s.set("existing_frame", Json::int(ev.existing_frame as i64));
                    s.set("incoming_frame", Json::int(ev.incoming_frame as i64));
                    s.set("existing_bytes", Json::str(crate::sha256::to_hex(&ev.existing_bytes)));
                    s.set("incoming_bytes", Json::str(crate::sha256::to_hex(&ev.incoming_bytes)));
                    s.set("kept", Json::str(ev.kept));
                    s
                })
                .collect(),
        ),
    );
    o.set(
        "retransmissions",
        Json::Arr(
            a.retransmissions
                .iter()
                .map(|ev| {
                    let mut s = Json::obj();
                    s.set("seq_start", Json::int(ev.seq_start as i64));
                    s.set("len", Json::int(ev.len as i64));
                    s.set("frame", Json::int(ev.frame as i64));
                    s
                })
                .collect(),
        ),
    );
    o.set(
        "out_of_order",
        Json::Arr(
            a.out_of_order
                .iter()
                .map(|ev| {
                    let mut s = Json::obj();
                    s.set("seq", Json::int(ev.seq as i64));
                    s.set("expected", Json::int(ev.expected as i64));
                    s.set("frame", Json::int(ev.frame as i64));
                    s
                })
                .collect(),
        ),
    );
    o.set(
        "gaps",
        Json::Arr(
            a.gaps
                .iter()
                .map(|g| {
                    let mut s = Json::obj();
                    s.set("start", Json::int(g.start as i64));
                    s.set("end", Json::int(g.end as i64));
                    s
                })
                .collect(),
        ),
    );
    o
}
