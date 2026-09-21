//! 把 Analyzer 的结果物化为证据 JSON、重组流文件与结果指纹。

use crate::json::Value;
use crate::model::{fmt_ip, Frame};
use crate::session::{reassemble_direction, Analyzer, Params, Policy, Session};
use crate::sha256::sha256_hex;

pub const SCHEMA: &str = "pwgsb-evidence/1";

pub struct BuiltAnalysis {
    pub evidence: Value,
    pub canonical: String,
    pub fingerprint: String,
    /// (会话序号, 方向, 重组字节)
    pub streams: Vec<(usize, usize, Vec<u8>)>,
}

pub fn analyze(corpus_id: &str, frames: &[Frame], params: Params) -> BuiltAnalysis {
    let result = Analyzer::new(params).run(frames);
    let policy = params.policy;

    let mut sessions_json: Vec<Value> = Vec::new();
    let mut streams: Vec<(usize, usize, Vec<u8>)> = Vec::new();

    for session in &result.sessions {
        sessions_json.push(session_json(session, policy, &mut streams));
    }

    let mut isolated = Vec::new();
    for iso in &result.isolated {
        let mut o = Value::obj();
        o.set("frame", Value::Int(iso.frame_index as i128));
        o.set("ts_ns", Value::Int(iso.ts_ns as i128));
        o.set("datagram", Value::Str(iso.key.clone()));
        o.set("reason", Value::Str(iso.reason.clone()));
        isolated.push(o);
    }

    let mut malformed = Vec::new();
    for (frame, reason) in &result.malformed {
        let mut o = Value::obj();
        o.set("frame", Value::Int(*frame as i128));
        o.set("reason", Value::Str(reason.clone()));
        malformed.push(o);
    }

    let mut root = Value::obj();
    root.set("schema", Value::Str(SCHEMA.into()));
    root.set("corpus_id", Value::Str(corpus_id.into()));
    root.set("params", params.to_json());
    root.set("frame_count", Value::Int(result.frame_count as i128));
    root.set("ignored_frames", Value::Int(result.ignored as i128));
    root.set("malformed_frames", Value::Arr(malformed));
    root.set("isolated_datagrams", Value::Arr(isolated));
    root.set("sessions", Value::Arr(sessions_json));

    let canonical = root.serialize();
    let fingerprint = sha256_hex(canonical.as_bytes());
    root.set("fingerprint", Value::Str(fingerprint.clone()));

    BuiltAnalysis {
        evidence: root,
        canonical,
        fingerprint,
        streams,
    }
}

fn endpoint_json(ip: &[u8; 16], port: u16) -> Value {
    let mut o = Value::obj();
    o.set("ip", Value::Str(fmt_ip(ip)));
    o.set("port", Value::Int(port as i128));
    o
}

fn session_json(session: &Session, policy: Policy, streams: &mut Vec<(usize, usize, Vec<u8>)>) -> Value {
    let mut o = Value::obj();
    o.set("session_id", Value::Int(session.id as i128));
    o.set("generation", Value::Int(session.generation as i128));
    o.set(
        "partial",
        Value::Bool(session.isn[0].is_none() && session.isn[1].is_none()),
    );
    o.set("started_mid_capture", Value::Bool(session.partial));
    o.set("close_reason", Value::Str(session.close_reason.clone()));
    o.set("first_ts_ns", Value::Int(session.first_ts as i128));
    o.set("last_ts_ns", Value::Int(session.last_ts as i128));

    let (a, b) = (session.key.lo, session.key.hi);
    let mut tuple = Value::obj();
    tuple.set("a", endpoint_json(&a.ip, a.port));
    tuple.set("b", endpoint_json(&b.ip, b.port));
    o.set("tuple", tuple);

    o.set(
        "isn",
        Value::Arr(
            session
                .isn
                .iter()
                .map(|i| match i {
                    Some(v) => Value::Int(*v as i128),
                    None => Value::Null,
                })
                .collect(),
        ),
    );
    o.set(
        "fin_frame",
        Value::Arr(
            session
                .fin_frame
                .iter()
                .map(|f| f.map(|v| Value::Int(v as i128)).unwrap_or(Value::Null))
                .collect(),
        ),
    );
    o.set(
        "rst_frame",
        session
            .rst_frame
            .map(|v| Value::Int(v as i128))
            .unwrap_or(Value::Null),
    );
    o.set(
        "notes",
        Value::Arr(session.notes.iter().map(|n| Value::Str(n.clone())).collect()),
    );

    let mut dirs = Vec::new();
    for dir in 0..2usize {
        let outcome = reassemble_direction(&session.segments[dir], session.isn[dir], policy);
        let (from, to) = if dir == 0 { (a, b) } else { (b, a) };
        let mut d = Value::obj();
        d.set("dir", Value::Int(dir as i128));
        d.set("from", endpoint_json(&from.ip, from.port));
        d.set("to", endpoint_json(&to.ip, to.port));
        d.set(
            "base_seq",
            outcome.base.map(|v| Value::Int(v as i128)).unwrap_or(Value::Null),
        );
        d.set("segment_count", Value::Int(session.segments[dir].len() as i128));
        let received: usize = session.segments[dir].iter().map(|s| s.data.len()).sum();
        d.set("received_bytes", Value::Int(received as i128));
        d.set("stream_offset", Value::Int(outcome.stream_offset as i128));
        d.set("stream_len", Value::Int(outcome.stream.len() as i128));
        d.set("contiguous_len", Value::Int(outcome.contiguous_len as i128));
        d.set("retransmissions", Value::Int(outcome.retransmissions as i128));
        d.set("out_of_order", Value::Int(outcome.out_of_order as i128));
        d.set("overlaps", Value::Int(outcome.overlaps as i128));
        d.set(
            "ranges",
            Value::Arr(
                outcome
                    .ranges
                    .iter()
                    .map(|(s, e)| {
                        Value::Arr(vec![Value::Int(*s as i128), Value::Int(*e as i128)])
                    })
                    .collect(),
            ),
        );
        d.set(
            "gaps",
            Value::Arr(
                outcome
                    .gaps
                    .iter()
                    .map(|(s, e)| {
                        Value::Arr(vec![Value::Int(*s as i128), Value::Int(*e as i128)])
                    })
                    .collect(),
            ),
        );
        d.set("events", outcome.events);
        dirs.push(d);
        streams.push((session.id, dir, outcome.stream));
    }
    o.set("directions", Value::Arr(dirs));
    o
}
