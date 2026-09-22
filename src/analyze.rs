use crate::capture::Capture;
use crate::hash;
use crate::ipreasm;
use crate::json::{self, Json};
use crate::model;
use crate::tcp::{DatagramFrame, Engine, EngineConfig, OverlapPolicy, SegRecord, Session};

pub struct AnalysisOptions {
    pub policy: OverlapPolicy,
    pub timeout_us: i128,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        AnalysisOptions {
            policy: OverlapPolicy::FirstSeen,
            timeout_us: 2_000_000,
        }
    }
}

pub fn run(cap: &Capture, opts: &AnalysisOptions) -> Json {
    // Frames are processed in original capture order; equal timestamps keep
    // that order (frame index), which is the required tie-break.
    let mut packets = Vec::new();
    let mut skipped = Vec::new();
    for (i, frame) in cap.frames.iter().enumerate() {
        match model::extract_packet(i, cap.link, frame) {
            Some(p) => packets.push(p),
            None => skipped.push(serr(i, "non-IP or unparseable frame")),
        }
    }
    let ipr = ipreasm::reassemble(packets, &cap.ts_us);

    let mut engine = Engine::new(EngineConfig {
        policy: opts.policy,
        timeout_us: opts.timeout_us,
    });

    // Reassembled datagrams are stamped with the first fragment's index,
    // preserving global ordering against other frames.
    for dg in &ipr.datagrams {
        if let Some(t) = &dg.tcp {
            engine.ingest(&DatagramFrame {
                frame_idx: dg.frame_idx,
                ts_us: cap.ts_us[dg.frame_idx],
                src: dg.src.clone(),
                dst: dg.dst.clone(),
                ip_version: dg.ip_version,
                sport: t.sport,
                dport: t.dport,
                seq: t.seq,
                ack: t.ack,
                flags: t.flags,
                payload: t.payload.clone(),
            });
        }
    }
    engine.finalize();

    let frame_hashes: Vec<String> = cap
        .frames
        .iter()
        .map(|f| hash::hex(&hash::sha256(f)))
        .collect();

    let mut sessions = Vec::new();
    for (si, s) in engine.sessions.iter().enumerate() {
        sessions.push(session_json(si, s, &engine, &frame_hashes, &cap.ts_us));
    }

    let mut frag_notes = Vec::new();
    for n in &ipr.notes {
        let mut o = Json::obj();
        o.set("frame", Json::Num(n.frame_idx as i128));
        o.set("reason", Json::Str(n.reason.into()));
        o.set("fragment_group", Json::Str(n.key.clone()));
        frag_notes.push(o);
    }

    let mut root = Json::obj();
    root.set("tool", Json::Str("网络会话重组台".into()));
    root.set("format_version", Json::Num(1));
    root.set("input_kind", Json::Str(cap.kind.clone()));
    root.set("frame_count", Json::Num(cap.frames.len() as i128));
    let mut cfg = Json::obj();
    cfg.set("overlap_policy", Json::Str(opts.policy.name().into()));
    cfg.set("timeout_us", Json::Num(opts.timeout_us));
    root.set("config", cfg);
    root.set("sessions", Json::Arr(sessions));
    root.set("fragment_notes", Json::Arr(frag_notes));
    let mut sk: Vec<Json> = Vec::new();
    for (i, msg) in skipped {
        let mut o = Json::obj();
        o.set("frame", Json::Num(i as i128));
        o.set("reason", Json::Str(msg));
        sk.push(o);
    }
    root.set("skipped_frames", Json::Arr(sk));
    root
}

fn serr(i: usize, m: &str) -> (usize, String) {
    (i, m.to_string())
}

fn session_json(
    si: usize,
    s: &Session,
    engine: &Engine,
    frame_hashes: &[String],
    ts: &[i128],
) -> Json {
    let mut o = Json::obj();
    o.set("session_index", Json::Num(si as i128));
    o.set("generation", Json::Num(s.gen as i128));
    o.set("four_tuple", Json::Str(s.key.clone()));
    o.set("ip_version", Json::Num(s.ip_version as i128));
    let mut ep = Json::obj();
    ep.set("client", Json::Str(format!("{}:{}", s.c_ip, s.c_port)));
    ep.set("server", Json::Str(format!("{}:{}", s.s_ip, s.s_port)));
    o.set("endpoints", ep);
    o.set("state", Json::Str(s.state.clone()));
    o.set("close_reason", Json::Str(s.close_reason.clone()));
    o.set("handshake", Json::Str(s.handshake.clone()));
    o.set("started_mid_capture", Json::Bool(s.mid_capture));
    o.set("start_frame", Json::Num(s.start_frame as i128));
    o.set("end_frame", Json::Num(s.end_frame as i128));
    o.set("start_ts_us", Json::Num(s.start_ts));
    o.set("last_ts_us", Json::Num(s.last_ts));

    let mut dirs = Vec::new();
    for d in 0u8..2 {
        dirs.push(dir_json(d, s, engine, frame_hashes, ts));
    }
    o.set("directions", Json::Arr(dirs));

    let mut segs = Vec::new();
    for r in &s.segments {
        segs.push(seg_json(r, frame_hashes));
    }
    o.set("segments", Json::Arr(segs));

    let mut gaps = Vec::new();
    for (dir, b, e) in engine.gaps(si) {
        let mut g = Json::obj();
        g.set("direction", Json::Num(dir as i128));
        g.set("begin", Json::Num(b as i128));
        g.set("end", Json::Num(e as i128));
        g.set("length", Json::Num((e - b) as i128));
        gaps.push(g);
    }
    o.set("gaps", Json::Arr(gaps));
    o
}

fn dir_json(dir: u8, s: &Session, engine: &Engine, frame_hashes: &[String], _ts: &[i128]) -> Json {
    let st = &s.dirs[dir as usize];
    let _ = engine;
    let mut o = Json::obj();
    o.set(
        "label",
        Json::Str(if dir == 0 {
            format!("{}:{} -> {}:{}", s.c_ip, s.c_port, s.s_ip, s.s_port)
        } else {
            format!("{}:{} -> {}:{}", s.s_ip, s.s_port, s.c_ip, s.c_port)
        }),
    );
    o.set(
        "base_isn",
        match st.base {
            Some(b) => Json::Num(b as i128),
            None => Json::Null,
        },
    );
    o.set("base_from_syn", Json::Bool(st.base_syn));
    if let Some(f) = st.base_frame {
        o.set("base_frame", Json::Num(f as i128));
        o.set("base_frame_sha256", Json::Str(frame_hashes[f].clone()));
    }
    let data_start = if st.base_syn { 1i64 } else { 0 };
    o.set("data_begin", Json::Num(data_start as i128));
    o.set("reassembled_length", Json::Num(st.bytes.len() as i128));
    o.set("frontier", Json::Num(st.frontier as i128));
    o.set("max_span_end", Json::Num(st.max_end as i128));
    o.set("fin_seen", Json::Bool(st.fin));
    o.set("rst_seen", Json::Bool(st.rst));
    o.set("retransmissions", Json::Num(st.retrans as i128));
    o.set("out_of_order_segments", Json::Num(st.out_of_order as i128));
    o.set("overlap_events", Json::Num(st.overlap_events as i128));
    o.set("data_hex", Json::Str(json::bytes_to_hex(&st.bytes)));
    o.set(
        "data_utf8_lossy",
        Json::Str(String::from_utf8_lossy(&st.bytes).into_owned()),
    );

    // Per-byte ownership coverage map (frame indices, run-length encoded).
    let mut runs = Vec::new();
    let mut last: Option<(usize, usize)> = None;
    for &f in &st.owner {
        match last {
            Some((frame, n)) if frame == f => last = Some((frame, n + 1)),
            Some((frame, n)) => {
                runs.push((frame, n));
                last = Some((f, 1));
            }
            None => last = Some((f, 1)),
        }
    }
    if let Some((frame, n)) = last {
        runs.push((frame, n));
    }
    let mut cov = Vec::new();
    for (frame, len) in runs {
        let mut c = Json::obj();
        c.set("frame", Json::Num(frame as i128));
        c.set("frame_sha256", Json::Str(frame_hashes[frame].clone()));
        c.set("length", Json::Num(len as i128));
        cov.push(c);
    }
    o.set("coverage", Json::Arr(cov));
    o
}

fn seg_json(r: &SegRecord, frame_hashes: &[String]) -> Json {
    let mut o = Json::obj();
    o.set("frame", Json::Num(r.frame_idx as i128));
    o.set("frame_sha256", Json::Str(frame_hashes[r.frame_idx].clone()));
    o.set("direction", Json::Num(r.dir as i128));
    o.set("seq_abs", Json::Num(r.seq_abs as i128));
    o.set("begin", Json::Num(r.begin as i128));
    o.set("end", Json::Num(r.end as i128));
    o.set("length", Json::Num(r.len as i128));
    let mut flags = Vec::new();
    if r.flags & 0x02 != 0 {
        flags.push("SYN");
    }
    if r.flags & 0x10 != 0 {
        flags.push("ACK");
    }
    if r.flags & 0x01 != 0 {
        flags.push("FIN");
    }
    if r.flags & 0x04 != 0 {
        flags.push("RST");
    }
    if r.flags & 0x08 != 0 {
        flags.push("PSH");
    }
    o.set(
        "flags",
        Json::Arr(flags.into_iter().map(|f| Json::Str(f.into())).collect()),
    );
    o.set("relation", Json::Str(r.relation.clone()));
    o.set("conflict", Json::Bool(r.conflict));
    o.set("overwritten_bytes", Json::Num(r.overwritten as i128));
    o.set("ts_us", Json::Num(r.ts_us));
    o.set("payload_hex", Json::Str(json::bytes_to_hex(&r.data)));
    o
}

/// Fingerprint over the deterministic result, excluding volatile metadata.
pub fn fingerprint(result: &Json) -> String {
    // Strip both volatile analysis metadata and byte/payload evidence blobs,
    // then canonicalize through a parse/serialize cycle so that a freshly
    // computed result and an exported/re-imported result hash identically.
    let trimmed = strip_meta(result);
    let canon = json::to_string(&trimmed);
    let reparsed = json::parse(&canon).unwrap_or(trimmed);
    hash::hex(&hash::sha256(json::to_string(&reparsed).as_bytes()))
}

fn strip_meta(v: &Json) -> Json {
    match v {
        Json::Obj(m) => {
            let mut out = std::collections::BTreeMap::new();
            for (k, val) in m {
                if matches!(
                    k.as_str(),
                    "data_hex"
                        | "data_utf8_lossy"
                        | "payload_hex"
                        | "frame_sha256"
                        | "base_frame_sha256"
                ) {
                    continue;
                }
                out.insert(k.clone(), strip_meta(val));
            }
            Json::Obj(out)
        }
        Json::Arr(a) => Json::Arr(a.iter().map(strip_meta).collect()),
        other => other.clone(),
    }
}

pub fn strip_meta_pub(v: &Json) -> Json {
    strip_meta(v)
}
