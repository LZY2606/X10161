use crate::analyze::{analyze, Config};
use crate::pcap::{export_fixture, parse_capture};
use crate::session::OverlapPolicy;
use crate::store::Store;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

const INDEX_HTML: &str = include_str!("../static/index.html");
const MAX_BODY: usize = 256 * 1024 * 1024;

pub fn run(addr: &str, store: Store) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("网络会话重组台 listening on http://{addr}");
    let store = Arc::new(store);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    let _ = handle(s, &store);
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    body: Vec<u8>,
}

fn handle(mut stream: TcpStream, store: &Store) -> std::io::Result<()> {
    let req = match read_request(&mut stream)? {
        Some(r) => r,
        None => return Ok(()),
    };
    let (status, content_type, body) = route(&req, store);
    let disposition = if content_type == "application/octet-stream"
        || content_type == "application/json; download"
    {
        "Content-Disposition: attachment\r\n"
    } else {
        ""
    };
    let content_type = content_type.replace("; download", "");
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{disposition}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65536];
    let header_end;
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 1024 * 1024 {
            return Ok(None);
        }
    }
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }
    if content_length > MAX_BODY {
        return Ok(None);
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), parse_query(q)),
        None => (target, Vec::new()),
    };
    Ok(Some(Request {
        method,
        path,
        query,
        body,
    }))
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (url_decode(k), url_decode(v)),
            None => (url_decode(kv), String::new()),
        })
        .collect()
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn qget<'a>(req: &'a Request, key: &str) -> Option<&'a str> {
    req.query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn json_response(value: &impl serde::Serialize) -> (u16, &'static str, Vec<u8>) {
    (
        200,
        "application/json; charset=utf-8",
        serde_json::to_vec(value).expect("json"),
    )
}

fn err(status: u16, msg: &str) -> (u16, &'static str, Vec<u8>) {
    (
        status,
        "application/json; charset=utf-8",
        serde_json::to_vec(&serde_json::json!({"error": msg})).expect("json"),
    )
}

fn route(req: &Request, store: &Store) -> (u16, &'static str, Vec<u8>) {
    let segments: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
    match (req.method.as_str(), segments.as_slice()) {
        ("GET", []) => (
            200,
            "text/html; charset=utf-8",
            INDEX_HTML.as_bytes().to_vec(),
        ),
        ("GET", ["api", "analyses"]) => match store.list() {
            Ok(list) => json_response(&list),
            Err(e) => err(500, &e.to_string()),
        },
        ("POST", ["api", "upload"]) => upload(req, store),
        ("GET", ["api", "analysis", id]) => match store.load_result(id) {
            Ok(text) => (200, "application/json; charset=utf-8", text.into_bytes()),
            Err(_) => err(404, "analysis not found"),
        },
        ("GET", ["api", "analysis", id, "evidence"]) => match store.load_evidence(id) {
            Ok(text) => (200, "application/json; download", text.into_bytes()),
            Err(_) => err(404, "analysis not found"),
        },
        ("GET", ["api", "analysis", id, "fixture"]) => fixture_download(id, store),
        ("GET", ["api", "analysis", id, "payload", session, dir]) => {
            let file = format!("payload_s{session}_d{dir}.bin");
            match store.load_payload(id, &file) {
                Ok(bytes) => (200, "application/octet-stream", bytes),
                Err(_) => err(404, "payload not found"),
            }
        }
        ("POST", ["api", "analysis", id, "reanalyze"]) => reanalyze(req, id, store),
        _ => err(404, "not found"),
    }
}

fn upload(req: &Request, store: &Store) -> (u16, &'static str, Vec<u8>) {
    let policy = qget(req, "policy")
        .and_then(OverlapPolicy::parse)
        .unwrap_or(OverlapPolicy::FirstSeen);
    let name = qget(req, "name").unwrap_or("capture").to_string();
    let frames = match parse_capture(&req.body) {
        Ok(f) => f,
        Err(e) => return err(400, &format!("cannot parse capture: {e}")),
    };
    if frames.is_empty() {
        return err(400, "capture contains no frames");
    }
    let config = Config::default().with_overlap(policy);
    if let Err(e) = store.save_frames(&frames) {
        return err(500, &e.to_string());
    }
    let analysis = analyze(&frames, &config);
    match store.save_analysis(&name, &config, &frames, &analysis) {
        Ok(id) => json_response(&serde_json::json!({
            "id": id,
            "fingerprint": analysis.result.fingerprint,
            "sessions": analysis.result.sessions.len(),
            "frames": frames.len(),
        })),
        Err(e) => err(500, &e.to_string()),
    }
}

fn reanalyze(req: &Request, id: &str, store: &Store) -> (u16, &'static str, Vec<u8>) {
    let meta = match store.load_meta(id) {
        Ok(m) => m,
        Err(_) => return err(404, "analysis not found"),
    };
    let mut config = meta.config.clone();
    if let Some(p) = qget(req, "policy").and_then(OverlapPolicy::parse) {
        config = config.with_overlap(p);
    }
    let frames = match store.load_frames(&meta.frame_hashes, &meta.frame_ts_ns) {
        Ok(f) => f,
        Err(e) => return err(500, &e.to_string()),
    };
    let analysis = analyze(&frames, &config);
    match store.save_analysis(&meta.name, &config, &frames, &analysis) {
        Ok(new_id) => json_response(&serde_json::json!({
            "id": new_id,
            "previous_id": id,
            "fingerprint": analysis.result.fingerprint,
            "sessions": analysis.result.sessions.len(),
        })),
        Err(e) => err(500, &e.to_string()),
    }
}

fn fixture_download(id: &str, store: &Store) -> (u16, &'static str, Vec<u8>) {
    let meta = match store.load_meta(id) {
        Ok(m) => m,
        Err(_) => return err(404, "analysis not found"),
    };
    match store.load_frames(&meta.frame_hashes, &meta.frame_ts_ns) {
        Ok(frames) => (
            200,
            "application/json; download",
            export_fixture(&frames).into_bytes(),
        ),
        Err(e) => err(500, &e.to_string()),
    }
}
