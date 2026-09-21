//! Local HTTP service. Raw captures are content-addressed on disk; each
//! (capture, policy) pair yields a new analysis version that never
//! overwrites older versions.

use crate::analysis::{run_analysis, Analysis};
use crate::engine::OverlapPolicy;
use crate::fixture::{emit_text_fixture, parse_frames, Frame};
use crate::json::Json;
use crate::sha256::sha256_hex;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAX_BODY: usize = 256 * 1024 * 1024;

pub struct Store {
    dir: PathBuf,
    inner: Mutex<StoreInner>,
}

#[derive(Default)]
struct StoreInner {
    frames: HashMap<String, Arc<Vec<Frame>>>,
    analyses: HashMap<String, Arc<Analysis>>, // key: "<blob>:<policy>"
}

impl Store {
    pub fn new(dir: &Path) -> std::io::Result<Store> {
        std::fs::create_dir_all(dir.join("blobs"))?;
        std::fs::create_dir_all(dir.join("analyses"))?;
        Ok(Store { dir: dir.to_path_buf(), inner: Mutex::new(StoreInner::default()) })
    }

    /// Content-addressed ingest. Returns (blob hash, frame count, existed).
    pub fn ingest(&self, bytes: &[u8]) -> Result<(String, usize, bool), String> {
        let frames = parse_frames(bytes)?;
        let hash = sha256_hex(bytes);
        let path = self.dir.join("blobs").join(&hash);
        let existed = path.exists();
        if !existed {
            std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
        }
        let count = frames.len();
        self.inner.lock().unwrap().frames.insert(hash.clone(), Arc::new(frames));
        Ok((hash, count, existed))
    }

    pub fn load_frames(&self, hash: &str) -> Result<Arc<Vec<Frame>>, String> {
        if let Some(f) = self.inner.lock().unwrap().frames.get(hash) {
            return Ok(f.clone());
        }
        let path = self.dir.join("blobs").join(hash);
        let bytes = std::fs::read(&path).map_err(|_| format!("unknown capture {}", hash))?;
        let frames = parse_frames(&bytes)?;
        let arc = Arc::new(frames);
        self.inner.lock().unwrap().frames.insert(hash.to_string(), arc.clone());
        Ok(arc)
    }

    /// Analysis for (blob, policy). Results are persisted per version and
    /// never overwritten: a policy change produces a new analysis file.
    pub fn analysis(&self, hash: &str, policy: OverlapPolicy) -> Result<Arc<Analysis>, String> {
        let key = format!("{}:{}", hash, policy.as_str());
        if let Some(a) = self.inner.lock().unwrap().analyses.get(&key) {
            return Ok(a.clone());
        }
        let frames = self.load_frames(hash)?;
        let analysis = Arc::new(run_analysis(&frames, policy));
        let path = self
            .dir
            .join("analyses")
            .join(format!("{}-{}.json", hash, policy.as_str()));
        if !path.exists() {
            let _ = std::fs::write(&path, analysis.evidence_json().render());
        }
        self.inner.lock().unwrap().analyses.insert(key, analysis.clone());
        Ok(analysis)
    }

    pub fn list_blobs(&self) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(self.dir.join("blobs")) {
            for e in rd.flatten() {
                if let Ok(meta) = e.metadata() {
                    out.push((e.file_name().to_string_lossy().into_owned(), meta.len()));
                }
            }
        }
        out.sort();
        out
    }

    pub fn analysis_versions(&self, hash: &str) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(self.dir.join("analyses")) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with(hash) && name.ends_with(".json") {
                    out.push(name);
                }
            }
        }
        out.sort();
        out
    }
}

pub fn run(addr: &str, store: Arc<Store>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("网络会话重组台 listening on http://{}", addr);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let store = store.clone();
                std::thread::spawn(move || {
                    let _ = handle(s, store);
                });
            }
            Err(e) => eprintln!("accept: {}", e),
        }
    }
    Ok(())
}

struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    body: Vec<u8>,
}

fn handle(mut stream: TcpStream, store: Arc<Store>) -> std::io::Result<()> {
    let req = match read_request(&mut stream)? {
        Some(r) => r,
        None => return Ok(()),
    };
    let (status, ctype, body) = route(&req, &store);
    let mut resp = format!(
        "HTTP/1.1 {} \r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        status,
        ctype,
        body.len()
    )
    .into_bytes();
    // Content-Disposition for downloads.
    if let Some(cd) = content_disposition(&req) {
        resp.extend_from_slice(format!("Content-Disposition: {}\r\n", cd).as_bytes());
    }
    resp.extend_from_slice(b"\r\n");
    resp.extend_from_slice(&body);
    stream.write_all(&resp)?;
    Ok(())
}

fn content_disposition(req: &Request) -> Option<String> {
    if req.path.starts_with("/api/download") {
        Some(format!(
            "attachment; filename=\"reassembled-{}-{}-{}.bin\"",
            req.query.get("session").map(|s| s.as_str()).unwrap_or("x"),
            req.query.get("dir").map(|s| s.as_str()).unwrap_or("x"),
            req.query.get("policy").map(|s| s.as_str()).unwrap_or("x"),
        ))
    } else if req.path.starts_with("/api/export") {
        Some("attachment; filename=\"capture.fixture.txt\"".into())
    } else if req.path.starts_with("/api/evidence") {
        Some("attachment; filename=\"evidence.json\"".into())
    } else {
        None
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 64 * 1024 {
            return Ok(None);
        }
    }
    let header = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = header.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
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
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), parse_query(q)),
        None => (target, HashMap::new()),
    };
    Ok(Some(Request { method, path, query, body }))
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            m.insert(url_decode(k), url_decode(v));
        }
    }
    m
}

fn url_decode(s: &str) -> String {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn route(req: &Request, store: &Store) -> (&'static str, &'static str, Vec<u8>) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => ("200 OK", "text/html; charset=utf-8", crate::UI_HTML.as_bytes().to_vec()),
        ("POST", "/api/upload") => match store.ingest(&req.body) {
            Ok((hash, count, existed)) => {
                let mut o = Json::obj();
                o.set("blob", Json::str(hash));
                o.set("frames", Json::int(count as i64));
                o.set("existed", Json::Bool(existed));
                ("200 OK", "application/json", o.render().into_bytes())
            }
            Err(e) => bad_request(&e),
        },
        ("POST", "/api/demo") => match store.ingest(crate::builder::demo_fixture().as_bytes()) {
            Ok((hash, count, _)) => {
                let mut o = Json::obj();
                o.set("blob", Json::str(hash));
                o.set("frames", Json::int(count as i64));
                ("200 OK", "application/json", o.render().into_bytes())
            }
            Err(e) => bad_request(&e),
        },
        ("GET", "/api/blobs") => {
            let arr: Vec<Json> = store
                .list_blobs()
                .iter()
                .map(|(h, size)| {
                    let mut o = Json::obj();
                    o.set("blob", Json::str(h.clone()));
                    o.set("bytes", Json::int(*size as i64));
                    o.set(
                        "versions",
                        Json::Arr(store.analysis_versions(h).into_iter().map(Json::str).collect()),
                    );
                    o
                })
                .collect();
            ("200 OK", "application/json", Json::Arr(arr).render().into_bytes())
        }
        ("GET", "/api/analysis") | ("GET", "/api/evidence") => {
            match get_analysis(req, store) {
                Ok(a) => ("200 OK", "application/json", a.evidence_json().render().into_bytes()),
                Err(e) => not_found(&e),
            }
        }
        ("GET", "/api/fingerprint") => match get_analysis(req, store) {
            Ok(a) => {
                let mut o = Json::obj();
                o.set("fingerprint", Json::str(a.fingerprint.clone()));
                o.set("policy", Json::str(a.policy.as_str()));
                ("200 OK", "application/json", o.render().into_bytes())
            }
            Err(e) => not_found(&e),
        },
        ("GET", "/api/download") => match get_analysis(req, store) {
            Ok(a) => {
                let sid: usize = req.query.get("session").and_then(|s| s.parse().ok()).unwrap_or(0);
                let dir: usize = req.query.get("dir").and_then(|s| s.parse().ok()).unwrap_or(0);
                match a.dir_analyses.get(sid).and_then(|d| d.get(dir)) {
                    Some(d) => ("200 OK", "application/octet-stream", d.reassembled.clone()),
                    None => not_found("no such session/direction"),
                }
            }
            Err(e) => not_found(&e),
        },
        ("GET", "/api/export") => {
            let hash = req.query.get("blob").cloned().unwrap_or_default();
            match store.load_frames(&hash) {
                Ok(frames) => (
                    "200 OK",
                    "text/plain; charset=utf-8",
                    emit_text_fixture(&frames).into_bytes(),
                ),
                Err(e) => not_found(&e),
            }
        }
        _ => not_found("not found"),
    }
}

fn get_analysis(req: &Request, store: &Store) -> Result<Arc<Analysis>, String> {
    let hash = req.query.get("blob").cloned().unwrap_or_default();
    let policy = req
        .query
        .get("policy")
        .and_then(|p| OverlapPolicy::parse(p))
        .unwrap_or(OverlapPolicy::FirstSeen);
    store.analysis(&hash, policy)
}

fn bad_request(msg: &str) -> (&'static str, &'static str, Vec<u8>) {
    ("400 Bad Request", "text/plain; charset=utf-8", msg.as_bytes().to_vec())
}
fn not_found(msg: &str) -> (&'static str, &'static str, Vec<u8>) {
    ("404 Not Found", "text/plain; charset=utf-8", msg.as_bytes().to_vec())
}
