//! Minimal standard-library HTTP server for the workbench UI and JSON API.

use crate::analyze::AnalysisConfig;
use crate::fixture::{parse_input, write_pcap};
use crate::reasm::OverlapPolicy;
use crate::store::Store;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct State {
    store: Store,
}

pub fn run(addr: &str, data_dir: PathBuf) -> Result<(), String> {
    let store = Store::open(data_dir)?;
    let state = Arc::new(Mutex::new(State { store }));
    let listener = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
    println!("网络会话重组台 listening on http://{addr}");
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    let _ = handle_connection(stream, state);
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, state: Arc<Mutex<State>>) -> Result<(), String> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    // Read headers.
    let header_end = loop {
        let n = stream.read(&mut tmp).map_err(io_err)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return Err("headers too large".to_string());
        }
    };
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_target = parts.next().unwrap_or("/").to_string();
    let (path, query) = match raw_target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_target, String::new()),
    };
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':').map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())))
        .collect();
    let has_body_header = headers.iter().any(|(k, _)| k == "content-length");
    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);

    // Honor Expect: 100-continue (curl sends it).
    if headers.iter().any(|(k, v)| k == "expect" && v.to_lowercase().contains("100-continue")) {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").map_err(io_err)?;
    }

    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let n = stream.read(&mut tmp).map_err(io_err)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = if has_body_header && buf.len() >= body_start {
        buf[body_start..body_start + content_length.min(buf.len() - body_start)].to_vec()
    } else {
        Vec::new()
    };

    let response = route(&method, &path, &query, &body, &state);
    write_response(&mut stream, response)
}

struct Response {
    status: u16,
    content_type: String,
    body: Vec<u8>,
    extra_headers: Vec<(String, String)>,
}

fn ok_json(value: &impl serde::Serialize) -> Response {
    let body = serde_json::to_vec_pretty(value).unwrap_or_default();
    Response {
        status: 200,
        content_type: "application/json; charset=utf-8".to_string(),
        body,
        extra_headers: vec![],
    }
}

fn text(status: u16, msg: &str) -> Response {
    Response {
        status,
        content_type: "text/plain; charset=utf-8".to_string(),
        body: msg.to_string().into_bytes(),
        extra_headers: vec![],
    }
}

fn error_json(status: u16, message: &str) -> Response {
    let payload = serde_json::json!({ "error": message });
    Response {
        status,
        content_type: "application/json; charset=utf-8".to_string(),
        body: serde_json::to_vec_pretty(&payload).unwrap_or_default(),
        extra_headers: vec![],
    }
}

fn write_response(stream: &mut TcpStream, resp: Response) -> Result<(), String> {
    let reason = match resp.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        resp.status, resp.content_type, resp.content_type, resp.body.len()
    );
    for (k, v) in &resp.extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).map_err(io_err)?;
    stream.write_all(&resp.body).map_err(io_err)?;
    Ok(())
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn io_err(e: std::io::Error) -> String {
    e.to_string()
}

#[derive(serde::Deserialize)]
struct AnalyzeRequest {
    overlap_policy: Option<String>,
    timeout_seconds: Option<f64>,
}

fn parse_policy(text: &str) -> Result<OverlapPolicy, String> {
    match text {
        "first-seen" | "firstseen" => Ok(OverlapPolicy::FirstSeen),
        "last-seen" | "lastseen" => Ok(OverlapPolicy::LastSeen),
        other => Err(format!("unknown overlap policy {other}")),
    }
}

fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').filter_map(|kv| kv.split_once('=')).find_map(|(k, v)| {
        if k == key {
            Some(percent_decode(v))
        } else {
            None
        }
    })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn route(method: &str, path: &str, query: &str, body: &[u8], state: &Arc<Mutex<State>>) -> Response {
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => serve_static("text/html; charset=utf-8", include_str!("../static/index.html")),
        ("GET", "/app.js") => serve_static("application/javascript; charset=utf-8", include_str!("../static/app.js")),
        ("GET", "/styles.css") => serve_static("text/css; charset=utf-8", include_str!("../static/styles.css")),
        ("GET", "/api/health") => ok_json(&serde_json::json!({ "status": "ok", "service": "网络会话重组台" })),
        ("GET", "/api/datasets") => with_state(state, |s| match s.store.list_datasets() {
            Ok(list) => ok_json(&list),
            Err(e) => error_json(500, &e),
        }),
        ("POST", "/api/datasets") => upload_dataset(body, state),
        ("POST", "/api/import-bundle") => import_bundle_route(body, state),
        ("GET", p) if p.starts_with("/api/datasets/") => dataset_get(p, query, state),
        ("POST", p) if p.starts_with("/api/datasets/") => dataset_post(p, body, state),
        _ => text(404, "not found"),
    }
}

fn serve_static(content_type: &str, content: &str) -> Response {
    Response {
        status: 200,
        content_type: content_type.to_string(),
        body: content.to_string().into_bytes(),
        extra_headers: vec![],
    }
}

fn with_state<F>(state: &Arc<Mutex<State>>, f: F) -> Response
where
    F: FnOnce(&State) -> Response,
{
    match state.lock() {
        Ok(s) => f(&s),
        Err(_) => error_json(500, "state lock poisoned"),
    }
}

fn dataset_get(path: &str, query: &str, state: &Arc<Mutex<State>>) -> Response {
    let rest = &path["/api/datasets/".len()..];
    let components: Vec<&str> = rest.split('/').collect();
    match components.as_slice() {
        [id] => with_state(state, |s| match s.store.get_dataset(id) {
            Ok(meta) => ok_json(&meta),
            Err(e) => error_json(404, &e),
        }),
        [id, "export"] => with_state(state, |s| match s.store.export_bundle(id) {
            Ok(bundle) => {
                let body = serde_json::to_vec_pretty(&bundle).unwrap_or_default();
                download_response(body, &format!("{id}-bundle.json"), "application/json")
            }
            Err(e) => error_json(404, &e),
        }),
        [id, "pcap"] => with_state(state, |s| match s.store.get_dataset(id) {
            Ok(meta) => {
                let bytes = write_pcap(&meta.frames);
                download_response(bytes, &format!("{id}.pcap"), "application/vnd.tcpdump.pcap")
            }
            Err(e) => error_json(404, &e),
        }),
        [id, "versions", version] => {
            let version: usize = match version.parse() {
                Ok(v) => v,
                Err(_) => return error_json(400, "version must be a number"),
            };
            with_state(state, |s| match s.store.load_result(id, version) {
                Ok(result) => match query_value(query, "download").as_deref() {
                    Some("reassembled") => download_reassembled(&result),
                    _ => ok_json(&result),
                },
                Err(e) => error_json(404, &e),
            })
        }
        _ => text(404, "not found"),
    }
}

fn dataset_post(path: &str, body: &[u8], state: &Arc<Mutex<State>>) -> Response {
    let rest = &path["/api/datasets/".len()..];
    let components: Vec<&str> = rest.split('/').collect();
    match components.as_slice() {
        [id, "analyze"] => {
            let req: AnalyzeRequest = if body.is_empty() {
                AnalyzeRequest { overlap_policy: None, timeout_seconds: None }
            } else {
                match serde_json::from_slice(body) {
                    Ok(v) => v,
                    Err(e) => return error_json(400, &format!("invalid request JSON: {e}")),
                }
            };
            let policy = match req.overlap_policy.as_deref() {
                None | Some("") => OverlapPolicy::default(),
                Some(p) => match parse_policy(p) {
                    Ok(v) => v,
                    Err(e) => return error_json(400, &e),
                },
            };
            let config = AnalysisConfig {
                overlap_policy: policy,
                timeout_seconds: req.timeout_seconds.unwrap_or(120.0),
            };
            with_state(state, |s| match s.store.analyze_dataset(id, config) {
                Ok((_meta, result, info)) => ok_json(&serde_json::json!({
                    "version": info,
                    "analysis": result,
                })),
                Err(e) => error_json(400, &e),
            })
        }
        [_id, "import-bundle"] => text(405, "use POST /api/import-bundle"),
        _ => text(404, "not found"),
    }
}

fn download_reassembled(result: &crate::analyze::AnalysisResult) -> Response {
    let mut buffer = Vec::new();
    for session in &result.sessions {
        buffer.extend_from_slice(format!("# session {} {}\n", session.session_id, session.flow).as_bytes());
        for (endpoint, dir) in &session.directions {
            buffer.extend_from_slice(
                format!("# direction {endpoint} delivered {} bytes\n", dir.delivered_length).as_bytes(),
            );
            if let Ok(bytes) = crate::types::decode_hex(&dir.delivered_hex) {
                buffer.extend_from_slice(&bytes);
                buffer.push(b'\n');
            }
        }
        buffer.push(b'\n');
    }
    download_response(buffer, "reassembled.txt", "text/plain; charset=utf-8")
}

fn download_response(body: Vec<u8>, filename: &str, content_type: &str) -> Response {
    Response {
        status: 200,
        content_type: content_type.to_string(),
        body,
        extra_headers: vec![(
            "Content-Disposition".to_string(),
            format!("attachment; filename=\"{filename}\""),
        )],
    }
}

/// Accept either raw fixture/pcap bytes or multipart/form-data containing a
/// `file` part and an optional `name` field.
fn upload_dataset(body: &[u8], state: &Arc<Mutex<State>>) -> Response {
    let (content, name) = extract_upload(body);
    let frames = match parse_input(&content) {
        Ok(f) => f,
        Err(e) => return error_json(400, &format!("failed to parse fixture: {e}")),
    };
    let dataset_name = name.unwrap_or_else(|| "uploaded fixture".to_string());
    with_state(state, |s| match s.store.create_dataset(dataset_name, frames) {
        Ok(meta) => ok_json(&serde_json::json!({
            "dataset_id": meta.id,
            "frame_count": meta.frame_count,
            "versions": meta.versions,
        })),
        Err(e) => error_json(400, &e),
    })
}

fn extract_upload(body: &[u8]) -> (Vec<u8>, Option<String>) {
    // Multipart detection requires content-type, which route() does not pass.
    // The browser always posts multipart; JSON callers post raw bytes. We sniff
    // for the multipart boundary marker directly.
    if body.starts_with(b"--") {
        parse_multipart(body)
    } else {
        (body.to_vec(), None)
    }
}

fn parse_multipart(body: &[u8]) -> (Vec<u8>, Option<String>) {
    // Boundary is the first line up to CRLF.
    let line_end = body.windows(2).position(|w| w == b"\r\n").unwrap_or(body.len());
    let boundary = &body[..line_end];
    let mut file_content = Vec::new();
    let mut name = None;
    let mut rest = &body[line_end..];
    while let Some(part) = next_part(&mut rest, boundary) {
        if part.name == "file" && file_content.is_empty() {
            file_content = part.data;
        } else if part.name == "name" && name.is_none() {
            name = Some(String::from_utf8_lossy(&part.data).trim().to_string());
        }
    }
    (file_content, name)
}

struct Part {
    name: String,
    data: Vec<u8>,
}

fn next_part(rest: &mut &[u8], boundary: &[u8]) -> Option<Part> {
    // After a boundary line the stream begins with CRLF; skip it.
    let data: &[u8] = if rest.starts_with(b"\r\n") { &rest[2..] } else { rest };
    let header_end = data.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = String::from_utf8_lossy(&data[..header_end]);
    let name = headers
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-disposition"))
        .and_then(|l| {
            l.split(';').find_map(|kv| {
                let kv = kv.trim();
                kv.strip_prefix("name=\"")
                    .and_then(|v| v.strip_suffix('\"'))
                    .map(|v| v.to_string())
            })
        })
        .unwrap_or_default();
    let payload_start = header_end + 4;
    let mut delimiter = Vec::with_capacity(2 + boundary.len());
    delimiter.extend_from_slice(b"\r\n");
    delimiter.extend_from_slice(boundary);
    let rel = find_subsequence(&data[payload_start..], &delimiter)?;
    let payload = data[payload_start..payload_start + rel].to_vec();
    let consumed = payload_start + rel + 2 + boundary.len();
    *rest = &data[consumed..];
    Some(Part { name, data: payload })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// POST /api/import-bundle is registered separately (no dataset id in path).
pub fn import_bundle_route(body: &[u8], state: &Arc<Mutex<State>>) -> Response {
    let bundle: crate::store::ExportBundle = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(e) => return error_json(400, &format!("invalid bundle: {e}")),
    };
    with_state(state, |s| match s.store.import_bundle(bundle) {
        Ok(meta) => ok_json(&serde_json::json!({
            "dataset_id": meta.id,
            "frame_count": meta.frame_count,
            "versions": meta.versions.len(),
        })),
        Err(e) => error_json(400, &e),
    })
}
