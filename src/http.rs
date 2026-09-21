//! 零依赖本地 HTTP 服务（thread-per-connection）。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::json::Value;
use crate::session::{Params, Policy};
use crate::store::Store;

const UI_HTML: &str = include_str!("ui.html");

struct Request {
    method: String,
    #[allow(dead_code)]
    target: String,
    path: String,
    body: Vec<u8>,
}

pub fn serve(addr: &str, store: Arc<Store>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("网络会话重组台 已启动: http://{}", addr);
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    if let Err(e) = handle(stream, &store) {
                        eprintln!("connection error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
    Ok(())
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Request> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 64 * 1024 * 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "headers too large"));
        }
    }
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
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
    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[body_start..body_start + content_length].to_vec();
    let path = target.split('?').next().unwrap_or("/").to_string();
    Ok(Request {
        method,
        target,
        path,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn handle(mut stream: TcpStream, store: &Store) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };

    match route(&req, store) {
        Ok(resp) => write_response(&mut stream, resp),
        Err((status, msg)) => {
            write_response(
                &mut stream,
                Response {
                    status,
                    content_type: "text/plain; charset=utf-8".into(),
                    body: msg.into_bytes(),
                    download: None,
                },
            )
        }
    }
}

struct Response {
    status: u16,
    content_type: String,
    body: Vec<u8>,
    download: Option<String>,
}

fn ok_json(v: Value) -> Response {
    Response {
        status: 200,
        content_type: "application/json; charset=utf-8".into(),
        body: v.serialize().into_bytes(),
        download: None,
    }
}

fn err(status: u16, msg: impl Into<String>) -> Result<Response, (u16, String)> {
    Err((status, msg.into()))
}

fn write_response(stream: &mut TcpStream, resp: Response) -> std::io::Result<()> {
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
        resp.status,
        reason,
        resp.content_type,
        resp.body.len()
    );
    if let Some(name) = resp.download {
        head.push_str(&format!(
            "Content-Disposition: attachment; filename=\"{}\"\r\n",
            name
        ));
    }
    head.push_str("Access-Control-Allow-Origin: *\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&resp.body)?;
    stream.flush()
}

fn route(req: &Request, store: &Store) -> Result<Response, (u16, String)> {
    let path = req.path.as_str();
    match (&req.method[..], path) {
        ("GET", "/") => Ok(Response {
            status: 200,
            content_type: "text/html; charset=utf-8".into(),
            body: UI_HTML.as_bytes().to_vec(),
            download: None,
        }),
        ("GET", "/api/health") => {
            let mut o = Value::obj();
            o.set("ok", Value::Bool(true));
            o.set("title", Value::Str("网络会话重组台".into()));
            Ok(ok_json(o))
        }
        ("GET", "/api/corpora") => {
            let mut arr = Vec::new();
            for c in store.list_corpora() {
                let mut o = Value::obj();
                o.set("id", Value::Str(c.id));
                o.set("frame_count", Value::Int(c.frame_count as i128));
                arr.push(o);
            }
            Ok(ok_json(Value::Arr(arr)))
        }
        ("POST", "/api/import") => {
            let meta = store
                .import(&req.body)
                .map_err(|e| (400, format!("import failed: {}", e)))?;
            let mut o = Value::obj();
            o.set("corpus_id", Value::Str(meta.id));
            o.set("frame_count", Value::Int(meta.frame_count as i128));
            Ok(ok_json(o))
        }
        ("POST", "/api/analyze") => {
            let body = std::str::from_utf8(&req.body).map_err(|e| (400, e.to_string()))?;
            let req_json = Value::parse(body).map_err(|e| (400, e))?;
            let corpus_id = req_json
                .get("corpus_id")
                .and_then(|v| v.as_str())
                .ok_or((400, "missing corpus_id".to_string()))?;
            let policy = req_json
                .get("policy")
                .and_then(|v| v.as_str())
                .map(Policy::from_name)
                .unwrap_or(Policy::FirstSeen);
            let timeout_ns = req_json
                .get("timeout_ns")
                .and_then(|v| v.as_u64())
                .unwrap_or(120_000_000_000);
            let params = Params {
                policy,
                timeout_ns,
                frag: Default::default(),
            };
            let meta = store
                .analyze(corpus_id, params)
                .map_err(|e| (500, format!("analyze failed: {}", e)))?;
            let mut o = Value::obj();
            o.set("analysis_id", Value::Str(meta.id));
            o.set("corpus_id", Value::Str(meta.corpus_id));
            o.set("fingerprint", Value::Str(meta.fingerprint));
            o.set("session_count", Value::Int(meta.session_count as i128));
            Ok(ok_json(o))
        }
        ("GET", "/api/analyses") => {
            let mut arr = Vec::new();
            for a in store.list_analyses() {
                let mut o = Value::obj();
                o.set("id", Value::Str(a.id));
                o.set("corpus_id", Value::Str(a.corpus_id));
                o.set("fingerprint", Value::Str(a.fingerprint));
                o.set("created_at_ns", Value::Int(a.created_at_ns as i128));
                o.set("policy", Value::Str(a.policy));
                o.set("session_count", Value::Int(a.session_count as i128));
                arr.push(o);
            }
            Ok(ok_json(Value::Arr(arr)))
        }
        _ => route_nested(req, store),
    }
}

fn route_nested(req: &Request, store: &Store) -> Result<Response, (u16, String)> {
    let parts: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();
    match parts.as_slice() {
        ["api", "analysis", id, "evidence.json"] if req.method == "GET" => {
            let evidence = store
                .read_evidence(id)
                .map_err(|e| (404, format!("analysis not found: {}", e)))?;
            Ok(Response {
                status: 200,
                content_type: "application/json; charset=utf-8".into(),
                body: evidence.serialize().into_bytes(),
                download: Some(format!("evidence_{}.json", &id[..12])),
            })
        }
        ["api", "analysis", id, "stream", sid, dir] if req.method == "GET" => {
            let sid: usize = sid.parse().map_err(|_| (400, "bad session id".into()))?;
            let dir: usize = dir.parse().map_err(|_| (400, "bad direction".into()))?;
            let data = store
                .read_stream(id, sid, dir)
                .map_err(|e| (404, format!("stream not found: {}", e)))?;
            Ok(Response {
                status: 200,
                content_type: "application/octet-stream".into(),
                body: data,
                download: Some(format!("stream_{}_dir{}.bin", sid, dir)),
            })
        }
        ["api", "analysis", id] if req.method == "GET" => {
            let evidence = store
                .read_evidence(id)
                .map_err(|e| (404, format!("analysis not found: {}", e)))?;
            Ok(ok_json(evidence))
        }
        _ => err(404, "not found"),
    }
}
