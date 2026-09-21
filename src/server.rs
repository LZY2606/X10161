//! 本地 HTTP 服务：纯标准库，线程处理连接，不访问任何网卡。

use crate::json::{parse, pretty, Value};
use crate::seq::OverlapPolicy;
use crate::store::Store;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;

const INDEX_HTML: &str = include_str!("../web/index.html");

pub fn serve(addr: &str, data_dir: &str) -> std::io::Result<()> {
    let store = Arc::new(Store::open(Path::new(data_dir))?);
    let listener = TcpListener::bind(addr)?;
    println!("网络会话重组台已启动: http://{}", addr);
    println!("数据目录: {}", data_dir);
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    let _ = handle(stream, store);
                });
            }
            Err(_) => continue,
        }
    }
    Ok(())
}

struct Response {
    status: u16,
    content_type: String,
    body: Vec<u8>,
    extra_headers: Vec<(String, String)>,
    filename: Option<String>,
}

impl Response {
    fn ok(body: impl Into<Vec<u8>>, content_type: &str) -> Response {
        Response {
            status: 200,
            content_type: content_type.to_string(),
            body: body.into(),
            extra_headers: Vec::new(),
            filename: None,
        }
    }

    fn json(v: &Value) -> Response {
        Response::ok(pretty(v), "application/json; charset=utf-8")
    }

    fn error(status: u16, msg: &str) -> Response {
        let v = Value::obj(vec![("error", Value::Str(msg.to_string()))]);
        Response {
            status,
            content_type: "application/json; charset=utf-8".to_string(),
            body: pretty(&v).into_bytes(),
            extra_headers: Vec::new(),
            filename: None,
        }
    }

    fn attachment(mut self, filename: String) -> Response {
        self.filename = Some(filename);
        self
    }

    fn write_to(&self, w: &mut dyn Write) -> std::io::Result<()> {
        let reason = match self.status {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            413 => "Payload Too Large",
            500 => "Internal Server Error",
            _ => "OK",
        };
        write!(w, "HTTP/1.1 {} {}\r\n", self.status, reason)?;
        write!(w, "Content-Type: {}\r\n", self.content_type)?;
        write!(w, "Content-Length: {}\r\n", self.body.len())?;
        write!(w, "Cache-Control: no-store\r\n")?;
        for (k, v) in &self.extra_headers {
            write!(w, "{}: {}\r\n", k, v)?;
        }
        if let Some(name) = &self.filename {
            write!(
                w,
                "Content-Disposition: attachment; filename=\"{}\"\r\n",
                name.replace('"', "_")
            )?;
        }
        write!(w, "Connection: close\r\n\r\n")?;
        w.write_all(&self.body)?;
        Ok(())
    }
}

fn handle(mut stream: TcpStream, store: Arc<Store>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut header_end = None;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            header_end = Some(pos);
            break;
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }
    let header_end = match header_end {
        Some(p) => p,
        None => return Ok(()),
    };
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let target = parts.next().unwrap_or("/");

    let mut content_length = 0usize;
    let mut content_type = String::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            match k.as_str() {
                "content-length" => content_length = v.parse().unwrap_or(0),
                "content-type" => content_type = v.to_string(),
                _ => {}
            }
        }
    }

    const MAX_UPLOAD: usize = 256 * 1024 * 1024;
    if content_length > MAX_UPLOAD {
        let _ = Response::error(413, "上传过大").write_to(&mut stream);
        return Ok(());
    }
    let body_start = header_end + 4;
    let want_end = body_start.saturating_add(content_length);
    while buf.len() < want_end {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body_end = want_end.min(buf.len());
    let body = &buf[body_start..body_end];

    let resp = route(method, target, body, &content_type, &store);
    resp.write_to(&mut stream)?;
    stream.flush()
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

fn route(method: &str, target: &str, body: &[u8], content_type: &str, store: &Store) -> Response {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            Response::ok(INDEX_HTML, "text/html; charset=utf-8")
        }
        ("GET", "/api/health") => Response::json(&Value::obj(vec![
            ("ok", Value::Bool(true)),
            ("service", Value::Str("网络会话重组台".into())),
        ])),
        ("GET", "/api/captures") => {
            let list = store
                .list_captures()
                .into_iter()
                .map(|c| {
                    Value::obj(vec![
                        ("capture_id", Value::Str(c.capture_id)),
                        ("link_type", Value::Int(c.link_type as i64)),
                        ("frame_count", Value::Int(c.frame_count as i64)),
                        ("source_kind", Value::Str(c.source_kind)),
                        ("raw_bytes_hash", Value::Str(c.raw_bytes_hash)),
                    ])
                })
                .collect();
            Response::json(&Value::obj(vec![("captures", Value::Array(list))]))
        }
        ("GET", "/api/analyses") => {
            let cid = qparam(query, "capture_id");
            let list = store
                .list_analyses(cid.as_deref())
                .into_iter()
                .map(|a| analysis_meta_json(&a))
                .collect();
            Response::json(&Value::obj(vec![("analyses", Value::Array(list))]))
        }
        ("POST", "/api/captures") => upload_capture(body, content_type, store),
        ("POST", "/api/analyze") => create_analysis(body, store),
        ("GET", p) if p.starts_with("/api/evidence") => {
            let id = qparam(query, "id").unwrap_or_default();
            match store.read_evidence(&id) {
                Some(txt) => {
                    let mut r = Response::ok(txt, "application/json; charset=utf-8");
                    if qparam(query, "download").as_deref() == Some("1") {
                        r = r.attachment(format!("evidence-{}.json", &id[..12.min(id.len())]));
                    }
                    r
                }
                None => Response::error(404, "分析结果不存在"),
            }
        }
        ("GET", p) if p.starts_with("/api/stream") => {
            let id = qparam(query, "id").unwrap_or_default();
            let session = qparam(query, "session").unwrap_or_default();
            let dir = qparam(query, "dir").unwrap_or_default();
            match store.read_stream(&id, &session, &dir) {
                Some(bytes) => Response::ok(bytes, "application/octet-stream")
                    .attachment(format!("{}.{}.bin", session, dir)),
                None => Response::error(404, "重组字节不存在"),
            }
        }
        ("GET", p) if p.starts_with("/api/capture/source") => {
            let id = qparam(query, "id").unwrap_or_default();
            match store.capture_source_bytes(&id) {
                Some(bytes) => Response::ok(bytes, "application/vnd.tcpdump.pcap")
                    .attachment(format!("{}.pcap", &id[..12.min(id.len())])),
                None => Response::error(404, "抓包不存在"),
            }
        }
        ("GET", "/api/sample") => Response::ok(
            crate::sample::fixture_json_string(),
            "application/json; charset=utf-8",
        ),
        _ => Response::error(404, "未知接口"),
    }
}

fn analysis_meta_json(a: &crate::store::StoredAnalysis) -> Value {
    Value::obj(vec![
        ("analysis_id", Value::Str(a.analysis_id.clone())),
        ("capture_id", Value::Str(a.capture_id.clone())),
        ("fingerprint", Value::Str(a.fingerprint.clone())),
        ("overlap", Value::Str(a.overlap.clone())),
        ("idle_timeout_us", Value::Int(a.idle_timeout_us)),
        ("created_seq", Value::Int(a.created_seq as i64)),
    ])
}

fn qparam(query: &str, key: &str) -> Option<String> {
    query.split('&').filter(|s| !s.is_empty()).find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            Some(percent_decode(v))
        } else {
            None
        }
    })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let h = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(h, 16) {
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
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn upload_capture(body: &[u8], content_type: &str, store: &Store) -> Response {
    let data = if content_type.starts_with("multipart/form-data") {
        match extract_multipart_file(body, content_type) {
            Ok(d) => d,
            Err(e) => return Response::error(400, &e),
        }
    } else {
        body.to_vec()
    };
    match store.import_bytes(&data) {
        Ok(c) => Response::json(&Value::obj(vec![
            ("capture_id", Value::Str(c.capture_id)),
            ("link_type", Value::Int(c.link_type as i64)),
            ("frame_count", Value::Int(c.frame_count as i64)),
            ("source_kind", Value::Str(c.source_kind)),
            ("raw_bytes_hash", Value::Str(c.raw_bytes_hash)),
        ])),
        Err(e) => Response::error(400, &e),
    }
}

fn create_analysis(body: &[u8], store: &Store) -> Response {
    let v = match parse(&String::from_utf8_lossy(body)) {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e),
    };
    let capture_id = v.get("capture_id").and_then(|x| x.as_str()).unwrap_or("");
    let overlap_str = v
        .get("overlap")
        .and_then(|x| x.as_str())
        .unwrap_or("first-seen");
    let overlap = match OverlapPolicy::parse(overlap_str) {
        Some(o) => o,
        None => return Response::error(400, "overlap 必须为 first-seen 或 last-seen"),
    };
    let timeout = v
        .get("idle_timeout_us")
        .and_then(|x| x.as_i64())
        .unwrap_or(120_000_000);
    match store.analyze(capture_id, overlap, timeout) {
        Ok(a) => Response::json(&analysis_meta_json(&a)),
        Err(e) => Response::error(400, &e),
    }
}

/// 极简 multipart/form-data 解析：取第一个带文件名的分片内容。
fn extract_multipart_file(body: &[u8], content_type: &str) -> Result<Vec<u8>, String> {
    let boundary = content_type
        .split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("boundary="))
        .ok_or("multipart 缺少 boundary")?;
    let delim = format!("--{}", boundary);
    let body_str = body;
    // 定位 boundary
    let pos = find_subslice(body_str, delim.as_bytes()).ok_or("未找到 multipart 边界")?;
    let rest = &body[pos..];
    let header_end = find_subslice(rest, b"\r\n\r\n").ok_or("multipart 分片缺少头部")?;
    let headers = String::from_utf8_lossy(&rest[..header_end]);
    if !headers.to_ascii_lowercase().contains("filename=") {
        return Err("multipart 中没有文件".into());
    }
    let content_start = header_end + 4;
    let terminator = format!("\r\n--{}", boundary);
    let content_rel = find_subslice(&rest[content_start..], terminator.as_bytes())
        .ok_or("multipart 文件缺少结束边界")?;
    Ok(rest[content_start..content_start + content_rel].to_vec())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::qparam;
    #[test]
    fn query_parse() {
        assert_eq!(qparam("id=abc&dir=A", "dir").as_deref(), Some("A"));
        assert_eq!(qparam("id=a%2Eb", "id").as_deref(), Some("a.b"));
    }
}
