mod common;
use common::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn temp_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "reasm-bench-server-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn http_get(addr: &str, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();
    let status = buf.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, buf)
}

#[test]
fn server_serves_ui_and_api_end_to_end() {
    let dir = temp_dir();
    let addr = format!("127.0.0.1:{}", pick_port());
    let addr_clone = addr.clone();
    let dir_clone = dir.clone();
    let handle = std::thread::spawn(move || {
        reasm_bench::server::run(&addr_clone, dir_clone).unwrap();
    });
    // Wait for listen.
    let mut ready = false;
    for _ in 0..50 {
        if TcpStream::connect(&addr).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "server did not start");

    let (status, body) = http_get(&addr, "/");
    assert_eq!(status, 200);
    let body_start = body.split("\r\n\r\n").nth(1).unwrap_or("");
    assert!(body_start.contains("网络会话重组台"), "UI title present");

    let (status, health) = http_get(&addr, "/api/health");
    assert_eq!(status, 200);
    assert!(health.contains("网络会话重组台"));

    let (status, datasets) = http_get(&addr, "/api/datasets");
    assert_eq!(status, 200);
    assert!(datasets.contains('['));

    // Upload a JSON fixture over multipart and verify analysis is reachable.
    let mut specs = handshake(0.0, 100, 500);
    specs.push(spec(0.03, 101, Some(501), PA, b"smoke"));
    let fixture_frames = build_frames(specs);
    let fixture_json = serde_json::to_string(&fixture_frames).unwrap();
    let dataset_id = post_raw_fixture(&addr, fixture_json);
    assert_eq!(dataset_id.len(), 16);

    let (status, analysis_body) = http_get(&addr, &format!("/api/datasets/{dataset_id}/versions/1"));
    assert_eq!(status, 200);
    let json = analysis_body.split("\r\n\r\n").nth(1).unwrap_or("");
    let result: reasm_bench::analyze::AnalysisResult = serde_json::from_str(json).unwrap();
    assert!(reasm_bench::analyze::FingerprintEnvelope::verify(&result));
    assert_eq!(result.sessions.len(), 1);

    // Creating a second policy version does not overwrite the first.
    post_analyze(&addr, &dataset_id, "last-seen", 120.0);
    let (status, meta_body) = http_get(&addr, &format!("/api/datasets/{dataset_id}"));
    assert_eq!(status, 200);
    let meta: reasm_bench::store::DatasetMeta =
        serde_json::from_str(meta_body.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(meta.versions.len(), 2);
    let v1 = std::fs::read(dir.join("datasets").join(&dataset_id).join("v1.json")).unwrap();
    assert!(String::from_utf8_lossy(&v1).contains("first-seen"));
    handle.thread().unpark();
}

fn pick_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn http_post(addr: &str, path: &str, content_type: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();
    let status = buf.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, buf)
}

fn post_raw_fixture(addr: &str, fixture_json: String) -> String {
    // Multipart form with a file part.
    let boundary = "----reasmtestboundary";
    let mut body = String::new();
    body.push_str(&format!("--{boundary}\r\n"));
    body.push_str("Content-Disposition: form-data; name=\"name\"\r\n\r\n");
    body.push_str("smoke fixture\r\n");
    body.push_str(&format!("--{boundary}\r\n"));
    body.push_str("Content-Disposition: form-data; name=\"file\"; filename=\"fixture.json\"\r\n");
    body.push_str("Content-Type: application/json\r\n\r\n");
    body.push_str(&fixture_json);
    body.push_str(&format!("\r\n--{boundary}--\r\n"));
    let (status, resp) = http_post(
        addr,
        "/api/datasets",
        &format!("multipart/form-data; boundary={boundary}"),
        &body,
    );
    assert_eq!(status, 200, "upload failed: {resp}");
    let json = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    v["dataset_id"].as_str().unwrap().to_string()
}

fn post_analyze(addr: &str, id: &str, policy: &str, timeout: f64) {
    let body = format!(r#"{{"overlap_policy":"{policy}","timeout_seconds":{timeout}}}"#);
    let (status, resp) = http_post(
        addr,
        &format!("/api/datasets/{id}/analyze"),
        "application/json",
        &body,
    );
    assert_eq!(status, 200, "analyze failed: {resp}");
}
