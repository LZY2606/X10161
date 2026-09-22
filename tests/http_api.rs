#![cfg(test)]
mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

use common::*;
use reasm::builder::Builder;
use reasm::json;

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

fn request(addr: &str, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    let head = format!(
        "{} {} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        method,
        path,
        body.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).unwrap();
    let split = find(&all, b"\r\n\r\n");
    let status = String::from_utf8_lossy(&all[..split.min(all.len())])
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    (status, all[split + 4..].to_vec())
}

fn find(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or(hay.len())
}

#[test]
fn http_upload_versions_and_frame_store() {
    let addr = free_addr();
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "reasm-test-{}-{}",
        std::process::id(),
        addr.replace(':', "-")
    ));
    let dirpb: PathBuf = dir.clone();
    let _ = std::fs::remove_dir_all(&dirpb);
    let a2 = addr.clone();
    let d2 = dirpb.clone();
    let handle = std::thread::spawn(move || {
        reasm::server::serve(&a2, d2).unwrap();
    });
    std::thread::sleep(std::time::Duration::from_millis(200));

    // title served
    let (st, body) = request(&addr, "GET", "/", &[]);
    assert_eq!(st, 200);
    assert!(String::from_utf8_lossy(&body).contains("网络会话重组台"));

    // build a fixture
    let mut b = Builder::new(1);
    hs(&mut b, 0, 100, 500);
    b.add(1000, c2s(101, 501, b"HTTPDATA", 1));
    let payload = json::to_string(&b.to_json()).into_bytes();

    // first-seen version
    let (st, body) = request(
        &addr,
        "POST",
        "/api/analyze?policy=first-seen&timeout_us=2000000",
        &payload,
    );
    assert_eq!(st, 200);
    let v1: serde_json_lite::Val = json::parse(&String::from_utf8_lossy(&body)).unwrap().into();
    let vid1 = v1.str_at(&["analysis", "version_id"]);
    assert!(!vid1.is_empty());

    // same request -> same immutable version id (content addressed, no overwrite)
    let (_, body) = request(
        &addr,
        "POST",
        "/api/analyze?policy=first-seen&timeout_us=2000000",
        &payload,
    );
    let v1b: serde_json_lite::Val = json::parse(&String::from_utf8_lossy(&body)).unwrap().into();
    assert_eq!(vid1, v1b.str_at(&["analysis", "version_id"]));

    // conflicting retransmission => last-seen creates a distinct version
    b.add(1100, c2s(101, 501, b"XTTPDATA", 2));
    let payload2 = json::to_string(&b.to_json()).into_bytes();
    let (_, b_fs) = request(
        &addr,
        "POST",
        "/api/analyze?policy=first-seen&timeout_us=2000000",
        &payload2,
    );
    let (_, b_ls) = request(
        &addr,
        "POST",
        "/api/analyze?policy=last-seen&timeout_us=2000000",
        &payload2,
    );
    let fs: serde_json_lite::Val = json::parse(&String::from_utf8_lossy(&b_fs)).unwrap().into();
    let ls: serde_json_lite::Val = json::parse(&String::from_utf8_lossy(&b_ls)).unwrap().into();
    assert_ne!(
        fs.str_at(&["analysis", "version_id"]),
        ls.str_at(&["analysis", "version_id"])
    );
    assert_eq!(
        fs.str_at(&["sessions", "0", "directions", "0", "data_utf8_lossy"]),
        "HTTPDATA"
    );
    assert_eq!(
        ls.str_at(&["sessions", "0", "directions", "0", "data_utf8_lossy"]),
        "XTTPDATA"
    );

    // versions lists both policies; old results still present
    let (_, body) = request(&addr, "GET", "/api/versions", &[]);
    let list = json::parse(&String::from_utf8_lossy(&body)).unwrap();
    let arr = list.as_array().unwrap();
    let policies: Vec<&str> = arr
        .iter()
        .map(|x| x.get("overlap_policy").unwrap().as_str().unwrap())
        .collect();
    assert!(policies.contains(&"first-seen"));
    assert!(policies.contains(&"last-seen"));

    // frame content addressing: fetch a frame by sha256
    let fsha = fs.str_at(&["sessions", "0", "segments", "3", "frame_sha256"]);
    assert_eq!(fsha.len(), 64);
    let (st, frame) = request(&addr, "GET", &format!("/api/frame?sha256={}", fsha), &[]);
    assert_eq!(st, 200);
    assert_eq!(common_sha(&frame), fsha);

    let _ = handle;
}

fn common_sha(b: &[u8]) -> String {
    reasm::hash::hex(&reasm::hash::sha256(b))
}

mod serde_json_lite {
    use reasm::json::Json;
    pub struct Val(pub Json);
    impl From<Json> for Val {
        fn from(j: Json) -> Self {
            Val(j)
        }
    }
    impl Val {
        pub fn str_at(&self, path: &[&str]) -> String {
            let mut cur = &self.0;
            for p in path {
                if let Ok(i) = p.parse::<usize>() {
                    cur = &cur.as_array().unwrap()[i];
                } else {
                    cur = cur.get(p).unwrap();
                }
            }
            cur.as_str().unwrap_or("").to_string()
        }
    }
}
