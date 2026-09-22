use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::builder;
use crate::json::{self, Json};
use crate::storage::Store;
use crate::tcp::OverlapPolicy;

struct App {
    store: Store,
}

pub fn serve(addr: &str, data_dir: PathBuf) -> std::io::Result<()> {
    let store = Store::open(&data_dir)?;
    let app = Arc::new(Mutex::new(App { store }));
    let listener = TcpListener::bind(addr)?;
    eprintln!(
        "网络会话重组台 listening on http://{} (data dir {:?})",
        addr, data_dir
    );
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let app = app.clone();
                thread::spawn(move || {
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _ = handle(s, app);
                    }))
                    .is_err()
                    {
                        eprintln!("connection handler panicked; worker survived");
                    }
                });
            }
            Err(_) => continue,
        }
    }
    Ok(())
}

struct Request {
    method: String,
    path: String,
    query: String,
    body: Vec<u8>,
}

fn handle(mut stream: TcpStream, app: Arc<Mutex<App>>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut all = Vec::new();
    let mut buf = [0u8; 8192];
    // Read headers
    let header_end;
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        all.extend_from_slice(&buf[..n]);
        if let Some(p) = find_double_crlf(&all) {
            header_end = p;
            break;
        }
        if all.len() > 64 * 1024 * 1024 {
            return Ok(());
        }
    }
    let head = String::from_utf8_lossy(&all[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let reqline = lines.next().unwrap_or("");
    let mut parts = reqline.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/");
    let (path, query) = match target.find('?') {
        Some(i) => (target[..i].to_string(), target[i + 1..].to_string()),
        None => (target.to_string(), String::new()),
    };
    let mut content_length = 0usize;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = all[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_length);

    let req = Request {
        method,
        path,
        query,
        body,
    };
    let (status, ctype, out) = route(req, &app);
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        status,
        reason(status),
        ctype,
        out.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&out)?;
    stream.flush()?;
    Ok(())
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn json_response(v: &Json) -> (u16, &'static str, Vec<u8>) {
    (
        200,
        "application/json; charset=utf-8",
        json::to_string(v).into_bytes(),
    )
}

fn err_json(status: u16, msg: &str) -> (u16, &'static str, Vec<u8>) {
    let mut o = Json::obj();
    o.set("error", Json::Str(msg.into()));
    (
        status,
        "application/json; charset=utf-8",
        json::to_string(&o).into_bytes(),
    )
}

fn qget(q: &str, key: &str) -> Option<String> {
    for pair in q.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        if k == key {
            return Some(url_decode(v));
        }
    }
    None
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(h, 16).unwrap_or(0));
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn route(req: Request, app: &Arc<Mutex<App>>) -> (u16, &'static str, Vec<u8>) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => (
            200,
            "text/html; charset=utf-8",
            include_str!("../static/index.html").as_bytes().to_vec(),
        ),
        ("GET", "/api/health") => {
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("name", Json::Str("网络会话重组台".into()));
            json_response(&o)
        }
        ("GET", "/api/versions") => {
            let g = app.lock().unwrap();
            let mut arr = Vec::new();
            for a in g.store.list_versions() {
                let mut o = Json::obj();
                o.set("version_id", Json::Str(a.id));
                o.set("created_ts_us", Json::Num(a.created_ts_us));
                o.set("input_sha256", Json::Str(a.input_sha));
                o.set("overlap_policy", Json::Str(a.policy));
                o.set("timeout_us", Json::Num(a.timeout_us));
                o.set("result_sha256", Json::Str(a.result_sha));
                o.set("fingerprint", Json::Str(a.fingerprint));
                arr.push(o);
            }
            json_response(&Json::Arr(arr))
        }
        ("GET", "/api/version") => match qget(&req.query, "id") {
            Some(id) if !id.contains('/') && !id.contains("..") => {
                let g = app.lock().unwrap();
                let p = g.store.root().join("results").join(format!("{}.json", id));
                match std::fs::read(p) {
                    Ok(b) => (200, "application/json; charset=utf-8", b),
                    Err(_) => err_json(404, "version not found"),
                }
            }
            _ => err_json(400, "missing id"),
        },
        ("GET", "/api/frame") => match qget(&req.query, "sha256") {
            Some(sha) if sha.len() == 64 && sha.bytes().all(|c| c.is_ascii_hexdigit()) => {
                let g = app.lock().unwrap();
                let p = g.store.root().join("frames").join(format!("{}.bin", sha));
                match std::fs::read(p) {
                    Ok(b) => (200, "application/octet-stream", b),
                    Err(_) => err_json(404, "frame not found"),
                }
            }
            _ => err_json(400, "bad sha256"),
        },
        ("GET", "/api/demo") => {
            let name = qget(&req.query, "scenario").unwrap_or_else(|| "wrap".into());
            let data = demo_fixture(&name);
            (200, "application/json; charset=utf-8", data.into_bytes())
        }
        ("GET", "/api/demo-list") => {
            let names = [
                "wrap",
                "retrans",
                "outoforder",
                "gap",
                "reuse",
                "midcap",
                "finrst",
                "frag_overlap",
                "same_ts",
                "mixed",
            ];
            let arr = names.iter().map(|n| Json::Str((*n).into())).collect();
            json_response(&Json::Arr(arr))
        }
        ("POST", "/api/analyze") => {
            let policy = OverlapPolicy::parse(
                &qget(&req.query, "policy").unwrap_or_else(|| "first-seen".into()),
            );
            let timeout = qget(&req.query, "timeout_us")
                .and_then(|x| x.parse::<i128>().ok())
                .unwrap_or(2_000_000);
            let g = app.lock().unwrap();
            match g.store.save_input(&req.body).and_then(|(id, _)| Ok(id)) {
                Ok(input_id) => {
                    match g.store.analyze_version(
                        &input_id,
                        &req.body,
                        policy,
                        timeout,
                        crate::storage::now_us(),
                    ) {
                        Ok(a) => {
                            let bytes = std::fs::read(&a.path).unwrap_or_default();
                            (200, "application/json; charset=utf-8", bytes)
                        }
                        Err(e) => err_json(400, &e),
                    }
                }
                Err(e) => err_json(500, &e.to_string()),
            }
        }
        _ => err_json(404, "not found"),
    }
}

// ---------- Demo fixture generation (deterministic constructors) ----------

fn demo_fixture(name: &str) -> String {
    use crate::model::{ACK, FIN, PSH, RST, SYN};
    use builder::{data, flags, handshake, tcp_packet, tcp_packet_frag, Builder};
    let c = "10.0.0.1";
    let s = "10.0.0.2";
    let (cp, sp) = (40000u16, 80u16);
    let mut b = Builder::new(1);
    match name {
        "wrap" => {
            // Sequence number wrap across the 32-bit boundary.
            let isn = u32::MAX - 4;
            let mut t = handshake(&mut b, 0, c, cp, s, sp, isn, 1000);
            let seqc = isn.wrapping_add(1);
            let payload = b"0123456789ABCDEF";
            t = data(&mut b, t, c, cp, s, sp, seqc, 1001, payload, 200);
            let ack = seqc.wrapping_add(payload.len() as u32);
            flags(&mut b, t, s, sp, c, cp, 1001, ack, ACK, 201);
        }
        "retrans" => {
            let mut t = handshake(&mut b, 0, c, cp, s, sp, 100, 500);
            let p = b"HELLO";
            t = data(&mut b, t, c, cp, s, sp, 101, 501, p, 300);
            // identical retransmission
            data(&mut b, t, c, cp, s, sp, 101, 501, p, 301);
            // conflicting retransmission: first byte differs
            let mut p2 = p.to_vec();
            p2[0] = b'X';
            data(&mut b, t + 100, c, cp, s, sp, 101, 501, &p2, 302);
        }
        "outoforder" => {
            let t = handshake(&mut b, 0, c, cp, s, sp, 100, 500);
            let _ = t;
            // segments arrive out of order: [10..20], [20..30], then [0..10]
            b.add(
                1000,
                tcp_packet(c, cp, s, sp, 111, 501, ACK | PSH, b"KLMNOPQRST", 400),
            );
            b.add(
                1100,
                tcp_packet(c, cp, s, sp, 121, 501, ACK | PSH, b"UVWXYZabcd", 401),
            );
            b.add(
                1200,
                tcp_packet(c, cp, s, sp, 101, 501, ACK | PSH, b"ABCDEFGHIJ", 402),
            );
        }
        "gap" => {
            let t = handshake(&mut b, 0, c, cp, s, sp, 100, 500);
            let _ = t;
            // [0..5], then [20..25] -> a 15 byte gap
            b.add(
                1000,
                tcp_packet(c, cp, s, sp, 101, 501, ACK | PSH, b"AAAAA", 500),
            );
            b.add(
                1100,
                tcp_packet(c, cp, s, sp, 121, 501, ACK | PSH, b"BBBBB", 501),
            );
        }
        "reuse" => {
            // Generation 1: full connection that closes.
            let mut t = handshake(&mut b, 0, c, cp, s, sp, 100, 500);
            t = data(&mut b, t, c, cp, s, sp, 101, 501, b"first", 600);
            t = flags(&mut b, t, c, cp, s, sp, 106, 501, FIN | ACK, 601);
            t = flags(&mut b, t, s, sp, c, cp, 501, 107, FIN | ACK, 602);
            // Generation 2: same four-tuple reused after close.
            let mut t2 = t + 1000;
            t2 = {
                let x = t2;
                b.add(x, tcp_packet(c, cp, s, sp, 900, 0, SYN, &[], 700));
                x + 100
            };
            b.add(t2, tcp_packet(s, sp, c, cp, 9000, 901, SYN | ACK, &[], 701));
            let t3 = t2 + 100;
            b.add(
                t3,
                tcp_packet(c, cp, s, sp, 901, 9001, ACK | PSH, b"second-conn", 702),
            );
        }
        "midcap" => {
            // No handshake; capture starts in the middle of a session.
            b.add(
                1000,
                tcp_packet(c, cp, s, sp, 777, 10, ACK | PSH, b"mid-stream-data", 800),
            );
            b.add(
                1100,
                tcp_packet(s, sp, c, cp, 10, 792, ACK | PSH, b"reply", 801),
            );
        }
        "finrst" => {
            // FIN and RST race in the same direction at different frames.
            let mut t = handshake(&mut b, 0, c, cp, s, sp, 100, 500);
            t = data(&mut b, t, c, cp, s, sp, 101, 501, b"bye", 900);
            flags(&mut b, t, c, cp, s, sp, 104, 501, FIN | ACK, 901);
            flags(&mut b, t + 50, c, cp, s, sp, 104, 501, RST | ACK, 902);
        }
        "frag_overlap" => {
            // IPv4 fragmented TCP datagram with overlapping fragments.
            let t = handshake(&mut b, 0, c, cp, s, sp, 100, 500);
            let _ = t;
            // First fragment: IP+TCP header + 8 bytes (offset 0, MF)
            let f0 = tcp_packet_frag(
                c,
                cp,
                s,
                sp,
                101,
                501,
                ACK | PSH,
                b"FRAG0001",
                950,
                Some((0, true)),
            );
            let f1 = tcp_packet_frag(c, cp, s, sp, 0, 0, 0, b"OVERLAP!!", 950, Some((8, true)));
            // overlaps with previous region (offset 8, but content re-covers byte 8..16)
            let f_bad = tcp_packet_frag(c, cp, s, sp, 0, 0, 0, b"XX", 950, Some((14, false)));
            b.add(2000, f0);
            b.add(2100, f1);
            b.add(2200, f_bad);
            // A clean, separate session remains unaffected.
            b.add(
                2300,
                tcp_packet(
                    "10.0.0.3",
                    5000,
                    "10.0.0.4",
                    81,
                    1,
                    1,
                    ACK | PSH,
                    b"clean",
                    960,
                ),
            );
        }
        "same_ts" => {
            // Identical timestamps: ordering must follow original frame index.
            let t = 0i128;
            b.add(t, tcp_packet(c, cp, s, sp, 100, 0, SYN, &[], 1000));
            b.add(t, tcp_packet(s, sp, c, cp, 500, 101, SYN | ACK, &[], 1001));
            b.add(t, tcp_packet(c, cp, s, sp, 101, 501, ACK, &[], 1002));
            b.add(
                t,
                tcp_packet(c, cp, s, sp, 101, 501, ACK | PSH, b"AAA", 1003),
            );
            b.add(
                t,
                tcp_packet(c, cp, s, sp, 104, 501, ACK | PSH, b"BBB", 1004),
            );
        }
        _ => {
            // "mixed": gap then fill + conflicting overlap across two directions.
            let t = handshake(&mut b, 0, c, cp, s, sp, 100, 500);
            b.add(
                t,
                tcp_packet(c, cp, s, sp, 121, 501, ACK | PSH, b"later", 1100),
            );
            b.add(
                t + 100,
                tcp_packet(c, cp, s, sp, 101, 501, ACK | PSH, b"first", 1101),
            );
            // conflicting retransmission of "first" (last byte changed)
            b.add(
                t + 200,
                tcp_packet(c, cp, s, sp, 101, 501, ACK | PSH, b"firsX", 1102),
            );
            b.add(
                t + 300,
                tcp_packet(s, sp, c, cp, 501, 126, ACK | PSH, b"resp", 1103),
            );
            flags(&mut b, t + 400, c, cp, s, sp, 126, 505, FIN | ACK, 1104);
            flags(&mut b, t + 500, s, sp, c, cp, 505, 127, FIN | ACK, 1105);
        }
    }
    b.to_json_string()
}
