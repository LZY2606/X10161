use std::path::PathBuf;

use reasm::server;

fn main() {
    let mut addr = "127.0.0.1:5235".to_string();
    let mut data_dir = PathBuf::from(".reasm-data");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--addr" => {
                if let Some(v) = args.next() {
                    addr = v;
                }
            }
            "--data-dir" => {
                if let Some(v) = args.next() {
                    data_dir = PathBuf::from(v);
                }
            }
            "-h" | "--help" => {
                eprintln!("usage: reasm [--addr 127.0.0.1:5235] [--data-dir .reasm-data]");
                return;
            }
            other => {
                eprintln!("unknown argument: {}", other);
                std::process::exit(2);
            }
        }
    }
    if let Err(e) = server::serve(&addr, data_dir) {
        eprintln!("server error: {}", e);
        std::process::exit(1);
    }
}
