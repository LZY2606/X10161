use reasm_bench::server;
use std::path::PathBuf;

fn print_help() {
    println!(
        "网络会话重组台\n\n\
USAGE:\n    reasm-bench --addr <IP:PORT> [--data-dir <DIR>]\n\n\
OPTIONS:\n    \
--addr <IP:PORT>    Listen address (required), e.g. 127.0.0.1:5235\n    \
--data-dir <DIR>    Content store directory (default: ./reasm-data)\n    \
-h, --help           Show this help\n"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut addr: Option<String> = None;
    let mut data_dir = PathBuf::from("reasm-data");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--addr" => addr = iter.next().cloned(),
            "--data-dir" => {
                if let Some(v) = iter.next() {
                    data_dir = PathBuf::from(v);
                }
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_help();
                std::process::exit(2);
            }
        }
    }
    let addr = match addr {
        Some(a) => a,
        None => {
            eprintln!("error: --addr is required");
            print_help();
            std::process::exit(2);
        }
    };
    if let Err(e) = server::run(&addr, data_dir) {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
