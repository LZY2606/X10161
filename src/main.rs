use reasm::server;
use reasm::store::Store;

fn main() {
    let mut addr = "127.0.0.1:5235".to_string();
    let mut data = "data".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => {
                addr = args.next().unwrap_or_else(|| {
                    eprintln!("--addr requires a value");
                    std::process::exit(2);
                });
            }
            "--data" => {
                data = args.next().unwrap_or_else(|| {
                    eprintln!("--data requires a value");
                    std::process::exit(2);
                });
            }
            "-h" | "--help" => {
                println!("session-reassembly --addr 127.0.0.1:5235 [--data DIR]");
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let store = match Store::new(&data) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot open data dir {data}: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = server::run(&addr, store) {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
