use std::process::ExitCode;

fn main() -> ExitCode {
    let mut addr = "127.0.0.1:5235".to_string();
    let mut data_dir = "reasm-data".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--addr" => addr = args.next().unwrap_or(addr),
            "--data-dir" => data_dir = args.next().unwrap_or(data_dir),
            "--help" | "-h" => {
                println!("用法: reasm --addr 127.0.0.1:5235 [--data-dir DIR]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("未知参数 {}", other);
                return ExitCode::FAILURE;
            }
        }
    }
    match reasm::server::serve(&addr, &data_dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("服务启动失败: {}", e);
            ExitCode::FAILURE
        }
    }
}
