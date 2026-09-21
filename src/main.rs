//! 网络会话重组台 —— 本地离线服务入口。
//!
//! 用法：pwgsb --addr 127.0.0.1:5235 [--data-dir ./data]
//! 不调用系统抓包权限，不读取实时网卡。

use std::sync::Arc;

use pwgsb::http;
use pwgsb::store::Store;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:5235".to_string();
    let mut data_dir = "data".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                if i < args.len() {
                    addr = args[i].clone();
                }
            }
            "--data-dir" => {
                i += 1;
                if i < args.len() {
                    data_dir = args[i].clone();
                }
            }
            "-h" | "--help" => {
                println!("用法: pwgsb --addr 127.0.0.1:5235 [--data-dir data]");
                return;
            }
            other => {
                eprintln!("未知参数: {}", other);
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let store = match Store::open(&data_dir) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("初始化数据目录 {} 失败: {}", data_dir, e);
            std::process::exit(1);
        }
    };

    if let Err(e) = http::serve(&addr, store) {
        eprintln!("服务退出: {}", e);
        std::process::exit(1);
    }
}
