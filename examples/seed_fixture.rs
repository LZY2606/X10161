//! 生成一份覆盖多种场景的演示夹具：
//!   cargo run --example seed_fixture > demo-fixture.json
//!
//! 场景：序号环绕 + 重传 + 乱序 + 缺口；同四元组复用两代次；
//! 中途抓取 partial；IPv4 重叠分片隔离；相同时间戳。

use pwgsb::builder::*;
use pwgsb::fixture;
use pwgsb::model::Frame;

const C: [u8; 4] = [10, 0, 0, 1];
const S: [u8; 4] = [10, 0, 0, 2];

fn push(out: &mut Vec<Frame>, ts: u64, raw: Vec<u8>) {
    out.push(Frame {
        index: out.len() as u32,
        ts_ns: ts * 1_000_000,
        raw,
    });
}

fn main() {
    let mut f: Vec<Frame> = Vec::new();

    // 会话 1：环绕 ISN，重传、乱序、缺口
    push(&mut f, 1, syn(C, S, 4000, 80, 0xffff_fff8));
    push(&mut f, 2, synack(S, C, 80, 4000, 0x1000, 0xffff_fff9));
    push(&mut f, 3, pure_ack(C, S, 4000, 80, 0xffff_fff9, 0x1001));
    push(&mut f, 4, ack_bytes(C, S, 4000, 80, 0xffff_fff9, 0x1001, b"AAAA"));
    push(&mut f, 5, ack_bytes(C, S, 4000, 80, 0x0000_0003, 0x1001, b"CC")); // 乱序且绕回
    push(&mut f, 6, ack_bytes(C, S, 4000, 80, 0xffff_fffd, 0x1001, b"\x00\x00\x00\x00BB")); // 填补，绕回
    push(&mut f, 7, ack_bytes(C, S, 4000, 80, 0xffff_fff9, 0x1001, b"AAAA")); // 完全重传
    push(&mut f, 8, ack_bytes(C, S, 4000, 80, 0x100, 0x1001, b"later-gap")); // 造成缺口
    push(&mut f, 9, pure_ack(S, C, 80, 4000, 0x1001, 0xffff_fff9));
    push(&mut f, 10, fin_ack(C, S, 4000, 80, 0x10a, 0x1001));
    push(&mut f, 11, fin_ack(S, C, 80, 4000, 0x1001, 0x10b));

    // 同四元组复用：新代次
    push(&mut f, 12, syn(C, S, 4000, 80, 0x5000));
    push(&mut f, 13, synack(S, C, 80, 4000, 0x6000, 0x5001));
    push(&mut f, 14, pure_ack(C, S, 4000, 80, 0x5001, 0x6001));
    push(&mut f, 15, ack_bytes(C, S, 4000, 80, 0x5001, 0x6001, b"second generation"));

    // 另一条会话：中途抓取（无握手）
    push(&mut f, 16, ack_bytes([10, 2, 0, 1], [10, 2, 0, 2], 9000, 80, 0x9000, 0x1, b"partial capture"));

    // IPv4 重叠分片 -> 数据报隔离
    let dgram = tcp_datagram(4000, 80, 1, 1, 0x18, b"isolated-bytes-here");
    push(&mut f, 17, ipv4_fragment(C, S, 0x4242, 0, true, &dgram[0..24]));
    push(&mut f, 18, ipv4_fragment(C, S, 0x4242, 16, false, &dgram[16..]));

    // 相同时间戳：帧序号决定顺序
    push(&mut f, 20, ack_bytes([10, 3, 0, 1], [10, 3, 0, 2], 5555, 80, 1, 1, b"same-ts "));
    push(&mut f, 20, ack_bytes([10, 3, 0, 1], [10, 3, 0, 2], 5555, 80, 9, 1, b"ordering"));

    print!("{}", fixture::build_fixture(&f));
}
