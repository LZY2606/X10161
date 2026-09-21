//! 演示夹具：一个连接内同时含正常字节、乱序、重传、重叠与缺口，
//! 外加一个优雅关闭的短连接。

use crate::builder::{FrameBuilder, F_ACK, F_FIN, F_PSH, F_SYN};
use crate::json::Value;
use crate::pcap::RawFrame;

fn hex(b: &[u8]) -> String {
    crate::hash::hex(b)
}

pub fn raw_frames() -> Vec<RawFrame> {
    let mut b = FrameBuilder::new();
    let (c, s) = ("10.0.0.1", "10.0.0.2");
    let (cp, sp) = (40001u16, 80u16);

    // 三次握手，ISN 设在环绕边界附近以演示 32 位序号。
    b.tcp(1_000_000, c, cp, s, sp, 0xffff_fff0, 0, F_SYN, b"");
    b.tcp(
        1_010_000,
        s,
        sp,
        c,
        cp,
        1000,
        0xffff_fff1,
        F_SYN | F_ACK,
        b"",
    );
    b.tcp(1_020_000, c, cp, s, sp, 0xffff_fff1, 1001, F_ACK, b"");

    // 数据：先到 [0,5)，再乱序到 [10,15) 形成缺口，随后补缺 [5,10)。
    b.tcp(
        1_100_000,
        c,
        cp,
        s,
        sp,
        0xffff_fff1,
        1001,
        F_PSH | F_ACK,
        b"AAAAA",
    );
    b.tcp(1_200_000, c, cp, s, sp, 0xffff_fffb, 1001, F_ACK, b"KKKKK");
    b.tcp(
        1_300_000,
        c,
        cp,
        s,
        sp,
        0xffff_fff6,
        1001,
        F_PSH | F_ACK,
        b"BBBBB",
    );
    // 完全重传（字节相同）。
    b.tcp(1_400_000, c, cp, s, sp, 0xffff_fff1, 1001, F_ACK, b"AAAAA");
    // 重叠且字节不同：[3..5)，证据保留两种值，first-seen 默认保留 A。
    b.tcp(1_500_000, c, cp, s, sp, 0xffff_fff4, 1001, F_ACK, b"XX");

    // 服务端返回 3 字节。
    b.tcp(
        1_600_000,
        s,
        sp,
        c,
        cp,
        1001,
        0x0000_0010,
        F_PSH | F_ACK,
        b"hi!",
    );

    // 优雅关闭。
    b.tcp(
        1_700_000,
        c,
        cp,
        s,
        sp,
        0x0000_0010,
        1004,
        F_FIN | F_ACK,
        b"",
    );
    b.tcp(
        1_800_000,
        s,
        sp,
        c,
        cp,
        1004,
        0x0000_0011,
        F_FIN | F_ACK,
        b"",
    );
    b.tcp(1_900_000, c, cp, s, sp, 0x0000_0011, 1005, F_ACK, b"");

    b.into_raw()
}

pub fn fixture_json() -> Value {
    let frames = raw_frames()
        .into_iter()
        .map(|f| {
            Value::obj(vec![
                ("us", Value::Int(f.ts_us)),
                ("hex", Value::Str(hex(&f.data))),
            ])
        })
        .collect();
    Value::obj(vec![
        ("format", Value::Str("reasm-fixture/1".into())),
        ("link_type", Value::Str("ethernet".into())),
        ("frames", Value::Array(frames)),
    ])
}

pub fn fixture_json_string() -> String {
    crate::json::pretty(&fixture_json())
}
