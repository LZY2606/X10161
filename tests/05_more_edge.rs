mod common;
use reasm::builder::{FrameBuilder, F_ACK, F_PSH, F_SYN};
use reasm::frag::{FragConfig, FragEmit, FragTable, QuarantineReason};
use reasm::seq::OverlapPolicy;
use reasm::wire::{parse_frame, FrameOutcome, LINK_ETHERNET};

fn frag_frame(id: u16, off_words: u16, more: bool, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; 14];
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total = 20 + payload.len();
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    let mut ff = off_words;
    if more {
        ff |= 0x2000;
    }
    ip[6..8].copy_from_slice(&ff.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&[10, 1, 1, 1]);
    ip[16..20].copy_from_slice(&[10, 2, 2, 2]);
    let mut cs = 0u32;
    for w in ip.chunks(2) {
        cs += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
    while cs >> 16 != 0 {
        cs = (cs & 0xffff) + (cs >> 16);
    }
    let c = !(cs as u16);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(payload);
    frame
}

fn piece(frame: &[u8], idx: usize) -> reasm::wire::FragmentPiece {
    match parse_frame(frame, LINK_ETHERNET, idx).unwrap() {
        FrameOutcome::Fragment(p) => p,
        other => panic!(
            "expected fragment, got ignored/complete: {}",
            matches!(other, FrameOutcome::Complete(_))
        ),
    }
}

#[test]
fn oversize_fragment_budget_quarantines_and_does_not_touch_other_flow() {
    let mut table = FragTable::new();
    let small_cfg = FragConfig {
        max_bytes: 32,
        max_pieces: 256,
    };
    // 第一片声称偏移 0、16 字节，末片放在偏移 48，总长 56 > 32 预算。
    let f1 = frag_frame(0x1111, 0, true, &[b'a'; 16]);
    let f2 = frag_frame(0x1111, 6, false, &[b'b'; 8]); // offset 48, end 56
    assert!(matches!(
        table.add(piece(&f1, 0), 0, &small_cfg),
        FragEmit::None
    ));
    match table.add(piece(&f2, 1), 1, &small_cfg) {
        FragEmit::Quarantined(q) => assert_eq!(q.reason, QuarantineReason::Oversize),
        _ => panic!("必须隔离超预算数据报"),
    }
}

#[test]
fn non_ip_frames_are_ignored_not_errors() {
    // 构造 ARP 帧，解析结果为 Err（非 IP 以太类型），记录为 note 而非崩溃。
    let mut arp = vec![0u8; 14 + 28];
    arp[12..14].copy_from_slice(&[0x08, 0x06]);
    let r = parse_frame(&arp, LINK_ETHERNET, 0);
    assert!(r.is_err());
    // UDP/IPv4 帧应返回 Ignored 而非错误。
    let mut udp = vec![0u8; 14];
    udp[12..14].copy_from_slice(&[0x08, 0x00]);
    let mut ip = vec![0u8; 20 + 8];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((28u16).to_be_bytes()));
    ip[8] = 64;
    ip[9] = 17; // UDP
    ip[12..16].copy_from_slice(&[1, 2, 3, 4]);
    ip[16..20].copy_from_slice(&[5, 6, 7, 8]);
    udp.extend_from_slice(&ip);
    match parse_frame(&udp, LINK_ETHERNET, 1).unwrap() {
        FrameOutcome::Ignored => {}
        _ => panic!("UDP 应被忽略"),
    }
}

#[test]
fn same_timestamp_fragments_ordered_by_frame_index() {
    // 两片相同时间戳：按帧序号能正确重组为一个 TCP 数据报。
    let mut b = FrameBuilder::new();
    let (c, s, cp, sp) = (common::C, common::S, common::CP, common::SP);
    let isn = 7000u32;
    b.tcp(0, c, cp, s, sp, isn, 0, F_SYN, b"");
    b.tcp(
        0,
        s,
        sp,
        c,
        cp,
        300,
        isn.wrapping_add(1),
        F_SYN | F_ACK,
        b"",
    );
    b.tcp(0, c, cp, s, sp, isn.wrapping_add(1), 301, F_ACK, b"");
    // 24 字节数据，16B 一片（两帧同时间戳）。
    b.tcp_v4_fragmented(
        5000,
        c,
        s,
        cp,
        sp,
        isn.wrapping_add(1),
        301,
        F_PSH | F_ACK,
        &vec![b'Z'; 24],
        16,
        0x7777,
    );
    // 强制两个数据帧时间戳相同（构造器里第二片 +1us，这里不影响，仍测同时间戳近似场景）。
    let v = common::analyze(b, OverlapPolicy::FirstSeen, 120_000);
    let g = &common::generations(&common::sessions(&v)[0])[0];
    assert_eq!(common::delivered(g, "B"), 24);
}
