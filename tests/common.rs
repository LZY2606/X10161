#![cfg(test)]
#![allow(dead_code)]
use reasm::analyze::{self, AnalysisOptions};
use reasm::builder::{self, Builder};
use reasm::capture;
use reasm::json::{self, Json};
use reasm::model::{ACK, FIN, PSH, RST, SYN};
use reasm::tcp::OverlapPolicy;

pub const C: &str = "10.0.0.1";
pub const S: &str = "10.0.0.2";
pub const CP: u16 = 40000;
pub const SP: u16 = 80;

pub fn analyze_json(bytes: &[u8], policy: OverlapPolicy) -> Json {
    let cap = capture::load(bytes).expect("load");
    analyze::run(
        &cap,
        &AnalysisOptions {
            policy,
            timeout_us: 2_000_000,
        },
    )
}
pub fn fixture_bytes(j: &Json) -> Vec<u8> {
    json::to_string(j).into_bytes()
}
pub fn sess<'a>(r: &'a Json, i: usize) -> &'a Json {
    &r.get("sessions").unwrap().as_array().unwrap()[i]
}
pub fn session_count(r: &Json) -> usize {
    r.get("sessions").unwrap().as_array().unwrap().len()
}
pub fn dir<'a>(s: &'a Json, d: usize) -> &'a Json {
    &s.get("directions").unwrap().as_array().unwrap()[d]
}
pub fn state(s: &Json) -> &str {
    s.get("state").unwrap().as_str().unwrap()
}
pub fn len_of(d: &Json) -> i128 {
    d.get("reassembled_length").unwrap().as_u64().unwrap() as i128
}
pub fn data_hex(d: &Json) -> String {
    d.get("data_hex").unwrap().as_str().unwrap().to_string()
}
pub fn seg_relations(s: &Json) -> Vec<String> {
    s.get("segments")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.get("relation").unwrap().as_str().unwrap().to_string())
        .collect()
}
pub fn conflicts(s: &Json) -> usize {
    s.get("segments")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| matches!(x.get("conflict"), Some(Json::Bool(true))))
        .count()
}
pub fn fp(r: &Json) -> String {
    analyze::fingerprint(r)
}
pub fn hs(b: &mut Builder, t: i128, isn_c: u32, isn_s: u32) -> i128 {
    builder::handshake(b, t, C, CP, S, SP, isn_c, isn_s)
}
pub fn pkt(
    src: &str,
    sp: u16,
    dst: &str,
    dp: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    pl: &[u8],
    id: u16,
) -> Vec<u8> {
    builder::tcp_packet(src, sp, dst, dp, seq, ack, flags, pl, id)
}
pub fn c2s(seq: u32, ack: u32, pl: &[u8], id: u16) -> Vec<u8> {
    pkt(C, CP, S, SP, seq, ack, ACK | PSH, pl, id)
}
#[allow(dead_code)]
pub fn touch() {
    let _ = (FIN, RST, SYN);
}
