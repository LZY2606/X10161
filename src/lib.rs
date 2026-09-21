//! 网络会话重组台 — 离线抓包会话重组核心库。
//!
//! 解析链路层 / IPv4 / IPv6 / TCP 元数据，把双向流归并为会话代次，
//! 支持 32 位环绕序号比较、可配置重叠策略（first-seen / last-seen）、
//! IP 分片重组与隔离、partial 会话，以及确定性证据指纹。

pub mod hash;
pub mod pcap;
pub mod fixture;
pub mod packet;
pub mod reasm;
pub mod session;
pub mod store;
pub mod server;
pub mod ui;
