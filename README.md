# 网络会话重组台

纯离线的网络会话重组工作台：接收简化 **pcap** 或项目自定义的**确定性帧夹具**
（JSON），解析链路层、IPv4/IPv6 与 TCP 元数据，把双向流按**代次**归并成会话，
展示每个方向的序号区间、重传、缺口、乱序、重叠覆盖与最终重组字节，并可下载重组
结果与完整证据 JSON。

- 纯 Rust 标准库实现，**零第三方依赖**，不调用系统抓包权限，不读取实时网卡。
- 原始帧按 SHA-256 内容寻址保存；分析结果按 `(夹具, 参数, schema)` 派生版本 id，
  切换重叠策略生成新版本，**旧结果永不覆盖**。

## 安装与演示

```bash
cargo build --locked
cargo test --all-targets
cargo run --locked -- --addr 127.0.0.1:5235
# 打开 http://127.0.0.1:5235 ，页面标题为「网络会话重组台」
```

生成演示夹具（环绕/重传/乱序/缺口、四元组复用、中途抓取、重叠分片、相同时间戳）：

```bash
cargo run --example seed_fixture --locked > demo-fixture.json
```

在页面上：上传夹具 → 选择重叠策略（first-seen / last-seen）→「生成分析版本」
→ 筛选会话 → 点击会话查看序号空间覆盖条与事件 → 下载方向重组字节或证据 JSON。

## 夹具格式

```json
{
  "format": "pwgsb-fixture/1",
  "frames": [
    { "ts_ns": 1000, "raw": "<十六进制 Ethernet/裸IP 帧>" },
    { "ts_ns": 2000, "raw": "..." }
  ]
}
```

- 帧在数组中的位置即**原始帧序号**；所有排序均为 `(ts_ns, 帧序号)`，
  相同时间戳严格按原始帧序号。
- pcap 支持经典全局头格式（微秒/纳秒、大小端、Ethernet/RAW 链路类型）。

## 语义约定

- **连接代次**：四元组仅用于定位流；旧代次经双向 FIN、RST 或空闲超时关闭后，
  同一四元组上的新发起 SYN 才开启下一代。旧代次关闭后到达的迟到报文仍归旧代次，
  绝不伪造连接。
- **中途抓取**：首包无 SYN 时建立 `partial` 会话，不伪造握手，重组 base 取首个
  数据段序号。
- **32 位环绕**：所有序号比较使用环绕有符号差（±2^31）。
- **重叠策略**：`first-seen` 丢弃后到冲突字节，`last-seen` 用后到字节替换；
  无论哪种策略，冲突双方字节与帧号都写入证据事件 `overlap_bytes`。
- **IP 分片**：先按分片边界独立重组；任何字节重叠、分片数量/缓存/数据报尺寸超
  预算都会**隔离**该数据报（记录到 `isolated_datagrams`），不影响其他会话。
- **证据指纹**：证据 JSON（不含 fingerprint 字段）的 SHA-256；同参数重新导入分析
  指纹一致，改策略则产生新版本。

## 目录结构

- `src/parse.rs`：Ethernet / VLAN / IPv4 / IPv6（含分片扩展头）/ TCP 解析
- `src/frag.rs`：IP 分片重组与隔离
- `src/session.rs`：代次状态机、方向重组、事件与覆盖证据
- `src/analyze.rs`：证据 JSON、重组流、结果指纹
- `src/store.rs`：内容寻址 blob、夹具、分析版本落盘
- `src/http.rs` / `src/ui.html`：本地 HTTP API 与单页界面
- `src/builder.rs` / `examples/seed_fixture.rs`：确定性构造器与演示夹具
- `tests/integration.rs`：15 个场景测试
