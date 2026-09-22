# 网络会话重组台 (reasm)

一个**完全本地、零外部依赖**的网络会话重组工作台。在浏览器里重建离线抓包中的 TCP
会话，而不是依赖外部分析程序给出黑盒结果。不调用系统抓包权限、不读取实时网卡。

## 能力

- 解析 **链路层**（Ethernet，含 802.1Q/QinQ VLAN、Linux cooked SLL、裸 IPv4/IPv6）、
  **IPv4 / IPv6**（含 IPv6 扩展头与分片扩展头）与 **TCP** 元数据。
- 双向流按四元组归并为会话；同一四元组在旧连接结束后的**复用**会开新“代次”，
  SYN / FIN / RST / 超时共同决定代次边界。
- 32 位 TCP 序号使用环绕比较；独立的“数据流坐标”保证跨 `u32::MAX` 边界正确拼接。
- 报告每个方向的序号区间、**重传、缺口、乱序、重叠**与最终重组字节。
- 重叠片段采用可配置的 **first-seen / last-seen** 策略；无论哪种策略，被覆盖字节
  的原始片段都完整保留在“片段证据”中（payload + 帧 SHA-256）。
- 抓包在会话中间开始时建立 **partial** 会话，基准 ISN 明确标记为“非 SYN 推断”，
  **绝不伪造缺失的握手**。
- IP 分片先按自身边界重组；**重叠或超预算的分片使该数据报被隔离**，绝不影响其它
  会话（含独立的干净四元组）。
- 所有排序按原始帧序号；相同时间戳用原始帧序号决胜。
- 原始帧**内容寻址**（SHA-256 去重保存）；切换重叠策略会产生**新的不可变分析版本**，
  旧结果永不覆盖。

## 安装与演示

```bash
cargo build --locked
cargo test --all-targets
cargo run --locked -- --addr 127.0.0.1:5235
# 打开 http://127.0.0.1:5235 ，页面标题为“网络会话重组台”
```

数据目录默认 `./.reasm-data`，可用 `--data-dir <path>` 覆盖。

## 输入格式

- 经典 **pcap**（魔数 `a1b2c3d4` / 纳秒变体，支持端序翻转；链路类型
  Ethernet=1、Linux SLL=113、RAW IPv4=228、RAW IPv6=31）。
- 项目自定义的**确定性 JSON 夹具**：

```json
{
  "linktype": 1,
  "frames": [
    {"ts_us": 0, "data": "<以太网帧 hex>"},
    {"ts_us": 100, "data": "..."}
  ]
}
```

页面内置 10 个构造场景：序号环绕、重传/冲突、乱序、缺口、四元组复用、中途抓取、
FIN/RST 竞态、IPv4 分片重叠、相同时间戳，以及综合 `mixed`。

## HTTP 接口

- `GET  /` 单页界面
- `GET  /api/health`
- `GET  /api/demo-list`、`GET /api/demo?scenario=<name>`
- `POST /api/analyze?policy=first-seen|last-seen&timeout_us=<us>`（body 为 pcap/夹具原始字节）
- `GET  /api/versions`（所有不可变版本）
- `GET  /api/version?id=<version_id>`（回看旧版本结果）
- `GET  /api/frame?sha256=<64hex>`（按内容哈希取原始帧）

## 结果 / 证据 JSON

每个分析版本包含：四元组与代次、状态与关闭原因、握手状态（seen/partial/missing）、
每方向基准 ISN 与来源帧、序号区间（data begin / frontier / max span）、重传/乱序/重叠
计数、最终重组字节（hex 与 UTF-8 有损视图）、逐字节覆盖来源（帧序号 + 帧哈希的游程编码）、
每个片段的分类与 payload 证据、缺口列表，以及 IP 分片隔离记录。`fingerprint` 为剔除
易变元数据与字节块后的规范 SHA-256，导入/导出后保持一致。

## 代码结构

- `src/json.rs` 最小确定性 JSON（BTreeMap 规范序，用于指纹）
- `src/hash.rs` SHA-256
- `src/model.rs` 链路层 / IPv4 / IPv6 / TCP 解析
- `src/capture.rs` pcap 与夹具载入
- `src/ipreasm.rs` IP 分片重组与重叠/超预算隔离
- `src/tcp.rs` 代次识别、环绕序号、重传/乱序/重叠分类与字节流重组
- `src/analyze.rs` 编排与结果/指纹生成
- `src/builder.rs` 确定性帧夹具构造器（测试与演示）
- `src/storage.rs` 内容寻址存储与不可变版本
- `src/server.rs` 本地 HTTP 服务与演示夹具
- `tests/` 15 个边界场景 + HTTP 端到端集成测试
