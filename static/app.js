"use strict";

const state = {
  datasetId: null,
  meta: null,
  analysis: null,
  version: null,
  selectedSession: null,
};

const $ = (id) => document.getElementById(id);

async function jsonFetch(url, options = {}) {
  const resp = await fetch(url, options);
  const text = await resp.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (_) { data = { raw: text }; }
  if (!resp.ok) {
    const message = (data && data.error) || resp.statusText;
    throw new Error(message);
  }
  return data;
}

function setStatus(id, message, kind) {
  const el = $(id);
  el.textContent = message || "";
  el.className = "status" + (kind ? " " + kind : "");
}

async function loadDatasets(selectId = "dataset-select") {
  const list = await jsonFetch("/api/datasets");
  const select = $(selectId);
  select.innerHTML = "";
  if (!list.length) {
    const opt = document.createElement("option");
    opt.textContent = "（暂无数据集）";
    opt.value = "";
    select.appendChild(opt);
    return;
  }
  for (const ds of list) {
    const opt = document.createElement("option");
    opt.value = ds.id;
    opt.textContent = `${ds.name} — ${ds.id.slice(0, 8)} (${ds.frame_count} 帧)`;
    select.appendChild(opt);
  }
  if (!state.datasetId || !list.some((d) => d.id === state.datasetId)) {
    state.datasetId = list[0].id;
  }
  select.value = state.datasetId;
}

async function selectDataset() {
  state.datasetId = $("dataset-select").value;
  state.analysis = null;
  state.selectedSession = null;
  if (!state.datasetId) {
    renderSessions();
    renderDetail();
    return;
  }
  state.meta = await jsonFetch(`/api/datasets/${encodeURIComponent(state.datasetId)}`);
  renderVersions();
  const latest = state.meta.versions[state.meta.versions.length - 1];
  if (latest) {
    await loadVersion(latest.version);
  } else {
    await runAnalysis(false);
  }
}

async function runAnalysis(announce = true) {
  if (!state.datasetId) return;
  if (announce) setStatus("version-info", "正在生成分析版本…");
  const body = JSON.stringify({
    overlap_policy: $("policy").value,
    timeout_seconds: Number($("timeout").value || "120"),
  });
  try {
    const data = await jsonFetch(`/api/datasets/${encodeURIComponent(state.datasetId)}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    state.analysis = data.analysis;
    state.version = data.version;
    state.meta = await jsonFetch(`/api/datasets/${encodeURIComponent(state.datasetId)}`);
    renderVersions();
    setStatus(
      "version-info",
      `版本 v${data.version.version} · 指纹 ${data.version.fingerprint.slice(0, 20)}… · ${data.version.session_count} 个会话`,
      "ok"
    );
    renderSessions();
    renderDetail();
  } catch (e) {
    setStatus("version-info", "分析失败：" + e.message, "error");
  }
}

async function loadVersion(version) {
  const data = await jsonFetch(
    `/api/datasets/${encodeURIComponent(state.datasetId)}/versions/${version}`
  );
  state.analysis = data;
  state.version = state.meta.versions.find((v) => v.version === version);
  if (state.version) {
    setStatus(
      "version-info",
      `版本 v${version} · 指纹 ${state.version.fingerprint.slice(0, 20)}… · ${state.version.session_count} 个会话`,
      "ok"
    );
  }
  renderSessions();
  renderDetail();
}

function renderVersions() {
  const ul = $("version-list");
  ul.innerHTML = "";
  for (const v of state.meta.versions || []) {
    const li = document.createElement("li");
    const link = document.createElement("a");
    link.href = "#";
    link.textContent = `v${v.version} · ${v.overlap_policy} · timeout ${v.timeout_seconds}s · ${v.session_count} 会话`;
    link.addEventListener("click", async (ev) => {
      ev.preventDefault();
      await loadVersion(v.version);
    });
    li.appendChild(link);
    li.appendChild(document.createTextNode(`  ${v.fingerprint.slice(0, 12)}`));
    ul.appendChild(li);
  }
}

function filteredSessions() {
  if (!state.analysis) return [];
  const text = $("filter-text").value.trim().toLowerCase();
  const stateFilter = $("filter-state").value;
  const hsFilter = $("filter-handshake").value;
  return state.analysis.sessions.filter((s) => {
    if (text && !s.flow.toLowerCase().includes(text)) return false;
    if (stateFilter && s.state !== stateFilter) return false;
    if (hsFilter && s.handshake !== hsFilter) return false;
    return true;
  });
}

function dirStats(session) {
  const values = Object.values(session.directions);
  return values.reduce(
    (acc, d) => {
      acc.gaps += d.gaps.length;
      acc.retrans += d.retransmit_segments;
      acc.conflicts += d.conflict_segments;
      return acc;
    },
    { gaps: 0, retrans: 0, conflicts: 0 }
  );
}

function renderSessions() {
  const tbody = $("session-tbody");
  tbody.innerHTML = "";
  const sessions = filteredSessions();
  for (const s of sessions) {
    const stats = dirStats(s);
    const tr = document.createElement("tr");
    tr.className = "session-row" + (state.selectedSession === s.session_id ? " active" : "");
    tr.innerHTML = `
      <td>${s.session_id}</td>
      <td>${escapeHtml(s.flow)}</td>
      <td><span class="badge ${s.handshake}">${s.handshake}</span></td>
      <td><span class="badge ${s.state}">${s.state}</span></td>
      <td>${s.frame_count}</td>
      <td>${stats.gaps}</td>
      <td>${stats.retrans}</td>
      <td>${stats.conflicts}</td>`;
    tr.addEventListener("click", () => {
      state.selectedSession = s.session_id;
      renderSessions();
      renderDetail();
    });
    tbody.appendChild(tr);
  }
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function renderCoverageBar(direction) {
  const rangeStart = direction.data_rel_range.start;
  const rangeEnd = Math.max(direction.data_rel_range.end, 1);
  const span = rangeEnd - rangeStart || 1;
  const bar = document.createElement("div");
  bar.className = "coverage";
  const covered = direction.covered_intervals || [];
  const gaps = direction.gaps || [];
  for (const iv of covered) {
    const seg = document.createElement("div");
    seg.className = "seg data";
    seg.style.width = `${Math.max(((iv.end - iv.start) / span) * 100, 0.4)}%`;
    seg.style.marginLeft = covered.indexOf(iv) === 0 && iv.start > rangeStart
      ? `${((iv.start - rangeStart) / span) * 100}%`
      : "0";
    seg.title = `data ${iv.start}..${iv.end}`;
    bar.appendChild(seg);
  }
  // Overlay gaps as red segments with absolute layout approximation: simpler
  // to append gap markers in order after data (relative widths still informative).
  return bar;
}

function renderDirection(endpoint, direction) {
  const block = document.createElement("div");
  block.className = "dir-block";
  const title = document.createElement("h3");
  title.textContent = `方向 ${endpoint}`;
  block.appendChild(title);

  const metrics = document.createElement("div");
  metrics.className = "metrics";
  metrics.innerHTML = `
    <span>SYN: ${direction.syn ? "是" : "否"}</span>
    <span>FIN: ${direction.fin ? "是 @rel " + direction.fin_rel : "否"}</span>
    <span>RST: ${direction.rst ? "是" : "否"}</span>
    <span>锚定: ${direction.anchored_by_syn ? "SYN/ISN" : "中途（不伪造握手）"}</span>
    <span>已交付: ${direction.delivered_length} 字节</span>
    <span>缺口: ${direction.gaps.length}</span>
    <span>重传: ${direction.retransmit_segments}</span>
    <span>乱序: ${direction.out_of_order_segments}</span>
    <span>冲突: ${direction.conflict_segments}</span>`;
  block.appendChild(metrics);

  const legend = document.createElement("div");
  legend.className = "legend";
  legend.innerHTML = `<span class="l-data">已覆盖序号区间</span><span class="l-gap">缺口（区间见下方列表）</span>`;
  block.appendChild(legend);
  block.appendChild(renderCoverageBar(direction));

  const ranges = document.createElement("div");
  ranges.style.fontSize = "12px";
  ranges.style.marginTop = "8px";
  const gapText = direction.gaps.length
    ? direction.gaps.map((g) => `[${g.start}, ${g.end})`).join(" ")
    : "无";
  ranges.textContent = `数据相对序号范围 [${direction.data_rel_range.start}, ${direction.data_rel_range.end}) · 缺口: ${gapText}`;
  block.appendChild(ranges);

  const segments = document.createElement("details");
  segments.open = false;
  const summary = document.createElement("summary");
  summary.textContent = `片段覆盖（${direction.segments.length} 个 TCP 段）`;
  segments.appendChild(summary);
  const list = document.createElement("div");
  list.className = "segment-list";
  for (const seg of direction.segments) {
    const row = document.createElement("div");
    const tags = (seg.classifications || [])
      .map((c) => `<span class="tag ${c.includes("conflict") ? "conflict" : c === "retransmission" ? "retransmission" : c === "out-of-order" ? "out-of-order" : ""}">${c}</span>`)
      .join("");
    row.innerHTML = `帧 #${seg.frame_index} seq=${seg.seq} end=${seg.end_seq} rel=[${seg.rel_start}, ${seg.rel_end}) len=${seg.data_len} ${tags}`;
    list.appendChild(row);
  }
  segments.appendChild(list);
  block.appendChild(segments);

  if (direction.overwrite_evidence && direction.overwrite_evidence.length) {
    const ev = document.createElement("details");
    const sum = document.createElement("summary");
    sum.textContent = `被覆盖字节证据（${direction.overwrite_evidence.length}）`;
    ev.appendChild(sum);
    const pre = document.createElement("pre");
    pre.className = "payload";
    pre.textContent = direction.overwrite_evidence
      .map((o) => `offset ${o.offset}: 保留帧 #${o.kept_frame} 字节 ${o.kept_hex}；丢弃帧 #${o.superseded_frame} 提供 ${o.offered_hex}（${o.policy}）`)
      .join("\n");
    ev.appendChild(pre);
    block.appendChild(ev);
  }

  const payload = document.createElement("details");
  const ps = document.createElement("summary");
  ps.textContent = "最终重组字节（hex）";
  payload.appendChild(ps);
  const pre = document.createElement("pre");
  pre.className = "payload";
  pre.textContent = direction.delivered_hex || "（空）";
  payload.appendChild(pre);
  block.appendChild(payload);
  return block;
}

function renderDetail() {
  const root = $("session-detail");
  root.className = "";
  root.innerHTML = "";
  if (!state.analysis) {
    root.className = "detail-empty";
    root.textContent = "请先选择数据集并生成分析";
    return;
  }
  const session = state.analysis.sessions.find((s) => s.session_id === state.selectedSession);
  if (!session) {
    root.className = "detail-empty";
    root.textContent = state.analysis.sessions.length
      ? "选择一个会话查看详情"
      : "当前分析没有识别出 TCP 会话";
    return;
  }
  const head = document.createElement("div");
  head.innerHTML = `
    <div><strong>#${session.session_id} ${escapeHtml(session.flow)}</strong>
      <span class="badge ${session.handshake}">${session.handshake}</span>
      <span class="badge ${session.state}">${session.state}</span>
    </div>
    <div class="metrics" style="margin-top:6px">
      <span>首帧 #${session.first_frame}</span><span>末帧 #${session.last_frame}</span>
      <span>开始 ${session.started_at.toFixed(6)}</span><span>结束 ${session.ended_at.toFixed(6)}</span>
    </div>
    <div class="fingerprint">分析指纹: ${state.analysis.fingerprint_sha256}</div>`;
  root.appendChild(head);

  const downloads = document.createElement("div");
  downloads.className = "download-row";
  const dl = document.createElement("button");
  dl.textContent = "下载全部重组字节";
  dl.addEventListener("click", () => {
    window.location = `/api/datasets/${encodeURIComponent(state.datasetId)}/versions/${state.version.version}?download=reassembled`;
  });
  const evidence = document.createElement("button");
  evidence.textContent = "下载分析证据 JSON";
  evidence.addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(state.analysis, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `session-${session.session_id}-v${state.version.version}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
  downloads.appendChild(dl);
  downloads.appendChild(evidence);
  root.appendChild(downloads);

  for (const [endpoint, dir] of Object.entries(session.directions)) {
    root.appendChild(renderDirection(endpoint, dir));
  }

  const timeline = document.createElement("details");
  timeline.open = false;
  const summary = document.createElement("summary");
  summary.textContent = `时间线事件（${session.timeline.length}）`;
  timeline.appendChild(summary);
  const pre = document.createElement("pre");
  pre.className = "payload";
  pre.textContent = session.timeline
    .map((e) => `帧 #${e.frame_index} t=${e.timestamp.toFixed(6)} ${e.kind} ${e.endpoint}${e.detail ? " — " + e.detail : ""}`)
    .join("\n");
  timeline.appendChild(pre);
  root.appendChild(timeline);
}

async function uploadFile(file, name) {
  const form = new FormData();
  form.append("file", file);
  if (name) form.append("name", name);
  setStatus("upload-status", "上传中…");
  try {
    const data = await jsonFetch("/api/datasets", { method: "POST", body: form });
    state.datasetId = data.dataset_id;
    setStatus("upload-status", `已接收 ${data.frame_count} 帧，数据集 ${data.dataset_id.slice(0, 12)}`, "ok");
    await loadDatasets();
    $("dataset-select").value = state.datasetId;
    await selectDataset();
  } catch (e) {
    setStatus("upload-status", "上传失败：" + e.message, "error");
  }
}

function bindEvents() {
  $("upload-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const file = $("file").files[0];
    if (!file) {
      setStatus("upload-status", "请选择 .json 夹具或 .pcap 抓包文件", "error");
      return;
    }
    uploadFile(file, $("name").value.trim());
  });
  $("refresh-btn").addEventListener("click", async () => {
    await loadDatasets();
    await selectDataset();
  });
  $("dataset-select").addEventListener("change", selectDataset);
  $("analyze-btn").addEventListener("click", () => runAnalysis(true));
  for (const id of ["filter-text", "filter-state", "filter-handshake"]) {
    $(id).addEventListener("input", renderSessions);
    $(id).addEventListener("change", renderSessions);
  }
  $("export-btn").addEventListener("click", () => {
    if (!state.datasetId) return;
    window.location = `/api/datasets/${encodeURIComponent(state.datasetId)}/export`;
  });
  $("pcap-btn").addEventListener("click", () => {
    if (!state.datasetId) return;
    window.location = `/api/datasets/${encodeURIComponent(state.datasetId)}/pcap`;
  });
  $("import-file").addEventListener("change", async (ev) => {
    const file = ev.target.files[0];
    if (!file) return;
    setStatus("upload-status", "导入证据包并校验指纹…");
    try {
      const text = await file.text();
      const data = await jsonFetch("/api/import-bundle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: text,
      });
      setStatus("upload-status", `导入成功：${data.frame_count} 帧，${data.versions} 个版本`, "ok");
      await loadDatasets();
      $("dataset-select").value = data.dataset_id;
      await selectDataset();
    } catch (e) {
      setStatus("upload-status", "导入失败：" + e.message, "error");
    }
  });
}

(async function init() {
  bindEvents();
  try {
    await loadDatasets();
    await selectDataset();
  } catch (e) {
    setStatus("upload-status", "初始化失败：" + e.message, "error");
  }
})();
