//! 本地内容寻址存储：原始帧 blob、抓包记录、分析版本（旧结果永不覆盖）。

use crate::fixture::{Fixture, InputKind};
use crate::hash::{hex, sha256};
use crate::json::{canonical, parse, pretty, Value};
use crate::pcap::{encode as pcap_encode, parse as pcap_parse, RawFrame};
use crate::reasm::{Analysis, AnalyzeConfig, Analyzer, InputFrame};
use crate::seq::OverlapPolicy;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct StoredCapture {
    pub capture_id: String,
    pub link_type: u32,
    pub frame_count: usize,
    pub source_kind: String,
    pub raw_bytes_hash: String,
}

#[derive(Debug, Clone)]
pub struct StoredAnalysis {
    pub analysis_id: String,
    pub capture_id: String,
    pub fingerprint: String,
    pub overlap: String,
    pub idle_timeout_us: i64,
    pub created_seq: usize,
}

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Store> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("captures"))?;
        fs::create_dir_all(root.join("analyses"))?;
        Ok(Store { root })
    }

    // ----- 抓包导入 -------------------------------------------------------

    pub fn import_bytes(&self, bytes: &[u8]) -> Result<StoredCapture, String> {
        let kind = crate::fixture::sniff(bytes);
        let (link_type, frames, source_kind) = match kind {
            InputKind::Pcap => {
                let (hdr, frames) = pcap_parse(bytes)?;
                (hdr.link_type, frames, "pcap".to_string())
            }
            InputKind::FixtureJson => {
                let fx = Fixture::parse(&String::from_utf8_lossy(bytes))?;
                (fx.link_type, fx.frames, "fixture-json".to_string())
            }
            InputKind::PcapNg => return Err("pcapng 暂不支持，请转成经典 pcap".into()),
            InputKind::Unknown => return Err("无法识别输入：需要经典 pcap 或夹具 JSON".into()),
        };

        // 原始帧内容寻址：逐帧 blob 去重保存。
        let mut blob_hashes = Vec::with_capacity(frames.len());
        for f in &frames {
            let h = hex(&sha256(&f.data));
            self.put_blob(&h, &f.data).map_err(io)?;
            blob_hashes.push(h);
        }

        // capture 身份：对规范化后的“(微秒时间戳, 帧字节哈希) 序列”取哈希，
        // 因此夹具导出再导入、或等价 pcap 往返都会得到同一身份/指纹。
        let mut idoc = Vec::<(String, Value)>::new();
        idoc.push(("link_type".into(), Value::Int(link_type as i64)));
        idoc.push((
            "frames".into(),
            Value::Array(
                frames
                    .iter()
                    .map(|f| {
                        Value::obj(vec![
                            ("us", Value::Int(f.ts_us)),
                            ("orig_len", Value::Int(f.orig_len as i64)),
                            ("sha256", Value::Str(hex(&sha256(&f.data)))),
                        ])
                    })
                    .collect(),
            ),
        ));
        let capture_id = hex(&sha256(canonical(&Value::Object(idoc)).as_bytes()));

        let dir = self.root.join("captures").join(&capture_id);
        if !dir.exists() {
            fs::create_dir_all(&dir).map_err(io)?;
            // 以原始上传字节原样留存（夹具 JSON / pcap）。
            fs::write(dir.join("source.bin"), bytes).map_err(io)?;
            let meta = Value::obj(vec![
                ("capture_id", Value::Str(capture_id.clone())),
                ("link_type", Value::Int(link_type as i64)),
                ("frame_count", Value::Int(frames.len() as i64)),
                ("source_kind", Value::Str(source_kind.clone())),
                ("raw_bytes_hash", Value::Str(hex(&sha256(bytes)))),
                (
                    "frame_blobs",
                    Value::Array(blob_hashes.into_iter().map(Value::Str).collect()),
                ),
                ("frames", frames_meta(&frames)),
            ]);
            fs::write(dir.join("meta.json"), pretty(&meta)).map_err(io)?;
            // 规范化导出：始终写一份小端 pcap，保证往返一致。
            let pcap = pcap_encode(link_type, &frames);
            fs::write(dir.join("canonical.pcap"), pcap).map_err(io)?;
        }

        Ok(StoredCapture {
            capture_id,
            link_type,
            frame_count: frames.len(),
            source_kind,
            raw_bytes_hash: hex(&sha256(bytes)),
        })
    }

    pub fn load_capture(&self, capture_id: &str) -> Result<(u32, Vec<InputFrame>), String> {
        let dir = self.root.join("captures").join(capture_id);
        let meta_raw = fs::read_to_string(dir.join("meta.json"))
            .map_err(|_| format!("抓包 {} 不存在", capture_id))?;
        let meta = parse(&meta_raw)?;
        let link_type = meta.get("link_type").and_then(|v| v.as_i64()).unwrap_or(1) as u32;
        let pcap_bytes = fs::read(dir.join("canonical.pcap")).map_err(io_str)?;
        let (_, frames) = pcap_parse(&pcap_bytes)?;
        let inputs = frames
            .iter()
            .enumerate()
            .map(|(i, f)| InputFrame {
                order: i,
                ts_us: f.ts_us,
                data: f.data.clone(),
            })
            .collect();
        Ok((link_type, inputs))
    }

    pub fn list_captures(&self) -> Vec<StoredCapture> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(self.root.join("captures")) {
            for e in entries.flatten() {
                let p = e.path().join("meta.json");
                if let Ok(txt) = fs::read_to_string(p) {
                    if let Ok(m) = parse(&txt) {
                        out.push(StoredCapture {
                            capture_id: str_field(&m, "capture_id"),
                            link_type: m.get("link_type").and_then(|v| v.as_i64()).unwrap_or(1)
                                as u32,
                            frame_count: m.get("frame_count").and_then(|v| v.as_i64()).unwrap_or(0)
                                as usize,
                            source_kind: str_field(&m, "source_kind"),
                            raw_bytes_hash: str_field(&m, "raw_bytes_hash"),
                        });
                    }
                }
            }
        }
        out.sort_by(|a, b| a.capture_id.cmp(&b.capture_id));
        out
    }

    pub fn capture_source_bytes(&self, capture_id: &str) -> Option<Vec<u8>> {
        fs::read(
            self.root
                .join("captures")
                .join(capture_id)
                .join("canonical.pcap"),
        )
        .ok()
    }

    // ----- 分析版本 -------------------------------------------------------

    pub fn analyze(
        &self,
        capture_id: &str,
        overlap: OverlapPolicy,
        idle_timeout_us: i64,
    ) -> Result<StoredAnalysis, String> {
        let (link_type, frames) = self.load_capture(capture_id)?;
        let cfg = AnalyzeConfig {
            overlap,
            idle_timeout_us,
            ..AnalyzeConfig::default()
        };
        let analysis: Analysis = Analyzer::new(cfg).run(&frames, link_type);

        // 分析身份 = capture + 规范化配置 + 分析器版本。
        let idoc = Value::obj(vec![
            ("analyzer", Value::Str(crate::ANALYZER_VERSION.into())),
            ("capture_id", Value::Str(capture_id.into())),
            ("config", analysis.config_json.clone()),
        ]);
        let analysis_id = hex(&sha256(canonical(&idoc).as_bytes()));
        // 结果指纹：对规范化结果文档（不含存储元信息）取哈希。
        let fingerprint = hex(&sha256(canonical(&analysis.result).as_bytes()));

        let dir = self.root.join("analyses").join(&analysis_id);
        if !dir.exists() {
            fs::create_dir_all(&dir).map_err(io)?;
            fs::write(dir.join("evidence.json"), pretty(&analysis.result)).map_err(io)?;
            fs::write(
                dir.join("evidence.canonical.json"),
                canonical(&analysis.result),
            )
            .map_err(io)?;
            fs::write(dir.join("fingerprint.txt"), &fingerprint).map_err(io)?;
            // 每个会话方向的连续前缀字节，独立文件下载。
            let streams_dir = dir.join("streams");
            fs::create_dir_all(&streams_dir).map_err(io)?;
            for sb in &analysis.streams {
                let name = format!("{}.{}.bin", sb.session, sb.dir_key);
                fs::write(streams_dir.join(name), &sb.bytes).map_err(io)?;
            }
            let seq = self.next_seq();
            let meta = Value::obj(vec![
                ("analysis_id", Value::Str(analysis_id.clone())),
                ("capture_id", Value::Str(capture_id.into())),
                ("fingerprint", Value::Str(fingerprint.clone())),
                ("overlap", Value::Str(overlap.as_str().into())),
                ("idle_timeout_us", Value::Int(idle_timeout_us)),
                ("created_seq", Value::Int(seq as i64)),
            ]);
            fs::write(dir.join("meta.json"), pretty(&meta)).map_err(io)?;
        }

        let meta_raw = fs::read_to_string(dir.join("meta.json")).map_err(io)?;
        let meta = parse(&meta_raw)?;
        Ok(StoredAnalysis {
            analysis_id,
            capture_id: capture_id.to_string(),
            fingerprint,
            overlap: overlap.as_str().to_string(),
            idle_timeout_us,
            created_seq: meta
                .get("created_seq")
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as usize,
        })
    }

    pub fn list_analyses(&self, capture_id: Option<&str>) -> Vec<StoredAnalysis> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(self.root.join("analyses")) {
            for e in entries.flatten() {
                let p = e.path().join("meta.json");
                if let Ok(txt) = fs::read_to_string(p) {
                    if let Ok(m) = parse(&txt) {
                        let cid = str_field(&m, "capture_id");
                        if capture_id.map_or(true, |c| c == cid) {
                            out.push(StoredAnalysis {
                                analysis_id: str_field(&m, "analysis_id"),
                                capture_id: cid,
                                fingerprint: str_field(&m, "fingerprint"),
                                overlap: str_field(&m, "overlap"),
                                idle_timeout_us: m
                                    .get("idle_timeout_us")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(120_000_000),
                                created_seq: m
                                    .get("created_seq")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(0)
                                    as usize,
                            });
                        }
                    }
                }
            }
        }
        out.sort_by_key(|a| a.created_seq);
        out
    }

    pub fn read_evidence(&self, analysis_id: &str) -> Option<String> {
        fs::read_to_string(
            self.root
                .join("analyses")
                .join(analysis_id)
                .join("evidence.json"),
        )
        .ok()
    }

    pub fn read_stream(&self, analysis_id: &str, session: &str, dir_key: &str) -> Option<Vec<u8>> {
        let safe_session = sanitize(session);
        let safe_dir = sanitize(dir_key);
        if safe_session != session || safe_dir != dir_dir(dir_key) {
            return None;
        }
        let p = self
            .root
            .join("analyses")
            .join(analysis_id)
            .join("streams")
            .join(format!("{}.{}.bin", safe_session, safe_dir));
        fs::read(p).ok()
    }

    pub fn evidence_file_path(&self, analysis_id: &str) -> PathBuf {
        self.root
            .join("analyses")
            .join(analysis_id)
            .join("evidence.json")
    }

    fn put_blob(&self, hash: &str, data: &[u8]) -> std::io::Result<()> {
        let p = self.root.join("blobs").join(hash);
        if !p.exists() {
            fs::write(p, data)?;
        }
        Ok(())
    }

    fn next_seq(&self) -> usize {
        fs::read_dir(self.root.join("analyses"))
            .map(|d| d.count())
            .unwrap_or(0)
    }
}

fn frames_meta(frames: &[RawFrame]) -> Value {
    Value::Array(
        frames
            .iter()
            .enumerate()
            .map(|(i, f)| {
                Value::obj(vec![
                    ("order", Value::Int(i as i64)),
                    ("us", Value::Int(f.ts_us)),
                    ("incl_len", Value::Int(f.data.len() as i64)),
                    ("orig_len", Value::Int(f.orig_len as i64)),
                    ("truncated", Value::Bool(f.data.len() as u32 != f.orig_len)),
                ])
            })
            .collect(),
    )
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
        .collect()
}

fn dir_dir(s: &str) -> String {
    s.to_string()
}

fn io(e: std::io::Error) -> String {
    e.to_string()
}

fn io_str(e: std::io::Error) -> String {
    e.to_string()
}
