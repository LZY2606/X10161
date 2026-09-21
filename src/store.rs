//! 磁盘存储：
//! - `blobs/<sha256>`：原始帧内容寻址，永不重复、永不覆盖。
//! - `corpora/<id>.json`：夹具（帧序号、时间戳、blob 引用）。
//! - `analyses/<id>/evidence.json` 与 `stream_<sid>_<dir>.bin`：
//!   分析 id 由 (corpus, 参数, schema) 决定；策略变化产生新版本，旧结果保留。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::analyze::{analyze, BuiltAnalysis};
use crate::fixture;
use crate::json::Value;
use crate::model::Frame;
use crate::session::Params;
use crate::sha256::sha256_hex;
use crate::util::hex_encode;

pub struct Store {
    root: PathBuf,
    lock: Mutex<()>,
}

#[derive(Clone, Debug)]
pub struct CorpusMeta {
    pub id: String,
    pub frame_count: usize,
}

#[derive(Clone, Debug)]
pub struct AnalysisMeta {
    pub id: String,
    pub corpus_id: String,
    pub fingerprint: String,
    pub created_at_ns: u64,
    pub policy: String,
    pub session_count: usize,
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Store> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("corpora"))?;
        fs::create_dir_all(root.join("analyses"))?;
        Ok(Store {
            root,
            lock: Mutex::new(()),
        })
    }

    fn write_if_absent(path: &Path, bytes: &[u8]) -> std::io::Result<bool> {
        if path.exists() {
            return Ok(false);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, path)?;
        Ok(true)
    }

    /// 导入原始输入（pcap 或 JSON 夹具），帧内容寻址落盘。
    pub fn import(&self, data: &[u8]) -> Result<CorpusMeta, String> {
        let _g = self.lock.lock().unwrap();
        let frames = fixture::parse_any(data)?;
        self.store_frames(&frames)
    }

    fn store_frames(&self, frames: &[Frame]) -> Result<CorpusMeta, String> {
        let mut refs = Vec::with_capacity(frames.len());
        for f in frames {
            let hash = sha256_hex(&f.raw);
            let blob = self.root.join("blobs").join(&hash);
            Store::write_if_absent(&blob, &f.raw)
                .map_err(|e| format!("write blob: {}", e))?;
            let mut r = Value::obj();
            r.set("index", Value::Int(f.index as i128));
            r.set("ts_ns", Value::Int(f.ts_ns as i128));
            r.set("blob", Value::Str(hash));
            refs.push(r);
        }
        let mut doc = Value::obj();
        doc.set("format", Value::Str("pwgsb-corpus/1".into()));
        doc.set("frames", Value::Arr(refs));
        let body = doc.serialize();
        let id = sha256_hex(body.as_bytes());
        let path = self.root.join("corpora").join(format!("{}.json", id));
        Store::write_if_absent(&path, body.as_bytes()).map_err(|e| e.to_string())?;
        Ok(CorpusMeta {
            id,
            frame_count: frames.len(),
        })
    }

    pub fn load_corpus(&self, id: &str) -> Result<Vec<Frame>, String> {
        if !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("bad corpus id".into());
        }
        let path = self.root.join("corpora").join(format!("{}.json", id));
        let body = fs::read_to_string(&path).map_err(|e| format!("read corpus: {}", e))?;
        let doc = Value::parse(&body).map_err(|e| format!("bad corpus json: {}", e))?;
        let arr = doc
            .get("frames")
            .and_then(|v| v.as_array())
            .ok_or("corpus missing frames")?;
        let mut frames = Vec::new();
        for item in arr {
            let index = item.get("index").and_then(|v| v.as_i64()).unwrap_or(0) as u32;
            let ts_ns = item.get("ts_ns").and_then(|v| v.as_u64()).ok_or("bad ts")?;
            let blob = item
                .get("blob")
                .and_then(|v| v.as_str())
                .ok_or("bad blob ref")?;
            let raw = fs::read(self.root.join("blobs").join(blob))
                .map_err(|e| format!("read blob: {}", e))?;
            frames.push(Frame { index, ts_ns, raw });
        }
        Ok(frames)
    }

    pub fn list_corpora(&self) -> Vec<CorpusMeta> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(self.root.join("corpora")) {
            for e in entries.flatten() {
                if let Some(name) = e.file_name().to_str() {
                    if let Some(id) = name.strip_suffix(".json") {
                        if let Ok(frames) = self.load_corpus(id) {
                            out.push(CorpusMeta {
                                id: id.to_string(),
                                frame_count: frames.len(),
                            });
                        }
                    }
                }
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// 运行分析并落盘新版本；相同 (corpus, 参数) 返回既有版本，绝不覆盖旧结果。
    pub fn analyze(&self, corpus_id: &str, params: Params) -> Result<AnalysisMeta, String> {
        let _g = self.lock.lock().unwrap();
        let frames = self.load_corpus(corpus_id)?;
        let BuiltAnalysis {
            evidence,
            streams,
            fingerprint,
            ..
        } = analyze(corpus_id, &frames, params);

        let mut key_doc = Value::obj();
        key_doc.set("schema", Value::Str(crate::analyze::SCHEMA.into()));
        key_doc.set("corpus_id", Value::Str(corpus_id.into()));
        key_doc.set("params", params.to_json());
        let analysis_id = sha256_hex(key_doc.serialize().as_bytes());

        let dir = self.root.join("analyses").join(&analysis_id);
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

        let evidence_bytes = evidence.serialize().into_bytes();
        Store::write_if_absent(&dir.join("evidence.json"), &evidence_bytes)
            .map_err(|e| e.to_string())?;
        for (sid, d, data) in streams {
            Store::write_if_absent(
                &dir.join(format!("stream_{}_{}.bin", sid, d)),
                &data,
            )
            .map_err(|e| e.to_string())?;
        }

        let session_count = evidence
            .get("sessions")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let mut meta_doc = Value::obj();
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i128)
            .unwrap_or(0);
        meta_doc.set("id", Value::Str(analysis_id.clone()));
        meta_doc.set("corpus_id", Value::Str(corpus_id.into()));
        meta_doc.set("fingerprint", Value::Str(fingerprint.clone()));
        meta_doc.set("created_at_ns", Value::Int(created));
        meta_doc.set("policy", Value::Str(params.policy.name().into()));
        meta_doc.set("session_count", Value::Int(session_count as i128));
        Store::write_if_absent(&dir.join("meta.json"), meta_doc.serialize().as_bytes())
            .map_err(|e| e.to_string())?;

        Ok(AnalysisMeta {
            id: analysis_id,
            corpus_id: corpus_id.to_string(),
            fingerprint,
            created_at_ns: created as u64,
            policy: params.policy.name().to_string(),
            session_count,
        })
    }

    pub fn list_analyses(&self) -> Vec<AnalysisMeta> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(self.root.join("analyses")) {
            for e in entries.flatten() {
                if let Some(id) = e.file_name().to_str() {
                    if let Ok(body) =
                        fs::read_to_string(self.root.join("analyses").join(id).join("meta.json"))
                    {
                        if let Ok(doc) = Value::parse(&body) {
                            out.push(AnalysisMeta {
                                id: doc.get("id").and_then(|v| v.as_str()).unwrap_or(id).into(),
                                corpus_id: doc
                                    .get("corpus_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .into(),
                                fingerprint: doc
                                    .get("fingerprint")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .into(),
                                created_at_ns: doc
                                    .get("created_at_ns")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0),
                                policy: doc
                                    .get("policy")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .into(),
                                session_count: doc
                                    .get("session_count")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(0) as usize,
                            });
                        }
                    }
                }
            }
        }
        out.sort_by(|a, b| b.created_at_ns.cmp(&a.created_at_ns).then(a.id.cmp(&b.id)));
        out
    }

    pub fn read_evidence(&self, analysis_id: &str) -> Result<Value, String> {
        let path = self.analysis_dir(analysis_id)?.join("evidence.json");
        let body = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        Value::parse(&body).map_err(|e| e)
    }

    pub fn read_stream(
        &self,
        analysis_id: &str,
        session_id: usize,
        dir: usize,
    ) -> Result<Vec<u8>, String> {
        if dir > 1 {
            return Err("bad direction".into());
        }
        let path = self
            .analysis_dir(analysis_id)?
            .join(format!("stream_{}_{}.bin", session_id, dir));
        fs::read(&path).map_err(|e| e.to_string())
    }

    fn analysis_dir(&self, id: &str) -> Result<PathBuf, String> {
        if !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("bad analysis id".into());
        }
        Ok(self.root.join("analyses").join(id))
    }
}

#[allow(dead_code)]
fn ensure_unused() -> String {
    hex_encode(b"")
}
