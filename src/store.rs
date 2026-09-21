//! File-backed, content-addressed storage.
//!
//! Layout under the data directory:
//!   blobs/<sha256>                 raw frame bytes, deduplicated
//!   datasets/<id>/meta.json        dataset metadata + normalized frames
//!   datasets/<id>/v<n>.json        immutable analysis versions
//! The active version pointer is metadata only; rerunning with a new policy
//! creates a new file and never overwrites older results.

use crate::analyze::{analyze, AnalysisConfig, AnalysisResult};
use crate::types::RawFrame;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatasetMeta {
    pub id: String,
    pub created_at: f64,
    pub name: String,
    pub frame_count: usize,
    pub frames: Vec<RawFrame>,
    #[serde(default)]
    pub versions: Vec<VersionInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: usize,
    pub fingerprint: String,
    pub overlap_policy: String,
    pub timeout_seconds: f64,
    pub session_count: usize,
    pub created_at: f64,
    pub file: String,
}

#[derive(Serialize, Deserialize)]
pub struct ExportBundle {
    pub schema: String,
    pub dataset: DatasetMeta,
    /// Map of sha256 hex -> hex-encoded raw bytes referenced by the dataset.
    pub blobs: BTreeMap<String, String>,
    /// Version file name -> canonical analysis JSON (immutable old results).
    #[serde(default)]
    pub analyses: BTreeMap<String, String>,
}

pub struct Store {
    root: PathBuf,
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("blobs")).map_err(io_err)?;
        std::fs::create_dir_all(root.join("datasets")).map_err(io_err)?;
        Ok(Store { root })
    }

    fn dataset_dir(&self, id: &str) -> PathBuf {
        self.root.join("datasets").join(id)
    }

    /// Store every frame's raw bytes under its content hash; return digest map.
    fn store_blobs(&self, frames: &[RawFrame]) -> Result<BTreeMap<String, Vec<u8>>, String> {
        let mut map = BTreeMap::new();
        for f in frames {
            let bytes = crate::types::decode_hex(&f.bytes_hex)?;
            let digest = crate::hash::sha256_hex(&bytes);
            let path = self.root.join("blobs").join(&digest);
            if !path.exists() {
                std::fs::write(path, &bytes).map_err(io_err)?;
            }
            map.insert(digest, bytes);
        }
        Ok(map)
    }

    pub fn create_dataset(&self, name: String, mut frames: Vec<RawFrame>) -> Result<DatasetMeta, String> {
        normalize_indices(&mut frames);
        let blobs = self.store_blobs(&frames)?;
        let canonical = serde_json::to_vec(&frames).map_err(|e| e.to_string())?;
        let id = crate::hash::sha256_hex(&canonical);
        let id = id.chars().take(16).collect::<String>();
        let dir = self.dataset_dir(&id);
        let meta_path = dir.join("meta.json");

        let meta = if meta_path.exists() {
            let raw = std::fs::read_to_string(&meta_path).map_err(io_err)?;
            serde_json::from_str::<DatasetMeta>(&raw).map_err(|e| e.to_string())?
        } else {
            std::fs::create_dir_all(&dir).map_err(io_err)?;
            DatasetMeta {
                id: id.clone(),
                created_at: now_secs(),
                name,
                frame_count: frames.len(),
                frames,
                versions: Vec::new(),
            }
        };
        // Ensure all referenced blobs exist even for pre-existing datasets.
        for (digest, bytes) in &blobs {
            let path = self.root.join("blobs").join(digest);
            if !path.exists() {
                std::fs::write(path, bytes).map_err(io_err)?;
            }
        }
        write_json_pretty(&meta_path, &meta)?;
        Ok(meta)
    }

    pub fn list_datasets(&self) -> Result<Vec<DatasetMeta>, String> {
        let mut out = Vec::new();
        let dir = self.root.join("datasets");
        for entry in std::fs::read_dir(dir).map_err(io_err)? {
            let entry = entry.map_err(io_err)?;
            let meta_path = entry.path().join("meta.json");
            if meta_path.exists() {
                let raw = std::fs::read_to_string(meta_path).map_err(io_err)?;
                out.push(serde_json::from_str::<DatasetMeta>(&raw).map_err(|e| e.to_string())?);
            }
        }
        out.sort_by(|a, b| b.created_at.partial_cmp(&a.created_at).unwrap_or(std::cmp::Ordering::Equal));
        Ok(out)
    }

    pub fn get_dataset(&self, id: &str) -> Result<DatasetMeta, String> {
        let path = self.dataset_dir(id).join("meta.json");
        let raw = std::fs::read_to_string(path).map_err(|e| format!("dataset {id} not found: {e}"))?;
        serde_json::from_str::<DatasetMeta>(&raw).map_err(|e| e.to_string())
    }

    /// Run analysis under `config`. If an identical (fingerprint, policy)
    /// version already exists it is returned; otherwise a new immutable version
    /// file is created.
    pub fn analyze_dataset(
        &self,
        id: &str,
        config: AnalysisConfig,
    ) -> Result<(DatasetMeta, AnalysisResult, VersionInfo), String> {
        let mut meta = self.get_dataset(id)?;
        let result = analyze(meta.frames.clone(), config.clone());

        if let Some(existing) = meta
            .versions
            .iter()
            .find(|v| v.fingerprint == result.fingerprint_sha256)
            .cloned()
        {
            let result_on_disk = self.load_result(id, existing.version)?;
            return Ok((meta, result_on_disk, existing));
        }
        let version = meta.versions.len() + 1;
        let file = format!("v{version}.json");
        let info = VersionInfo {
            version,
            fingerprint: result.fingerprint_sha256.clone(),
            overlap_policy: format!("{:?}", config.overlap_policy).to_lowercase(),
            timeout_seconds: config.timeout_seconds,
            session_count: result.sessions.len(),
            created_at: now_secs(),
            file: file.clone(),
        };
        write_json_pretty(&self.dataset_dir(id).join(&file), &result)?;
        meta.versions.push(info.clone());
        write_json_pretty(&self.dataset_dir(id).join("meta.json"), &meta)?;
        Ok((meta, result, info))
    }

    pub fn load_result(&self, id: &str, version: usize) -> Result<AnalysisResult, String> {
        let path = self.dataset_dir(id).join(format!("v{version}.json"));
        let raw = std::fs::read_to_string(path).map_err(io_err)?;
        serde_json::from_str::<AnalysisResult>(&raw).map_err(|e| e.to_string())
    }

    pub fn export_bundle(&self, id: &str) -> Result<ExportBundle, String> {
        let meta = self.get_dataset(id)?;
        let mut blobs = BTreeMap::new();
        for f in &meta.frames {
            let bytes = crate::types::decode_hex(&f.bytes_hex)?;
            let digest = crate::hash::sha256_hex(&bytes);
            blobs.insert(digest, crate::hash::hex(&bytes));
        }
        let mut analyses = BTreeMap::new();
        let m = self.get_dataset(id)?;
        for v in &m.versions {
            let path = self.dataset_dir(id).join(&v.file);
            if let Ok(text) = std::fs::read_to_string(path) {
                let result: AnalysisResult = serde_json::from_str(&text).map_err(|e| e.to_string())?;
                if !crate::analyze::FingerprintEnvelope::verify(&result) {
                    return Err(format!("stored version {} failed fingerprint verification", v.version));
                }
                let canonical = crate::analyze::canonical_json(&result);
                analyses.insert(v.file.clone(), canonical);
            }
        }
        Ok(ExportBundle {
            schema: "reasm-bench/bundle/v1".to_string(),
            dataset: m,
            blobs,
            analyses,
        })
    }

    pub fn import_bundle(&self, bundle: ExportBundle) -> Result<DatasetMeta, String> {
        if bundle.schema != "reasm-bench/bundle/v1" {
            return Err(format!("unsupported bundle schema {}", bundle.schema));
        }
        // Validate content addresses before persisting.
        for f in &bundle.dataset.frames {
            let bytes = crate::types::decode_hex(&f.bytes_hex)?;
            let digest = crate::hash::sha256_hex(&bytes);
            if !bundle.blobs.contains_key(&digest) {
                return Err(format!("bundle missing blob {digest}"));
            }
        }
        let meta = bundle.dataset;
        let dir = self.dataset_dir(&meta.id);
        std::fs::create_dir_all(&dir).map_err(io_err)?;
        for (digest, hex_bytes) in &bundle.blobs {
            let bytes = crate::types::decode_hex(hex_bytes)?;
            if crate::hash::sha256_hex(&bytes) != *digest {
                return Err(format!("blob {digest} failed content verification"));
            }
            let path = self.root.join("blobs").join(digest);
            if !path.exists() {
                std::fs::write(path, bytes).map_err(io_err)?;
            }
        }
        write_json_pretty(&dir.join("meta.json"), &meta)?;
        // Restore immutable analysis versions exactly; verify fingerprints.
        for v in &meta.versions {
            let path = dir.join(&v.file);
            if let Some(canonical) = bundle.analyses.get(&v.file) {
                let result: AnalysisResult =
                    serde_json::from_str(canonical).map_err(|e| e.to_string())?;
                if !crate::analyze::FingerprintEnvelope::verify(&result) {
                    return Err(format!("version {} fingerprint mismatch", v.version));
                }
                let pretty = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
                std::fs::write(path, pretty).map_err(io_err)?;
            } else if !path.exists() {
                let cfg = AnalysisConfig {
                    overlap_policy: parse_policy(&v.overlap_policy)?,
                    timeout_seconds: v.timeout_seconds,
                };
                self.analyze_dataset(&meta.id, cfg)?;
            }
        }
        Ok(meta)
    }
}

fn parse_policy(text: &str) -> Result<crate::reasm::OverlapPolicy, String> {
    match text {
        "firstseen" | "FirstSeen" | "first-seen" => Ok(crate::reasm::OverlapPolicy::FirstSeen),
        "lastseen" | "LastSeen" | "last-seen" => Ok(crate::reasm::OverlapPolicy::LastSeen),
        other => Err(format!("unknown overlap policy {other}")),
    }
}

pub fn normalize_indices(frames: &mut [RawFrame]) {
    for (i, f) in frames.iter_mut().enumerate() {
        if f.index.is_none() {
            f.index = Some(i);
        }
    }
}

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(io_err)
}

fn io_err(e: std::io::Error) -> String {
    e.to_string()
}
