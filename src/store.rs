use crate::analyze::{sha256_hex, Analysis, Config};
use crate::pcap::Frame;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisMeta {
    pub id: String,
    pub name: String,
    pub config: Config,
    pub frame_hashes: Vec<String>,
    pub frame_ts_ns: Vec<u64>,
    pub created_unix: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AnalysisSummary {
    pub id: String,
    pub name: String,
    pub policy: String,
    pub frame_count: usize,
    pub session_count: usize,
    pub fingerprint: String,
    pub created_unix: u64,
}

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("frames"))?;
        fs::create_dir_all(root.join("analyses"))?;
        Ok(Store { root })
    }

    /// Content-addressed save of raw frames; returns hashes in frame order.
    pub fn save_frames(&self, frames: &[Frame]) -> io::Result<Vec<String>> {
        let mut hashes = Vec::with_capacity(frames.len());
        for f in frames {
            let hash = sha256_hex(&f.data);
            let dir = self.root.join("frames").join(&hash[..2]);
            fs::create_dir_all(&dir)?;
            let path = dir.join(format!("{hash}.bin"));
            if !path.exists() {
                fs::write(path, &f.data)?;
            }
            hashes.push(hash);
        }
        Ok(hashes)
    }

    pub fn load_frames(&self, hashes: &[String], ts_ns: &[u64]) -> io::Result<Vec<Frame>> {
        let mut frames = Vec::with_capacity(hashes.len());
        for (i, h) in hashes.iter().enumerate() {
            let path = self.root.join("frames").join(&h[..2]).join(format!("{h}.bin"));
            let data = fs::read(&path)?;
            frames.push(Frame {
                index: i as u64,
                ts_ns: ts_ns.get(i).copied().unwrap_or(0),
                data,
            });
        }
        Ok(frames)
    }

    /// Analysis version id derives from input frames + full config, so a
    /// policy change produces a new version and old results stay untouched.
    pub fn analysis_id(frame_hashes: &[String], config: &Config) -> String {
        #[derive(Serialize)]
        struct Id<'a> {
            frames: &'a [String],
            config: &'a Config,
        }
        let json = serde_json::to_string(&Id {
            frames: frame_hashes,
            config,
        })
        .expect("id serialization");
        sha256_hex(json.as_bytes())[..16].to_string()
    }

    pub fn save_analysis(
        &self,
        name: &str,
        config: &Config,
        frames: &[Frame],
        analysis: &Analysis,
    ) -> io::Result<String> {
        let id = Self::analysis_id(&analysis.frame_hashes, config);
        let dir = self.root.join("analyses").join(&id);
        fs::create_dir_all(&dir)?;
        let meta = AnalysisMeta {
            id: id.clone(),
            name: name.to_string(),
            config: config.clone(),
            frame_hashes: analysis.frame_hashes.clone(),
            frame_ts_ns: frames.iter().map(|f| f.ts_ns).collect(),
            created_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        fs::write(
            dir.join("meta.json"),
            serde_json::to_string_pretty(&meta).expect("meta json"),
        )?;
        fs::write(
            dir.join("result.json"),
            serde_json::to_string_pretty(&analysis.result).expect("result json"),
        )?;
        fs::write(
            dir.join("evidence.json"),
            serde_json::to_string_pretty(&analysis.evidence).expect("evidence json"),
        )?;
        for p in &analysis.payloads {
            fs::write(dir.join(&p.file), &p.data)?;
        }
        Ok(id)
    }

    pub fn list(&self) -> io::Result<Vec<AnalysisSummary>> {
        let mut out = Vec::new();
        let dir = self.root.join("analyses");
        if !dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let meta_path = entry.path().join("meta.json");
            let result_path = entry.path().join("result.json");
            if !meta_path.exists() || !result_path.exists() {
                continue;
            }
            let meta: AnalysisMeta =
                serde_json::from_slice(&fs::read(&meta_path)?).map_err(bad_data)?;
            let result: serde_json::Value =
                serde_json::from_slice(&fs::read(&result_path)?).map_err(bad_data)?;
            out.push(AnalysisSummary {
                id: meta.id,
                name: meta.name,
                policy: meta.config.overlap,
                frame_count: meta.frame_hashes.len(),
                session_count: result["sessions"]
                    .as_array()
                    .map(|a| a.len())
                    .unwrap_or(0),
                fingerprint: result["fingerprint"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                created_unix: meta.created_unix,
            });
        }
        out.sort_by_key(|s| (s.created_unix, s.id.clone()));
        Ok(out)
    }

    fn analysis_dir(&self, id: &str) -> PathBuf {
        self.root.join("analyses").join(sanitize(id))
    }

    pub fn load_result(&self, id: &str) -> io::Result<String> {
        fs::read_to_string(self.analysis_dir(id).join("result.json"))
    }

    pub fn load_evidence(&self, id: &str) -> io::Result<String> {
        fs::read_to_string(self.analysis_dir(id).join("evidence.json"))
    }

    pub fn load_meta(&self, id: &str) -> io::Result<AnalysisMeta> {
        let text = fs::read_to_string(self.analysis_dir(id).join("meta.json"))?;
        serde_json::from_str(&text).map_err(bad_data)
    }

    pub fn load_payload(&self, id: &str, file: &str) -> io::Result<Vec<u8>> {
        let name = Path::new(file)
            .file_name()
            .ok_or_else(|| bad_data("bad file name"))?
            .to_owned();
        fs::read(self.analysis_dir(id).join(name))
    }
}

fn sanitize(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(64)
        .collect()
}

fn bad_data<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
