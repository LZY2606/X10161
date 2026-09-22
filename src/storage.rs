use std::fs;
use std::path::{Path, PathBuf};

use crate::analyze;
use crate::capture::Capture;
use crate::hash;
use crate::json::{self, Json};
use crate::tcp::OverlapPolicy;

pub struct Store {
    root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Artifact {
    pub id: String,
    pub created_ts_us: i128,
    pub input_sha: String,
    pub policy: String,
    pub timeout_us: i128,
    pub result_sha: String,
    pub fingerprint: String,
    pub path: PathBuf,
}

impl Store {
    pub fn open(root: &Path) -> std::io::Result<Store> {
        fs::create_dir_all(root.join("inputs"))?;
        fs::create_dir_all(root.join("frames"))?;
        fs::create_dir_all(root.join("results"))?;
        Ok(Store {
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Save raw upload bytes, content-addressed. Returns (id, path).
    pub fn save_input(&self, data: &[u8]) -> std::io::Result<(String, PathBuf)> {
        let id = hash::hex(&hash::sha256(data));
        let path = self.root.join("inputs").join(format!("{}.bin", id));
        if !path.exists() {
            fs::write(&path, data)?;
        }
        Ok((id, path))
    }

    /// Save each original frame, content-addressed. Identical frames dedupe.
    pub fn save_frames(&self, cap: &Capture) -> std::io::Result<Vec<String>> {
        let mut out = Vec::new();
        for f in &cap.frames {
            let id = hash::hex(&hash::sha256(f));
            let p = self.root.join("frames").join(format!("{}.bin", id));
            if !p.exists() {
                fs::write(p, f)?;
            }
            out.push(id);
        }
        Ok(out)
    }

    /// Run an analysis version. Strategy changes create a new, immutable file;
    /// old results are never overwritten.
    pub fn analyze_version(
        &self,
        input_id: &str,
        data: &[u8],
        policy: OverlapPolicy,
        timeout_us: i128,
        now_us: i128,
    ) -> Result<Artifact, String> {
        let cap = crate::capture::load(data)?;
        let opts = analyze::AnalysisOptions { policy, timeout_us };
        let _frames = self.save_frames(&cap).map_err(|e| e.to_string())?;
        let mut result = analyze::run(&cap, &opts);
        let fingerprint = analyze::fingerprint(&result);
        let result_canon = json::to_string(&result);
        let result_sha = hash::hex(&hash::sha256(result_canon.as_bytes()));

        let mut meta = Json::obj();
        meta.set("version_id", Json::Null); // filled below
        meta.set("created_ts_us", Json::Num(now_us));
        meta.set("input_sha256", Json::Str(input_id.to_string()));
        meta.set("result_sha256", Json::Str(result_sha.clone()));
        meta.set("fingerprint", Json::Str(fingerprint.clone()));
        let mut c = Json::obj();
        c.set("overlap_policy", Json::Str(policy.name().into()));
        c.set("timeout_us", Json::Num(timeout_us));
        meta.set("config", c);
        result.set("analysis", meta);

        let vid = format!("{}-{}", &fingerprint[..16], &result_sha[..8]);
        if let Json::Obj(m) = &mut result {
            if let Some(Json::Obj(mm)) = m.get_mut("analysis") {
                mm.insert("version_id".into(), Json::Str(vid.clone()));
            }
        }

        let pretty = json::to_string_pretty(&result);
        let path = self.root.join("results").join(format!("{}.json", vid));
        // Content-addressed: identical config+input -> same id, write is idempotent.
        if !path.exists() {
            fs::write(&path, pretty).map_err(|e| e.to_string())?;
        }

        Ok(Artifact {
            id: vid,
            created_ts_us: now_us,
            input_sha: input_id.to_string(),
            policy: policy.name().into(),
            timeout_us,
            result_sha,
            fingerprint,
            path,
        })
    }

    pub fn list_versions(&self) -> Vec<Artifact> {
        let mut out = Vec::new();
        let dir = match fs::read_dir(self.root.join("results")) {
            Ok(d) => d,
            Err(_) => return out,
        };
        for e in dir.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            if let Ok(bytes) = fs::read(&p) {
                if let Ok(v) = json::parse(&String::from_utf8_lossy(&bytes)) {
                    if let Some(a) = v.get("analysis") {
                        let g = |k: &str| a.get(k).cloned().unwrap_or(Json::Null);
                        out.push(Artifact {
                            id: g("version_id").as_str().unwrap_or("").to_string(),
                            created_ts_us: g("created_ts_us").as_u64().unwrap_or(0) as i128,
                            input_sha: g("input_sha256").as_str().unwrap_or("").to_string(),
                            policy: a
                                .get("config")
                                .and_then(|c| c.get("overlap_policy"))
                                .and_then(|x| x.as_str())
                                .unwrap_or("")
                                .to_string(),
                            timeout_us: a
                                .get("config")
                                .and_then(|c| c.get("timeout_us"))
                                .and_then(|x| x.as_u64())
                                .unwrap_or(0) as i128,
                            result_sha: g("result_sha256").as_str().unwrap_or("").to_string(),
                            fingerprint: g("fingerprint").as_str().unwrap_or("").to_string(),
                            path: p.clone(),
                        });
                    }
                }
            }
        }
        out.sort_by_key(|a| a.created_ts_us);
        out
    }
}

pub fn now_us() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i128)
        .unwrap_or(0)
}

// Keep Capture referenced for API stability.
#[allow(dead_code)]
fn _cap_marker(_c: &Capture) {}
