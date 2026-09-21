use crate::util::{hex_lower, sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub trait ContentStore {
    fn put(&self, content: &[u8]) -> String;
    fn get(&self, hash: &str) -> Option<Vec<u8>>;
    fn exists(&self, hash: &str) -> bool;
}

#[derive(Default)]
pub struct MemoryStore {
    values: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl ContentStore for MemoryStore {
    fn put(&self, content: &[u8]) -> String {
        let hash = hex_lower(&sha256(content));
        self.values
            .lock()
            .unwrap()
            .entry(hash.clone())
            .or_insert_with(|| content.to_vec());
        hash
    }

    fn get(&self, hash: &str) -> Option<Vec<u8>> {
        self.values.lock().unwrap().get(hash).cloned()
    }

    fn exists(&self, hash: &str) -> bool {
        self.values.lock().unwrap().contains_key(hash)
    }
}

pub struct DiskStore {
    root: PathBuf,
}

impl DiskStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("content")).map_err(|error| error.to_string())?;
        fs::create_dir_all(root.join("analyses")).map_err(|error| error.to_string())?;
        Ok(Self { root })
    }

    pub fn analyses_dir(&self) -> PathBuf {
        self.root.join("analyses")
    }

    fn path_for(&self, hash: &str) -> Option<PathBuf> {
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(self.root.join("content").join(&hash[0..2]).join(hash))
    }
}

impl ContentStore for DiskStore {
    fn put(&self, content: &[u8]) -> String {
        let hash = hex_lower(&sha256(content));
        if let Some(path) = self.path_for(&hash) {
            if !path.exists() {
                fs::create_dir_all(path.parent().unwrap()).ok();
                let temporary = self.root.join(format!(".{hash}.tmp"));
                fs::write(&temporary, content).ok();
                fs::rename(&temporary, path).ok();
            }
        }
        hash
    }

    fn get(&self, hash: &str) -> Option<Vec<u8>> {
        fs::read(self.path_for(hash)?).ok()
    }

    fn exists(&self, hash: &str) -> bool {
        self.path_for(hash).map(|path| path.exists()).unwrap_or(false)
    }
}
