use crate::analysis::analyze_capture;
use crate::capture::parse_capture;
use crate::json::{self, Value};
use crate::model::{AnalysisConfig, OverlapPolicy};
use crate::store::{ContentStore, DiskStore};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AnalysisRecord {
    pub id: String,
    pub input_sha256: String,
    pub fingerprint: String,
    pub config: AnalysisConfig,
    pub evidence: Value,
}

#[derive(Default)]
pub struct AnalysisEngine {
    records: Mutex<Vec<AnalysisRecord>>,
}

impl AnalysisEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn analyze(
        &self,
        input: &[u8],
        mut config: AnalysisConfig,
        overlap_policy: Option<OverlapPolicy>,
        store: &dyn ContentStore,
    ) -> Result<AnalysisRecord, String> {
        if let Some(policy) = overlap_policy {
            config.overlap_policy = policy;
        }
        let capture = parse_capture(input)?;
        let input_hash = store.put(input);
        let evidence = analyze_capture(&capture, config, store);
        let fingerprint_input = fingerprint_material(&input_hash, config, &evidence);
        let fingerprint = crate::util::hex_lower(&crate::util::sha256(
            fingerprint_input.as_bytes(),
        ));
        let id = fingerprint[..32].to_string();
        let record = AnalysisRecord {
            id,
            input_sha256: input_hash,
            fingerprint,
            config,
            evidence,
        };
        let mut records = self.records.lock().unwrap();
        if !records.iter().any(|existing| existing.id == record.id) {
            records.push(record.clone());
        }
        Ok(record)
    }

    pub fn get(&self, id: &str) -> Option<AnalysisRecord> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .find(|record| record.id == id)
            .cloned()
    }

    pub fn list(&self) -> Vec<AnalysisSummary> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .map(AnalysisSummary::from)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisSummary {
    pub id: String,
    pub input_sha256: String,
    pub fingerprint: String,
    pub overlap_policy: String,
}

impl From<&AnalysisRecord> for AnalysisSummary {
    fn from(record: &AnalysisRecord) -> Self {
        Self {
            id: record.id.clone(),
            input_sha256: record.input_sha256.clone(),
            fingerprint: record.fingerprint.clone(),
            overlap_policy: record.config.overlap_policy.as_str().into(),
        }
    }
}

pub fn config_from_query(query: Option<&str>) -> Result<Option<OverlapPolicy>, String> {
    let Some(query) = query else {
        return Ok(None);
    };
    for pair in query.split('&') {
        if let Some(raw) = pair.strip_prefix("policy=") {
            let value = percent_decode(raw);
            return Ok(Some(OverlapPolicy::parse(&value)?));
        }
        if let Some(raw) = pair.strip_prefix("overlap_policy=") {
            let value = percent_decode(raw);
            return Ok(Some(OverlapPolicy::parse(&value)?));
        }
    }
    Ok(None)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = hex_digit(bytes[index + 1]);
            let low = hex_digit(bytes[index + 2]);
            if let (Some(high), Some(low)) = (high, low) {
                out.push(high * 16 + low);
                index += 3;
                continue;
            }
        } else if bytes[index] == b'+' {
            out.push(b' ');
            index += 1;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn fingerprint_material(input_hash: &str, config: AnalysisConfig, evidence: &Value) -> String {
    let mut value = Value::object();
    value.put("config", config.to_json());
    value.put("evidence", evidence.clone());
    value.put("input_sha256", Value::from_string(input_hash));
    value.put("schema_version", Value::from_u64(1));
    value.canonical()
}

pub fn evidence_json(record: &AnalysisRecord) -> Value {
    let mut output = Value::object();
    output.put("analysis_id", Value::from_string(record.id.clone()));
    output.put("config", record.config.to_json());
    output.put("evidence", record.evidence.clone());
    output.put("fingerprint", Value::from_string(record.fingerprint.clone()));
    output.put("input_sha256", Value::from_string(record.input_sha256.clone()));
    output.put("schema_version", Value::from_u64(1));
    output
}

pub fn list_json(summaries: &[AnalysisSummary]) -> Value {
    let mut output = json::array();
    for summary in summaries {
        let mut value = Value::object();
        value.put("analysis_id", Value::from_string(summary.id.clone()));
        value.put("fingerprint", Value::from_string(summary.fingerprint.clone()));
        value.put("input_sha256", Value::from_string(summary.input_sha256.clone()));
        value.put("overlap_policy", Value::from_string(summary.overlap_policy.clone()));
        json::push(&mut output, value);
    }
    output
}

pub fn persist_analysis(disk: &DiskStore, record: &AnalysisRecord) -> Result<(), String> {
    let path: PathBuf = disk.analyses_dir().join(format!("{}.json", record.id));
    if path.exists() {
        return Ok(());
    }
    let temporary = disk
        .analyses_dir()
        .join(format!(".{}.tmp", record.id));
    fs::write(&temporary, evidence_json(record).canonical())
        .map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())
}

pub fn load_persisted(disk: &DiskStore, engine: Arc<AnalysisEngine>) -> Result<(), String> {
    for entry in fs::read_dir(disk.analyses_dir()).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let wrapper = json::parse(&text)?;
        let id = wrapper.get("analysis_id").and_then(Value::as_str).ok_or("missing id")?;
        let fingerprint = wrapper
            .get("fingerprint")
            .and_then(Value::as_str)
            .ok_or("missing fingerprint")?;
        let input_hash = wrapper
            .get("input_sha256")
            .and_then(Value::as_str)
            .ok_or("missing input hash")?;
        let config = parse_persisted_config(wrapper.get("config"))?;
        let evidence = wrapper
            .get("evidence")
            .cloned()
            .ok_or("missing evidence")?;
        let record = AnalysisRecord {
            id: id.into(),
            input_sha256: input_hash.into(),
            fingerprint: fingerprint.into(),
            config,
            evidence,
        };
        engine
            .records
            .lock()
            .unwrap()
            .push(record);
    }
    Ok(())
}

fn parse_persisted_config(value: Option<&Value>) -> Result<AnalysisConfig, String> {
    let mut config = AnalysisConfig::default();
    if let Some(value) = value {
        if let Some(policy) = value.get("overlap_policy").and_then(Value::as_str) {
            config.overlap_policy = OverlapPolicy::parse(policy)?;
        }
        if let Some(timeout) = value.get("tcp_timeout_ns").and_then(Value::as_i64) {
            config.tcp_timeout_ns = timeout;
        }
        if let Some(value) = value.get("max_ipv4_datagram").and_then(Value::as_u64) {
            config.max_ipv4_datagram = value as usize;
        }
        if let Some(value) = value.get("max_ipv6_datagram").and_then(Value::as_u64) {
            config.max_ipv6_datagram = value as usize;
        }
        if let Some(value) = value.get("fin_rst_race_ns").and_then(Value::as_i64) {
            config.fin_rst_race_ns = value;
        }
    }
    Ok(config)
}
