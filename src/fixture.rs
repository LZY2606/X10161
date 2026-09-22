use crate::parse::RawFrame;
use crate::sha256::{hex_decode, hex_encode};
use serde::{Deserialize, Serialize};

pub const FIXTURE_FORMAT: &str = "pwgsb-fixture/1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fixture {
    pub format: String,
    pub name: String,
    pub frames: Vec<FixtureFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureFrame {
    pub index: u64,
    pub ts_micros: i64,
    /// Link-layer frame bytes, lowercase hex.
    pub data: String,
}

/// Deterministic serialization: frames sorted by (ts_micros, index) and
/// re-indexed densely, compact JSON, fixed field order.
pub fn to_canonical_fixture(frames: &[RawFrame], name: &str) -> String {
    let mut sorted: Vec<&RawFrame> = frames.iter().collect();
    sorted.sort_by_key(|f| (f.ts_micros, f.index));
    let fixture = Fixture {
        format: FIXTURE_FORMAT.to_string(),
        name: name.to_string(),
        frames: sorted
            .iter()
            .enumerate()
            .map(|(i, f)| FixtureFrame {
                index: i as u64,
                ts_micros: f.ts_micros,
                data: hex_encode(&f.data),
            })
            .collect(),
    };
    serde_json::to_string(&fixture).expect("fixture serialization is infallible")
}

pub fn parse_fixture(bytes: &[u8]) -> Result<Vec<RawFrame>, String> {
    let fixture: Fixture =
        serde_json::from_slice(bytes).map_err(|e| format!("fixture: invalid JSON: {}", e))?;
    if fixture.format != FIXTURE_FORMAT {
        return Err(format!(
            "fixture: unsupported format {:?} (want {:?})",
            fixture.format, FIXTURE_FORMAT
        ));
    }
    let mut frames = Vec::with_capacity(fixture.frames.len());
    for f in &fixture.frames {
        frames.push(RawFrame {
            index: f.index,
            ts_micros: f.ts_micros,
            data: hex_decode(&f.data).map_err(|e| format!("fixture frame {}: {}", f.index, e))?,
        });
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_fixture_is_deterministic() {
        let frames = vec![
            RawFrame { index: 5, ts_micros: 10, data: vec![1, 2, 3] },
            RawFrame { index: 2, ts_micros: 10, data: vec![4, 5] },
            RawFrame { index: 0, ts_micros: 3, data: vec![9] },
        ];
        let a = to_canonical_fixture(&frames, "t");
        let b = to_canonical_fixture(&frames, "t");
        assert_eq!(a, b);
        let parsed = parse_fixture(a.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].ts_micros, 3);
        assert_eq!(parsed[0].index, 0);
        assert_eq!(parsed[1].index, 1);
        assert_eq!(parsed[1].data, vec![4, 5]);
        assert_eq!(parsed[2].data, vec![1, 2, 3]);
    }
}
