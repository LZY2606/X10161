use crate::json::{self, Json};
use crate::model::LinkType;

pub struct Capture {
    pub link: LinkType,
    pub frames: Vec<Vec<u8>>,
    pub ts_us: Vec<i128>,
    pub orig_len: Vec<usize>,
    pub kind: String,
}

impl Capture {
    pub fn len(&self) -> usize {
        self.frames.len()
    }
}

pub fn load(data: &[u8]) -> Result<Capture, String> {
    if data.len() >= 4 {
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic == 0xa1b2c3d4 || magic == 0xa1b23c4d || magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1
        {
            return parse_pcap(data);
        }
    }
    let s = std::str::from_utf8(data)
        .map_err(|_| "input is neither pcap nor UTF-8 JSON".to_string())?;
    parse_fixture(s)
}

fn parse_pcap(data: &[u8]) -> Result<Capture, String> {
    if data.len() < 24 {
        return Err("pcap too short".into());
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (swap, nano) = match magic {
        0xa1b2c3d4 => (false, false),
        0xa1b23c4d => (false, true),
        0xd4c3b2a1 => (true, false),
        0x4d3cb2a1 => (true, true),
        _ => return Err("bad pcap magic".into()),
    };
    let rd_u16 = |b: &[u8]| {
        if swap {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        }
    };
    let rd_u32 = |b: &[u8]| {
        if swap {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let _version = (rd_u16(&data[4..6]), rd_u16(&data[6..8]));
    let link = LinkType::from_u32(rd_u32(&data[20..24]))
        .ok_or_else(|| format!("unsupported linktype {}", rd_u32(&data[20..24])))?;

    let mut frames = Vec::new();
    let mut ts_us = Vec::new();
    let mut orig_len = Vec::new();
    let mut off = 24usize;
    while off + 16 <= data.len() {
        let sec = rd_u32(&data[off..off + 4]);
        let frac = rd_u32(&data[off + 4..off + 8]);
        let incl = rd_u32(&data[off + 8..off + 12]) as usize;
        let orig = rd_u32(&data[off + 12..off + 16]) as usize;
        off += 16;
        if off + incl > data.len() {
            return Err("truncated pcap record".into());
        }
        let mut ts = sec as i128 * 1_000_000;
        if nano {
            ts += frac as i128 / 1000;
        } else {
            ts += frac as i128;
        }
        frames.push(data[off..off + incl].to_vec());
        ts_us.push(ts);
        orig_len.push(orig.max(incl));
        off += incl;
    }
    Ok(Capture {
        link,
        frames,
        ts_us,
        orig_len,
        kind: "pcap".into(),
    })
}

fn parse_fixture(s: &str) -> Result<Capture, String> {
    let v = json::parse(s)?;
    let link_code = v.get("linktype").and_then(|x| x.as_u64()).unwrap_or(1);
    let link = LinkType::from_u32(link_code as u32)
        .ok_or_else(|| format!("unsupported linktype {}", link_code))?;
    let arr = v
        .get("frames")
        .and_then(|x| x.as_array())
        .ok_or("fixture needs a frames array")?;
    let mut frames = Vec::new();
    let mut ts_us = Vec::new();
    let mut orig_len = Vec::new();
    for (i, f) in arr.iter().enumerate() {
        let hex = f
            .get("data")
            .or_else(|| f.get("hex"))
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("frame {} missing data", i))?;
        let bytes = json::hex_to_bytes(hex).ok_or_else(|| format!("frame {} bad hex", i))?;
        let ts = f
            .get("ts_us")
            .or_else(|| f.get("ts"))
            .and_then(|x| match x {
                Json::Num(n) => Some(*n),
                _ => None,
            })
            .unwrap_or(i as i128);
        let orig = f
            .get("orig_len")
            .and_then(|x| x.as_u64())
            .map(|x| x as usize)
            .unwrap_or(bytes.len());
        let blen = bytes.len();
        frames.push(bytes);
        ts_us.push(ts);
        orig_len.push(orig.max(blen));
    }
    Ok(Capture {
        link,
        frames,
        ts_us,
        orig_len,
        kind: "fixture".into(),
    })
}
