use crate::json::{self, Value};
use crate::util::{base64_decode, parse_hex};

#[derive(Debug, Clone)]
pub struct FrameInput {
    pub specified_index: Option<usize>,
    pub timestamp_ns: i64,
    pub link_type: Option<u16>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CaptureInput {
    pub default_link_type: u16,
    pub frames: Vec<FrameInput>,
}

pub fn parse_capture(input: &[u8]) -> Result<CaptureInput, String> {
    if input.len() >= 4 && &input[..4] == b"\xd4\xc3\xb2\xa1"
        || input.len() >= 4 && &input[..4] == b"\x4d\x3c\xb2\xa1"
    {
        parse_pcap(input, false)
    } else if input.len() >= 4 && &input[..4] == b"\xa1\xb2\xc3\xd4"
        || input.len() >= 4 && &input[..4] == b"\xa1\xb2\x3c\x4d"
    {
        parse_pcap(input, true)
    } else {
        parse_fixture(std::str::from_utf8(input).map_err(|_| {
            "input is neither a pcap file nor UTF-8 JSON fixture".to_string()
        })?)
    }
}

pub fn parse_fixture(input: &str) -> Result<CaptureInput, String> {
    let value = json::parse(input)?;
    let object = value
        .as_object()
        .ok_or_else(|| "fixture root must be an object".to_string())?;
    let frames_value = object
        .get("frames")
        .and_then(Value::as_array)
        .ok_or_else(|| "fixture requires a frames array".to_string())?;
    let default_link_type = object
        .get("link_type")
        .map(read_link_type)
        .transpose()?
        .unwrap_or(1);
    let mut frames = Vec::with_capacity(frames_value.len());
    for frame_value in frames_value {
        let object = frame_value
            .as_object()
            .ok_or_else(|| "each frame must be an object".to_string())?;
        let bytes = if let Some(hex) = object.get("hex").and_then(Value::as_str) {
            parse_hex(hex)?
        } else if let Some(base64) = object.get("base64").and_then(Value::as_str) {
            base64_decode(base64)?
        } else {
            return Err("each frame requires hex or base64 bytes".into());
        };
        frames.push(FrameInput {
            specified_index: object.get("frame_index").and_then(Value::as_u64).map(|v| v as usize),
            timestamp_ns: object
                .get("timestamp_ns")
                .and_then(Value::as_i64)
                .or_else(|| {
                    object
                        .get("timestamp_us")
                        .and_then(Value::as_i64)
                        .map(|value| value.saturating_mul(1_000))
                })
                .unwrap_or(0),
            link_type: object.get("link_type").map(read_link_type).transpose()?,
            bytes,
        });
    }
    Ok(CaptureInput {
        default_link_type,
        frames,
    })
}

fn read_link_type(value: &Value) -> Result<u16, String> {
    value
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| "link_type must be an unsigned 16-bit integer".to_string())
}

fn parse_pcap(input: &[u8], big_endian: bool) -> Result<CaptureInput, String> {
    if input.len() < 24 {
        return Err("pcap global header is shorter than 24 bytes".into());
    }
    let nanos = &input[..4] == if big_endian {
        b"\xa1\xb2\x3c\x4d"
    } else {
        b"\x4d\x3c\xb2\xa1"
    };
    let read_u16 = |offset: usize| -> u16 {
        let value = u16::from_le_bytes([input[offset], input[offset + 1]]);
        if big_endian {
            value.swap_bytes()
        } else {
            value
        }
    };
    let read_u32 = |offset: usize| -> u32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&input[offset..offset + 4]);
        let value = u32::from_le_bytes(bytes);
        if big_endian {
            value.swap_bytes()
        } else {
            value
        }
    };
    let major = read_u16(4);
    let minor = read_u16(6);
    if major != 2 || minor != 4 {
        return Err("only pcap version 2.4 is supported".into());
    }
    let link_type = read_u32(20) as u16;
    if !matches!(link_type, 0 | 1 | 101 | 113) {
        return Err(format!("unsupported pcap link type {link_type}"));
    }
    let mut cursor = 24;
    let mut frames = Vec::new();
    while cursor < input.len() {
        if cursor + 16 > input.len() {
            return Err("truncated pcap record header".into());
        }
        let seconds = read_u32(cursor) as i64;
        let fraction = read_u32(cursor + 4) as i64;
        let included = read_u32(cursor + 8) as usize;
        let original = read_u32(cursor + 12) as usize;
        cursor += 16;
        if included > original || cursor + included > input.len() {
            return Err("pcap record length is invalid".into());
        }
        let timestamp_ns = if nanos {
            seconds
                .saturating_mul(1_000_000_000)
                .saturating_add(fraction)
        } else {
            seconds
                .saturating_mul(1_000_000_000)
                .saturating_add(fraction.saturating_mul(1_000))
        };
        frames.push(FrameInput {
            specified_index: None,
            timestamp_ns,
            link_type: None,
            bytes: input[cursor..cursor + included].to_vec(),
        });
        cursor += included;
    }
    Ok(CaptureInput {
        default_link_type: link_type,
        frames,
    })
}

pub fn write_pcap(frames: &[(i64, Vec<u8>)], link_type: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\xd4\xc3\xb2\xa1");
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&65_535u32.to_le_bytes());
    out.extend_from_slice(&u32::from(link_type).to_le_bytes());
    for (timestamp_ns, bytes) in frames {
        let seconds = timestamp_ns.div_euclid(1_000_000_000).max(0) as u32;
        let micros = ((timestamp_ns.rem_euclid(1_000_000_000)) / 1_000) as u32;
        out.extend_from_slice(&seconds.to_le_bytes());
        out.extend_from_slice(&micros.to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    out
}
