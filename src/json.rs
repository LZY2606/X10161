//! 最小 JSON 值模型、解析器与确定性序列化器（键保持插入顺序）。

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn obj() -> Value {
        Value::Obj(Vec::new())
    }
    pub fn set(&mut self, k: &str, v: Value) {
        if let Value::Obj(entries) = self {
            for (key, val) in entries.iter_mut() {
                if key == k {
                    *val = v;
                    return;
                }
            }
            entries.push((k.to_string(), v));
        }
    }
    pub fn get(&self, k: &str) -> Option<&Value> {
        if let Value::Obj(entries) = self {
            entries.iter().find(|(key, _)| key == k).map(|(_, v)| v)
        } else {
            None
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i as i64),
            Value::Float(f) if f.fract() == 0.0 => Some(*f as i64),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        self.as_i64().filter(|i| *i >= 0).map(|i| i as u64)
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn serialize(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    pub fn write(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Int(i) => out.push_str(&i.to_string()),
            Value::Float(f) => out.push_str(&f.to_string()),
            Value::Str(s) => write_json_string(s, out),
            Value::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Value::Obj(entries) => {
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_string(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    pub fn parse(input: &str) -> Result<Value, String> {
        let bytes = input.as_bytes();
        let mut pos = 0usize;
        let v = parse_value(bytes, &mut pos)?;
        skip_ws(bytes, &mut pos);
        if pos != bytes.len() {
            return Err(format!("trailing data at byte {}", pos));
        }
        Ok(v)
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn skip_ws(b: &[u8], pos: &mut usize) {
    while *pos < b.len() && matches!(b[*pos], b' ' | b'\t' | b'\n' | b'\r') {
        *pos += 1;
    }
}

fn parse_value(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    skip_ws(b, pos);
    if *pos >= b.len() {
        return Err("unexpected end of input".into());
    }
    match b[*pos] {
        b'{' => parse_object(b, pos),
        b'[' => parse_array(b, pos),
        b'"' => parse_string(b, pos).map(Value::Str),
        b't' | b'f' => parse_bool(b, pos),
        b'n' => parse_null(b, pos),
        b'-' | b'0'..=b'9' => parse_number(b, pos),
        c => Err(format!("unexpected byte {} at {}", c as char, pos)),
    }
}

fn parse_object(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    *pos += 1;
    let mut entries = Vec::new();
    skip_ws(b, pos);
    if *pos < b.len() && b[*pos] == b'}' {
        *pos += 1;
        return Ok(Value::Obj(entries));
    }
    loop {
        skip_ws(b, pos);
        let key = parse_string(b, pos)?;
        skip_ws(b, pos);
        if *pos >= b.len() || b[*pos] != b':' {
            return Err(format!("expected ':' at {}", pos));
        }
        *pos += 1;
        let val = parse_value(b, pos)?;
        entries.push((key, val));
        skip_ws(b, pos);
        if *pos >= b.len() {
            return Err("unterminated object".into());
        }
        match b[*pos] {
            b',' => {
                *pos += 1;
            }
            b'}' => {
                *pos += 1;
                return Ok(Value::Obj(entries));
            }
            c => return Err(format!("expected ',' or '}}' got {} at {}", c as char, pos)),
        }
    }
}

fn parse_array(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    *pos += 1;
    let mut items = Vec::new();
    skip_ws(b, pos);
    if *pos < b.len() && b[*pos] == b']' {
        *pos += 1;
        return Ok(Value::Arr(items));
    }
    loop {
        let val = parse_value(b, pos)?;
        items.push(val);
        skip_ws(b, pos);
        if *pos >= b.len() {
            return Err("unterminated array".into());
        }
        match b[*pos] {
            b',' => {
                *pos += 1;
            }
            b']' => {
                *pos += 1;
                return Ok(Value::Arr(items));
            }
            c => return Err(format!("expected ',' or ']' got {} at {}", c as char, pos)),
        }
    }
}

fn parse_string(b: &[u8], pos: &mut usize) -> Result<String, String> {
    *pos += 1;
    let mut out = String::new();
    while *pos < b.len() {
        let c = b[*pos];
        *pos += 1;
        match c {
            b'"' => return Ok(out),
            b'\\' => {
                if *pos >= b.len() {
                    return Err("bad escape".into());
                }
                let e = b[*pos];
                *pos += 1;
                match e {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'b' => out.push('\u{08}'),
                    b'f' => out.push('\u{0c}'),
                    b'u' => {
                        if *pos + 4 > b.len() {
                            return Err("bad unicode escape".into());
                        }
                        let hex = std::str::from_utf8(&b[*pos..*pos + 4])
                            .map_err(|_| "bad unicode escape")?;
                        let cp = u32::from_str_radix(hex, 16)
                            .map_err(|_| "bad unicode escape")?;
                        *pos += 4;
                        if (0xD800..=0xDBFF).contains(&cp) {
                            // surrogate pair
                            if *pos + 6 > b.len()
                                || b[*pos] != b'\\'
                                || b[*pos + 1] != b'u'
                            {
                                return Err("bad surrogate pair".into());
                            }
                            let hex2 = std::str::from_utf8(&b[*pos + 2..*pos + 6])
                                .map_err(|_| "bad surrogate pair")?;
                            let lo = u32::from_str_radix(hex2, 16)
                                .map_err(|_| "bad surrogate pair")?;
                            *pos += 6;
                            let combined = 0x10000
                                + ((cp - 0xD800) << 10)
                                + (lo - 0xDC00);
                            out.push(char::from_u32(combined).ok_or("bad code point")?);
                        } else {
                            out.push(char::from_u32(cp).ok_or("bad code point")?);
                        }
                    }
                    _ => return Err(format!("bad escape \\{}", e as char)),
                }
            }
            _ => {
                // UTF-8 passthrough: collect run
                let start = *pos - 1;
                let mut len = match c {
                    0x00..=0x7F => 1,
                    0xC0..=0xDF => 2,
                    0xE0..=0xEF => 3,
                    0xF0..=0xF7 => 4,
                    _ => return Err("bad utf8".into()),
                };
                while len > 1 {
                    if *pos >= b.len() || (b[*pos] & 0xC0) != 0x80 {
                        return Err("bad utf8".into());
                    }
                    *pos += 1;
                    len -= 1;
                }
                out.push_str(
                    std::str::from_utf8(&b[start..*pos])
                        .map_err(|_| "bad utf8".to_string())?,
                );
            }
        }
    }
    Err("unterminated string".into())
}

fn parse_bool(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    if b.len() >= *pos + 4 && &b[*pos..*pos + 4] == b"true" {
        *pos += 4;
        Ok(Value::Bool(true))
    } else if b.len() >= *pos + 5 && &b[*pos..*pos + 5] == b"false" {
        *pos += 5;
        Ok(Value::Bool(false))
    } else {
        Err("bad literal".into())
    }
}

fn parse_null(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    if b.len() >= *pos + 4 && &b[*pos..*pos + 4] == b"null" {
        *pos += 4;
        Ok(Value::Null)
    } else {
        Err("bad literal".into())
    }
}

fn parse_number(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    let start = *pos;
    if b[*pos] == b'-' {
        *pos += 1;
    }
    while *pos < b.len() && b[*pos].is_ascii_digit() {
        *pos += 1;
    }
    let mut is_float = false;
    if *pos < b.len() && b[*pos] == b'.' {
        is_float = true;
        *pos += 1;
        while *pos < b.len() && b[*pos].is_ascii_digit() {
            *pos += 1;
        }
    }
    if *pos < b.len() && (b[*pos] == b'e' || b[*pos] == b'E') {
        is_float = true;
        *pos += 1;
        if *pos < b.len() && (b[*pos] == b'+' || b[*pos] == b'-') {
            *pos += 1;
        }
        while *pos < b.len() && b[*pos].is_ascii_digit() {
            *pos += 1;
        }
    }
    let text = std::str::from_utf8(&b[start..*pos]).map_err(|_| "bad number")?;
    if is_float {
        Ok(Value::Float(text.parse().map_err(|_| "bad number")?))
    } else {
        Ok(Value::Int(text.parse().map_err(|_| "bad integer")?))
    }
}

/// 仅用于合并键集合的小工具；常规序列化保持插入顺序。
#[allow(dead_code)]
pub fn index_object(v: &Value) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    if let Value::Obj(entries) = v {
        for (k, val) in entries {
            map.insert(k.clone(), val.clone());
        }
    }
    map
}
