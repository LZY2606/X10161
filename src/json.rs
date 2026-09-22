// Minimal deterministic JSON implementation (std only).
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(i128),
    F64(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj() -> Json {
        Json::Obj(BTreeMap::new())
    }
    pub fn set(&mut self, k: &str, v: Json) {
        if let Json::Obj(m) = self {
            m.insert(k.to_string(), v);
        }
    }
    pub fn get(&self, k: &str) -> Option<&Json> {
        if let Json::Obj(m) = self {
            m.get(k)
        } else {
            None
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        if let Json::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        if let Json::Num(n) = self {
            u64::try_from(*n).ok()
        } else {
            None
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Json>> {
        if let Json::Arr(a) = self {
            Some(a)
        } else {
            None
        }
    }
    pub fn as_object(&self) -> Option<&BTreeMap<String, Json>> {
        if let Json::Obj(m) = self {
            Some(m)
        } else {
            None
        }
    }
    pub fn from_map(m: BTreeMap<String, Json>) -> Json {
        Json::Obj(m)
    }
    pub fn bytes(&self) -> Option<&[u8]> {
        Some(self.as_str()?.as_bytes())
    }
}

pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub fn bytes_to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(HEX[(x >> 4) as usize]);
        s.push(HEX[(x & 0xf) as usize]);
    }
    s
}

const HEX: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

pub fn to_string(v: &Json) -> String {
    let mut out = String::new();
    write(v, &mut out);
    out
}

pub fn to_string_pretty(v: &Json) -> String {
    let mut out = String::new();
    write_pretty(v, &mut out, 0);
    out.push('\n');
    out
}

fn write(v: &Json, out: &mut String) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Num(n) => out.push_str(&n.to_string()),
        Json::F64(f) => {
            if f.fract() == 0.0 && f.is_finite() {
                out.push_str(&format!("{:.1}", f));
            } else {
                out.push_str(&f.to_string());
            }
        }
        Json::Str(s) => write_str(s, out),
        Json::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out);
            }
            out.push(']');
        }
        Json::Obj(m) => {
            out.push('{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(k, out);
                out.push(':');
                write(v, out);
            }
            out.push('}');
        }
    }
}

fn write_pretty(v: &Json, out: &mut String, indent: usize) {
    let pad = "  ".repeat(indent);
    let pad1 = "  ".repeat(indent + 1);
    match v {
        Json::Arr(a) if a.is_empty() => out.push_str("[]"),
        Json::Obj(m) if m.is_empty() => out.push_str("{}"),
        Json::Arr(a) => {
            out.push_str("[\n");
            for (i, x) in a.iter().enumerate() {
                out.push_str(&pad1);
                write_pretty(x, out, indent + 1);
                if i + 1 < a.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push(']');
        }
        Json::Obj(m) => {
            out.push_str("{\n");
            for (i, (k, v)) in m.iter().enumerate() {
                out.push_str(&pad1);
                write_str(k, out);
                out.push_str(": ");
                write_pretty(v, out, indent + 1);
                if i + 1 < m.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push('}');
        }
        other => write(other, out),
    }
}

fn write_str(s: &str, out: &mut String) {
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

// ---- Parser ----

pub fn parse(input: &str) -> Result<Json, String> {
    let b = input.as_bytes();
    let mut p = Parser { b, i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != b.len() {
        return Err(format!("trailing data at {}", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() {
            match self.b[self.i] {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                _ => break,
            }
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        if self.i >= self.b.len() {
            return Err("unexpected end".into());
        }
        match self.b[self.i] {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Ok(Json::Str(self.string()?)),
            b't' | b'f' => self.boolean(),
            b'n' => self.null(),
            b'-' | b'0'..=b'9' => self.number(),
            c => Err(format!("unexpected '{}' at {}", c as char, self.i)),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.i += 1;
        let mut m = BTreeMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at {}", self.i));
            }
            self.i += 1;
            let v = self.value()?;
            m.insert(k, v);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at {}", self.i)),
            }
        }
        Ok(Json::Obj(m))
    }

    fn array(&mut self) -> Result<Json, String> {
        self.i += 1;
        let mut a = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Arr(a));
        }
        loop {
            a.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or ']' at {}", self.i)),
            }
        }
        Ok(Json::Arr(a))
    }

    fn string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err(format!("expected string at {}", self.i));
        }
        self.i += 1;
        let mut s = String::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    if self.i >= self.b.len() {
                        return Err("bad escape".into());
                    }
                    let e = self.b[self.i];
                    self.i += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'b' => s.push('\u{08}'),
                        b'f' => s.push('\u{0c}'),
                        b'u' => {
                            let cp = self.hex4()?;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                if self.peek() == Some(b'\\') {
                                    self.i += 1;
                                    if self.peek() == Some(b'u') {
                                        self.i += 1;
                                        let lo = self.hex4()?;
                                        if (0xDC00..=0xDFFF).contains(&lo) {
                                            let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                            if let Some(ch) = char::from_u32(c) {
                                                s.push(ch);
                                                continue;
                                            }
                                        }
                                    }
                                }
                                s.push('\u{FFFD}');
                            } else if let Some(ch) = char::from_u32(cp) {
                                s.push(ch);
                            } else {
                                s.push('\u{FFFD}');
                            }
                        }
                        _ => return Err(format!("bad escape \\{}", e as char)),
                    }
                }
                _ => {
                    // collect a UTF-8 run
                    let start = self.i - 1;
                    let len = if c < 0x80 {
                        1
                    } else if c >> 5 == 0b110 {
                        2
                    } else if c >> 4 == 0b1110 {
                        3
                    } else if c >> 3 == 0b11110 {
                        4
                    } else {
                        1
                    };
                    let end = (start + len).min(self.b.len());
                    self.i = end;
                    match std::str::from_utf8(&self.b[start..end]) {
                        Ok(part) => s.push_str(part),
                        Err(_) => s.push('\u{FFFD}'),
                    }
                }
            }
        }
        Err("unterminated string".into())
    }

    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.b.len() {
            return Err("bad \\u".into());
        }
        let mut v = 0u32;
        for _ in 0..4 {
            v = (v << 4) | hex_val(self.b[self.i]).ok_or("bad hex")? as u32;
            self.i += 1;
        }
        Ok(v)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let mut is_float = false;
        while self.i < self.b.len() {
            match self.b[self.i] {
                b'0'..=b'9' => self.i += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    is_float = true;
                    self.i += 1;
                }
                _ => break,
            }
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|e| e.to_string())?;
        if is_float {
            s.parse::<f64>()
                .map(Json::F64)
                .map_err(|e: std::num::ParseFloatError| e.to_string())
        } else {
            s.parse::<i128>()
                .map(Json::Num)
                .map_err(|e: std::num::ParseIntError| e.to_string())
        }
    }

    fn boolean(&mut self) -> Result<Json, String> {
        if self.b[self.i..].starts_with(b"true") {
            self.i += 4;
            Ok(Json::Bool(true))
        } else if self.b[self.i..].starts_with(b"false") {
            self.i += 5;
            Ok(Json::Bool(false))
        } else {
            Err(format!("bad literal at {}", self.i))
        }
    }

    fn null(&mut self) -> Result<Json, String> {
        if self.b[self.i..].starts_with(b"null") {
            self.i += 4;
            Ok(Json::Null)
        } else {
            Err(format!("bad literal at {}", self.i))
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
}
