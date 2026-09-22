//! Minimal deterministic JSON value, parser and serializer.
//! Canonical serialization (sorted object keys) is used for fingerprints.

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn obj() -> Json {
        Json::Obj(Vec::new())
    }

    pub fn set(&mut self, key: &str, val: Json) {
        if let Json::Obj(m) = self {
            m.push((key.to_string(), val));
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        if let Json::Obj(m) = self {
            m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
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

    pub fn as_num(&self) -> Option<f64> {
        if let Json::Num(n) = self {
            Some(*n)
        } else {
            None
        }
    }

    pub fn as_arr(&self) -> Option<&Vec<Json>> {
        if let Json::Arr(a) = self {
            Some(a)
        } else {
            None
        }
    }

    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    pub fn num(n: impl Into<f64>) -> Json {
        Json::Num(n.into())
    }

    /// Serialize with object keys sorted -> stable canonical form.
    pub fn to_canonical(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, true, 0);
        out
    }

    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, false, 0);
        out
    }

    fn write(&self, out: &mut String, compact: bool, indent: usize) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => write_num(*n, out),
            Json::Str(s) => write_str(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if !compact && !items.is_empty() {
                        out.push('\n');
                        out.push_str(&"  ".repeat(indent + 1));
                    }
                    it.write(out, compact, indent + 1);
                }
                if !compact && !items.is_empty() {
                    out.push('\n');
                    out.push_str(&"  ".repeat(indent));
                }
                out.push(']');
            }
            Json::Obj(m) => {
                let mut entries: Vec<&(String, Json)> = m.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if !compact && !entries.is_empty() {
                        out.push('\n');
                        out.push_str(&"  ".repeat(indent + 1));
                    }
                    write_str(k, out);
                    out.push(':');
                    if !compact {
                        out.push(' ');
                    }
                    v.write(out, compact, indent + 1);
                }
                if !compact && !entries.is_empty() {
                    out.push('\n');
                    out.push_str(&"  ".repeat(indent));
                }
                out.push('}');
            }
        }
    }

    pub fn parse(input: &str) -> Result<Json, String> {
        let bytes = input.as_bytes();
        let mut p = Parser { b: bytes, i: 0 };
        p.skip_ws();
        let v = p.value()?;
        p.skip_ws();
        if p.i != bytes.len() {
            return Err(format!("trailing data at byte {}", p.i));
        }
        Ok(v)
    }
}

fn write_num(n: f64, out: &mut String) {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 9.0e15 {
        out.push_str(&format!("{}", n as i64));
    } else if n.is_finite() {
        let s = format!("{}", n);
        out.push_str(&s);
    } else {
        out.push_str("null");
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
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Result<u8, String> {
        self.b.get(self.i).copied().ok_or_else(|| "unexpected end of input".to_string())
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek()? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Ok(Json::Str(self.string()?)),
            b't' => self.lit("true", Json::Bool(true)),
            b'f' => self.lit("false", Json::Bool(false)),
            b'n' => self.lit("null", Json::Null),
            _ => self.number(),
        }
    }

    fn lit(&mut self, word: &str, v: Json) -> Result<Json, String> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("invalid literal at byte {}", self.i))
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.peek()? == b'-' {
            self.i += 1;
        }
        while self.i < self.b.len()
            && matches!(self.b[self.i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        {
            self.i += 1;
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|e| e.to_string())?;
        s.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("invalid number '{}' at byte {}", s, start))
    }

    fn string(&mut self) -> Result<String, String> {
        if self.peek()? != b'"' {
            return Err(format!("expected string at byte {}", self.i));
        }
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            if self.i + 4 > self.b.len() {
                                return Err("bad \\u escape".to_string());
                            }
                            let hex = std::str::from_utf8(&self.b[self.i..self.i + 4])
                                .map_err(|e| e.to_string())?;
                            let cp = u32::from_str_radix(hex, 16)
                                .map_err(|_| "bad \\u escape".to_string())?;
                            self.i += 4;
                            // Handle surrogate pairs.
                            if (0xD800..0xDC00).contains(&cp) {
                                if self.b[self.i..].starts_with(b"\\u") {
                                    let hex2 =
                                        std::str::from_utf8(&self.b[self.i + 2..self.i + 6])
                                            .map_err(|e| e.to_string())?;
                                    let lo = u32::from_str_radix(hex2, 16)
                                        .map_err(|_| "bad \\u escape".to_string())?;
                                    self.i += 6;
                                    let combined =
                                        0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                    out.push(
                                        char::from_u32(combined).unwrap_or('\u{FFFD}'),
                                    );
                                } else {
                                    out.push('\u{FFFD}');
                                }
                            } else {
                                out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                            }
                        }
                        _ => return Err(format!("bad escape at byte {}", self.i)),
                    }
                }
                c if c < 0x80 => out.push(c as char),
                c => {
                    // UTF-8 multibyte: determine length and copy bytes.
                    let len = if c >= 0xF0 {
                        4
                    } else if c >= 0xE0 {
                        3
                    } else {
                        2
                    };
                    let start = self.i - 1;
                    let end = start + len;
                    if end > self.b.len() {
                        return Err("truncated utf-8".to_string());
                    }
                    let s = std::str::from_utf8(&self.b[start..end])
                        .map_err(|_| "invalid utf-8".to_string())?;
                    out.push_str(s);
                    self.i = end;
                }
            }
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.i += 1; // consume '{'
        let mut m = Vec::new();
        self.skip_ws();
        if self.peek()? == b'}' {
            self.i += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.skip_ws();
            let k = self.string()?;
            self.skip_ws();
            if self.peek()? != b':' {
                return Err(format!("expected ':' at byte {}", self.i));
            }
            self.i += 1;
            let v = self.value()?;
            m.push((k, v));
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                }
                b'}' => {
                    self.i += 1;
                    return Ok(Json::Obj(m));
                }
                c => return Err(format!("unexpected '{}' in object at byte {}", c as char, self.i)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.i += 1; // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek()? == b']' {
            self.i += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            let v = self.value()?;
            items.push(v);
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                }
                b']' => {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                c => return Err(format!("unexpected '{}' in array at byte {}", c as char, self.i)),
            }
        }
    }
}

pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).ok_or("bad hex digit")?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or("bad hex digit")?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}
