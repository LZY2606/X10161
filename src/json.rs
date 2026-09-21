//! 极小 JSON 解析器/序列化器，无第三方依赖。
//!
//! 对象保持键插入顺序；`canonical` 序列化按键排序，用于结果指纹。

use std::fmt::Write as _;

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
    pub fn obj(pairs: Vec<(&str, Json)>) -> Self {
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) if n.fract() == 0.0 && *n >= 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Vec<(String, Json)>> {
        match self {
            Json::Obj(o) => Some(o),
        }
    }

    pub fn parse(input: &[u8]) -> Result<Json, String> {
        let mut p = Parser { buf: input, pos: 0 };
        p.skip_ws();
        let v = p.parse_value()?;
        p.skip_ws();
        if p.pos != p.buf.len() {
            return Err(format!("json: 位置 {} 之后仍有多余字节", p.pos));
        }
        Ok(v)
    }

    /// 确定性序列化：无空白、对象键按字典序排序。
    pub fn to_canonical(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => write_number(out, *n),
            Json::Str(s) => write_json_str(out, s),
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write_canonical(out);
                }
                out.push(']');
            }
            Json::Obj(o) => {
                let mut sorted: Vec<&(String, Json)> = o.iter().collect();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                out.push('{');
                for (i, (k, v)) in sorted.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_str(out, k);
                    out.push(':');
                    v.write_canonical(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_number(out: &mut String, n: f64) {
    if !n.is_finite() {
        out.push_str("null");
    } else if n.fract() == 0.0 && n.abs() < 9.007199254740992e15 {
        let _ = write!(out, "{}", *n as i64);
    } else {
        let _ = write!(out, "{}", n);
    }
}

pub fn write_json_str(out: &mut String, s: &str) {
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
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.buf.len() && matches!(self.buf[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        if self.pos >= self.buf.len() {
            return Err("json: 意外结束".into());
        }
        match self.buf[self.pos] {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => Ok(Json::Str(self.parse_string()?)),
            b't' | b'f' => self.parse_bool(),
            b'n' => self.parse_null(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            c => Err(format!("json: 位置 {} 处意外字符 {:?}", self.pos, c as char)),
        }
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.pos += 1;
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err("json: 对象键必须是字符串".into());
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.next() != Some(b':') {
                return Err("json: 对象键后缺少 ':'".into());
            }
            let val = self.parse_value()?;
            pairs.push((key, val));
            self.skip_ws();
            match self.next() {
                Some(b',') => continue,
                Some(b'}') => break,
                other => return Err(format!("json: 对象中意外分隔符 {:?}", other)),
            }
        }
        Ok(Json::Obj(pairs))
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.next() {
                Some(b',') => continue,
                Some(b']') => break,
                other => return Err(format!("json: 数组中意外分隔符 {:?}", other)),
            }
        }
        Ok(Json::Arr(items))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.pos += 1; // 开引号
        let mut s = String::new();
        loop {
            match self.next() {
                None => return Err("json: 字符串未闭合".into()),
                Some(b'"') => break,
                Some(b'\\') => match self.next() {
                    Some(b'"') => s.push('"'),
                    Some(b'\\') => s.push('\\'),
                    Some(b'/') => s.push('/'),
                    Some(b'n') => s.push('\n'),
                    Some(b'r') => s.push('\r'),
                    Some(b't') => s.push('\t'),
                    Some(b'b') => s.push('\u{08}'),
                    Some(b'f') => s.push('\u{0c}'),
                    Some(b'u') => {
                        let cp = self.parse_hex4()?;
                        if (0xD800..=0xDBFF).contains(&cp) {
                            if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                                return Err("json: 代理对不完整".into());
                            }
                            let lo = self.parse_hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&lo) {
                                return Err("json: 低位代理无效".into());
                            }
                            let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            s.push(char::from_u32(c).ok_or("json: 无效码点")?);
                        } else {
                            s.push(char::from_u32(cp).ok_or("json: 无效码点")?);
                        }
                    }
                    other => return Err(format!("json: 无效转义 {:?}", other)),
                },
                Some(b) => {
                    // UTF-8 原样累积
                    if b < 0x80 {
                        s.push(b as char);
                    } else {
                        let start = self.pos - 1;
                        let width = if b >= 0xF0 { 4 } else if b >= 0xE0 { 3 } else { 2 };
                        if start + width > self.buf.len() {
                            return Err("json: 非法 UTF-8".into());
                        }
                        match std::str::from_utf8(&self.buf[start..start + width]) {
                            Ok(chunk) => {
                                s.push_str(chunk);
                                self.pos = start + width;
                            }
                            Err(_) => return Err("json: 非法 UTF-8".into()),
                        }
                    }
                }
            }
        }
        Ok(s)
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self.next().ok_or("json: \\u 转义不完整")?;
            let d = (c as char).to_digit(16).ok_or("json: \\u 非十六进制")?;
            v = v * 16 + d;
        }
        Ok(v)
    }

    fn parse_bool(&mut self) -> Result<Json, String> {
        if self.buf[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(Json::Bool(true))
        } else if self.buf[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(Json::Bool(false))
        } else {
            Err("json: 非法字面量".into())
        }
    }

    fn parse_null(&mut self) -> Result<Json, String> {
        if self.buf[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(Json::Null)
        } else {
            Err("json: 非法字面量".into())
        }
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == b'.' || c == b'e' || c == b'E' || c == b'+' || c == b'-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.buf[start..self.pos]).map_err(|_| "json: 非法数字")?;
        text.parse::<f64>().map(Json::Num).map_err(|_| format!("json: 无法解析数字 {}", text))
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let c = self.buf.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }
}
