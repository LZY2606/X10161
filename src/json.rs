//! 最小 JSON 解析器与确定性序列化器（无外部依赖）。
//!
//! 对象保持键的插入/解析顺序；`canonical` 会按键排序，用于内容指纹。

use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// 整数
    Int(i64),
    /// 浮点（仅夹具解析使用，指纹路径不使用）
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
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
            Value::Int(i) => Some(*i),
            Value::Float(f) => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }
}

pub fn parse(input: &str) -> Result<Value, String> {
    let bytes = input.as_bytes();
    let mut p = Parser { b: bytes, i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err(format!("json: 第 {} 字节后存在多余内容", p.i));
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

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn value(&mut self) -> Result<Value, String> {
        self.ws();
        match self.peek() {
            None => Err("json: 意外结束".into()),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') | Some(b'f') => self.boolean(),
            Some(b'n') => self.null(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(format!(
                "json: 位置 {} 出现意外字符 {:?}",
                self.i, c as char
            )),
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(out));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(format!("json: 位置 {} 期望字符串键", self.i));
            }
            let key = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(format!("json: 位置 {} 期望 ':'", self.i));
            }
            self.i += 1;
            let val = self.value()?;
            out.push((key, val));
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(out));
                }
                _ => return Err(format!("json: 位置 {} 期望 ',' 或 '}}'", self.i)),
            }
        }
    }

    fn array(&mut self) -> Result<Value, String> {
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(out));
        }
        loop {
            let v = self.value()?;
            out.push(v);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(out));
                }
                _ => return Err(format!("json: 位置 {} 期望 ',' 或 ']'", self.i)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut out = String::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.b.get(self.i).copied().ok_or("json: 转义意外结束")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if self.i + 4 > self.b.len() {
                                return Err("json: \\u 转义不完整".into());
                            }
                            let hex4 = std::str::from_utf8(&self.b[self.i..self.i + 4])
                                .map_err(|_| "json: 非法 \\u 转义".to_string())?;
                            let cp = u32::from_str_radix(hex4, 16)
                                .map_err(|_| "json: 非法 \\u 十六进制".to_string())?;
                            self.i += 4;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                // 高代理项，需要紧跟 \uXXXX 低代理项
                                if self.b.get(self.i..self.i + 2) == Some(&[b'\\', b'u'][..]) {
                                    let lo = u32::from_str_radix(
                                        std::str::from_utf8(&self.b[self.i + 2..self.i + 6])
                                            .map_err(|_| "json: 非法代理对".to_string())?,
                                        16,
                                    )
                                    .map_err(|_| "json: 非法代理对".to_string())?;
                                    self.i += 6;
                                    let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                    if let Some(ch) = char::from_u32(c) {
                                        out.push(ch);
                                    } else {
                                        return Err("json: 非法代理码点".into());
                                    }
                                } else {
                                    return Err("json: 高代理项缺少低代理项".into());
                                }
                            } else if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                            } else {
                                return Err("json: 非法 unicode 码点".into());
                            }
                        }
                        _ => return Err(format!("json: 非法转义 \\{}", e as char)),
                    }
                }
                _ => {
                    // 原样收集 UTF-8 字节
                    let start = self.i - 1;
                    let len = utf8_len(c);
                    if start + len > self.b.len() {
                        return Err("json: UTF-8 序列被截断".into());
                    }
                    out.push_str(
                        std::str::from_utf8(&self.b[start..start + len])
                            .map_err(|_| "json: 非法 UTF-8".to_string())?,
                    );
                    self.i = start + len;
                }
            }
        }
        Err("json: 字符串未闭合".into())
    }

    fn boolean(&mut self) -> Result<Value, String> {
        if self.b[self.i..].starts_with(b"true") {
            self.i += 4;
            Ok(Value::Bool(true))
        } else if self.b[self.i..].starts_with(b"false") {
            self.i += 5;
            Ok(Value::Bool(false))
        } else {
            Err(format!("json: 位置 {} 非法字面量", self.i))
        }
    }

    fn null(&mut self) -> Result<Value, String> {
        if self.b[self.i..].starts_with(b"null") {
            self.i += 4;
            Ok(Value::Null)
        } else {
            Err(format!("json: 位置 {} 非法字面量", self.i))
        }
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let mut is_float = false;
        while self.i < self.b.len() {
            let c = self.b[self.i];
            match c {
                b'0'..=b'9' => self.i += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    is_float = true;
                    self.i += 1;
                }
                _ => break,
            }
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "json: 非法数字")?;
        if is_float {
            s.parse::<f64>()
                .map(Value::Float)
                .map_err(|_| format!("json: 非法数字 {}", s))
        } else {
            s.parse::<i64>()
                .map(Value::Int)
                .map_err(|_| format!("json: 非法整数 {}", s))
        }
    }
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

fn escape(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// 紧凑、确定的 JSON：对象键按字典序排序。
pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => {
            let _ = write!(out, "{}", i);
        }
        Value::Float(f) => out.push_str(&fmt_f64(*f)),
        Value::Str(s) => escape(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(pairs) => {
            let sorted: BTreeMap<&str, &Value> =
                pairs.iter().map(|(k, v)| (k.as_str(), v)).collect();
            out.push('{');
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape(k, out);
                out.push(':');
                write_canonical(val, out);
            }
            out.push('}');
        }
    }
}

/// 人类可读的缩进 JSON，保持对象原有键顺序。
pub fn pretty(v: &Value) -> String {
    let mut out = String::new();
    write_pretty(v, &mut out, 0);
    out
}

fn write_pretty(v: &Value, out: &mut String, depth: usize) {
    let pad = "  ".repeat(depth);
    let pad1 = "  ".repeat(depth + 1);
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => {
            let _ = write!(out, "{}", i);
        }
        Value::Float(f) => out.push_str(&fmt_f64(*f)),
        Value::Str(s) => escape(s, out),
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Array(a) => {
            out.push_str("[\n");
            for (i, item) in a.iter().enumerate() {
                out.push_str(&pad1);
                write_pretty(item, out, depth + 1);
                if i + 1 < a.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push(']');
        }
        Value::Object(p) if p.is_empty() => out.push_str("{}"),
        Value::Object(pairs) => {
            out.push_str("{\n");
            for (i, (k, val)) in pairs.iter().enumerate() {
                out.push_str(&pad1);
                escape(k, out);
                out.push_str(": ");
                write_pretty(val, out, depth + 1);
                if i + 1 < pairs.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push('}');
        }
    }
}

fn fmt_f64(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e16 {
        format!("{:.1}", f)
    } else {
        format!("{}", f)
    }
}
