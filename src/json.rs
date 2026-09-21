use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    UInteger(u64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn object() -> Self {
        Value::Object(BTreeMap::new())
    }

    pub fn from_string(value: impl Into<String>) -> Self {
        Value::String(value.into())
    }

    pub fn from_usize(value: usize) -> Self {
        Value::UInteger(value as u64)
    }

    pub fn from_u64(value: u64) -> Self {
        Value::UInteger(value)
    }

    pub fn from_i64(value: i64) -> Self {
        Value::Integer(value)
    }

    pub fn put(&mut self, key: impl Into<String>, value: Value) {
        if let Value::Object(map) = self {
            map.insert(key.into(), value);
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        if let Value::Object(map) = self {
            map.get(key)
        } else {
            None
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        if let Value::String(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        if let Value::Array(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        if let Value::Object(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(value) => Some(*value),
            Value::UInteger(value) if *value <= i64::MAX as u64 => Some(*value as i64),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::UInteger(value) => Some(*value),
            Value::Integer(value) if *value >= 0 => Some(*value as u64),
            _ => None,
        }
    }

    pub fn canonical(&self) -> String {
        let mut out = String::new();
        write_value(&mut out, self);
        out
    }
}

pub fn array() -> Value {
    Value::Array(Vec::new())
}

pub fn push(array: &mut Value, value: Value) {
    if let Value::Array(items) = array {
        items.push(value);
    }
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Integer(value) => {
            let _ = write!(out, "{value}");
        }
        Value::UInteger(value) => {
            let _ = write!(out, "{value}");
        }
        Value::String(value) => write_string(out, value),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, item);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn parse(input: &str) -> Result<Value, String> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        index: 0,
    };
    parser.skip_whitespace();
    let value = parser.read_value()?;
    parser.skip_whitespace();
    if parser.index != parser.bytes.len() {
        return Err(parser.error("trailing JSON content"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Parser<'a> {
    fn read_value(&mut self) -> Result<Value, String> {
        self.skip_whitespace();
        if self.index >= self.bytes.len() {
            return Err(self.error("expected JSON value"));
        }
        match self.bytes[self.index] {
            b'{' => self.read_object(),
            b'[' => self.read_array(),
            b'"' => self.read_string().map(Value::String),
            b't' | b'f' => self.read_bool(),
            b'n' => self.read_null(),
            b'-' | b'0'..=b'9' => self.read_number(),
            _ => Err(self.error("unexpected JSON token")),
        }
    }

    fn read_object(&mut self) -> Result<Value, String> {
        self.index += 1;
        let mut map = BTreeMap::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.index += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_whitespace();
            let key = self.read_string()?;
            self.skip_whitespace();
            if self.next() != Some(b':') {
                return Err(self.error("expected ':' after object key"));
            }
            let value = self.read_value()?;
            map.insert(key, value);
            self.skip_whitespace();
            match self.next() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err(self.error("expected ',' or '}' in object")),
            }
        }
        Ok(Value::Object(map))
    }

    fn read_array(&mut self) -> Result<Value, String> {
        self.index += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.index += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.read_value()?);
            self.skip_whitespace();
            match self.next() {
                Some(b',') => continue,
                Some(b']') => break,
                _ => return Err(self.error("expected ',' or ']' in array")),
            }
        }
        Ok(Value::Array(items))
    }

    fn read_string(&mut self) -> Result<String, String> {
        if self.next() != Some(b'"') {
            return Err(self.error("expected string"));
        }
        let mut out = String::new();
        loop {
            match self.next() {
                None => return Err(self.error("unterminated string")),
                Some(b'"') => break,
                Some(b'\\') => match self.next() {
                    Some(b'"') => out.push('"'),
                    Some(b'\\') => out.push('\\'),
                    Some(b'/') => out.push('/'),
                    Some(b'b') => out.push('\u{08}'),
                    Some(b'f') => out.push('\u{0c}'),
                    Some(b'n') => out.push('\n'),
                    Some(b'r') => out.push('\r'),
                    Some(b't') => out.push('\t'),
                    Some(b'u') => {
                        let code = self.read_unicode_escape()?;
                        if (0xd800..=0xdbff).contains(&code) {
                            if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                                return Err(self.error("expected low surrogate"));
                            }
                            let low = self.read_unicode_escape()?;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return Err(self.error("invalid low surrogate"));
                            }
                            let value =
+                                0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                            if let Some(character) = char::from_u32(value) {
                                out.push(character);
                            }
                        } else if let Some(character) = char::from_u32(code) {
                            out.push(character);
                        } else {
                            return Err(self.error("invalid unicode escape"));
                        }
                    }
                    _ => return Err(self.error("invalid string escape")),
                },
                Some(byte) => {
                    if byte < 0x80 {
                        out.push(byte as char);
                    } else {
                        let start = self.index - 1;
                        let width = if byte >= 0xf0 {
                            4
                        } else if byte >= 0xe0 {
                            3
                        } else {
                            2
                        };
                        if self.bytes.len() < start + width {
                            return Err(self.error("invalid UTF-8 in string"));
                        }
                        let text = std::str::from_utf8(&self.bytes[start..start + width])
                            .map_err(|_| self.error("invalid UTF-8 in string"))?;
                        out.push_str(text);
                        self.index = start + width;
                    }
                }
            }
        }
        Ok(out)
    }

    fn read_unicode_escape(&mut self) -> Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..4 {
            let byte = self
                .next()
                .ok_or_else(|| self.error("short unicode escape"))?;
            let digit = match byte {
                b'0'..=b'9' => (byte - b'0') as u32,
                b'a'..=b'f' => (byte - b'a' + 10) as u32,
                b'A'..=b'F' => (byte - b'A' + 10) as u32,
                _ => return Err(self.error("invalid unicode hexadecimal digit")),
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn read_bool(&mut self) -> Result<Value, String> {
        if self.take_literal("true") {
            Ok(Value::Bool(true))
        } else if self.take_literal("false") {
            Ok(Value::Bool(false))
        } else {
            Err(self.error("invalid boolean"))
        }
    }

    fn read_null(&mut self) -> Result<Value, String> {
        if self.take_literal("null") {
            Ok(Value::Null)
        } else {
            Err(self.error("invalid null"))
        }
    }

    fn read_number(&mut self) -> Result<Value, String> {
        let start = self.index;
        let mut dot = false;
        let mut exponent = false;
        if self.peek() == Some(b'-') {
            self.index += 1;
        }
        while let Some(byte) = self.peek() {
            match byte {
                b'0'..=b'9' => self.index += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    if byte == b'.' {
                        dot = true;
                    }
                    if byte == b'e' || byte == b'E' {
                        exponent = true;
                    }
                    self.index += 1;
                }
                _ => break,
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.index])
            .map_err(|_| self.error("invalid number"))?;
        if dot || exponent {
            return Err(self.error("floating point numbers are not supported"));
        }
        if text.starts_with('-') {
            text.parse::<i64>()
                .map(Value::Integer)
                .map_err(|_| self.error("integer is out of range"))
        } else {
            text.parse::<u64>()
                .map(Value::UInteger)
                .map_err(|_| self.error("integer is out of range"))
        }
    }

    fn take_literal(&mut self, literal: &str) -> bool {
        if self.bytes[self.index..].starts_with(literal.as_bytes()) {
            self.index += literal.len();
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.peek(),
            Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
        ) {
            self.index += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek();
        if value.is_some() {
            self.index += 1;
        }
        value
    }

    fn error(&self, message: &str) -> String {
        format!("{message} at byte {}", self.index)
    }
}
