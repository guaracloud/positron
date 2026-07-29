use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

pub(crate) const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_DEPTH: usize = 32;
pub(crate) const MAX_COLLECTION_ITEMS: usize = 512;
pub(crate) const MAX_STRING_BYTES: usize = 128 * 1024;

pub(crate) type JsonObject = BTreeMap<String, JsonValue>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JsonValue {
    Null,
    Boolean(bool),
    Integer(u128),
    String(String),
    Array(Vec<JsonValue>),
    Object(JsonObject),
}

impl JsonValue {
    pub(crate) fn into_object(self, subject: &str) -> Result<JsonObject, JsonError> {
        match self {
            Self::Object(object) => Ok(object),
            _ => Err(JsonError::new(format!("{subject} must be a JSON object"))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JsonError {
    detail: String,
}

impl JsonError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl Error for JsonError {}

pub(crate) fn parse(input: &str) -> Result<JsonValue, JsonError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(JsonError::new(format!(
            "JSON input exceeds the {MAX_INPUT_BYTES}-byte limit"
        )));
    }

    let mut parser = Parser { input, position: 0 };
    parser.skip_whitespace()?;
    let value = parser.parse_value(0)?;
    parser.skip_whitespace()?;
    if parser.current().is_some() {
        return Err(parser.error("unexpected trailing content"));
    }

    Ok(value)
}

pub(crate) fn take_required(object: &mut JsonObject, field: &str) -> Result<JsonValue, JsonError> {
    object
        .remove(field)
        .ok_or_else(|| JsonError::new(format!("missing required field `{field}`")))
}

pub(crate) fn reject_unknown_fields(object: JsonObject, subject: &str) -> Result<(), JsonError> {
    match object.into_iter().next() {
        Some((field, _)) => Err(JsonError::new(format!(
            "{subject} contains unknown field `{field}`"
        ))),
        None => Ok(()),
    }
}

struct Parser<'input> {
    input: &'input str,
    position: usize,
}

impl Parser<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, JsonError> {
        match self.current() {
            Some('n') => {
                self.consume_literal("null")?;
                Ok(JsonValue::Null)
            },
            Some('t') => {
                self.consume_literal("true")?;
                Ok(JsonValue::Boolean(true))
            },
            Some('f') => {
                self.consume_literal("false")?;
                Ok(JsonValue::Boolean(false))
            },
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('[') => self.parse_array(depth),
            Some('{') => self.parse_object(depth),
            Some('0'..='9') => self.parse_integer().map(JsonValue::Integer),
            Some('-') => Err(self.error("only non-negative integer JSON numbers are supported")),
            Some(_) => Err(self.error("unexpected JSON token")),
            None => Err(self.error("expected a JSON value")),
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, JsonError> {
        self.ensure_container_depth(depth)?;
        self.consume_char('[')?;
        self.skip_whitespace()?;
        let mut values = Vec::with_capacity(MAX_COLLECTION_ITEMS);
        if self.consume_if(']')? {
            return Ok(JsonValue::Array(values));
        }

        loop {
            if values.len() >= MAX_COLLECTION_ITEMS {
                return Err(self.error(format!(
                    "JSON array exceeds the {MAX_COLLECTION_ITEMS}-item limit"
                )));
            }
            values.push(
                self.parse_value(
                    depth
                        .checked_add(1)
                        .ok_or_else(|| self.error("JSON nesting depth overflow"))?,
                )?,
            );
            self.skip_whitespace()?;
            if self.consume_if(']')? {
                return Ok(JsonValue::Array(values));
            }
            self.consume_char(',')?;
            self.skip_whitespace()?;
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, JsonError> {
        self.ensure_container_depth(depth)?;
        self.consume_char('{')?;
        self.skip_whitespace()?;
        let mut fields = BTreeMap::new();
        if self.consume_if('}')? {
            return Ok(JsonValue::Object(fields));
        }

        loop {
            if fields.len() >= MAX_COLLECTION_ITEMS {
                return Err(self.error(format!(
                    "JSON object exceeds the {MAX_COLLECTION_ITEMS}-item limit"
                )));
            }
            if self.current() != Some('"') {
                return Err(self.error("JSON object key must be a string"));
            }
            let key = self.parse_string()?;
            if fields.contains_key(&key) {
                return Err(self.error(format!("duplicate JSON object key `{key}`")));
            }
            self.skip_whitespace()?;
            self.consume_char(':')?;
            self.skip_whitespace()?;
            let value = self.parse_value(
                depth
                    .checked_add(1)
                    .ok_or_else(|| self.error("JSON nesting depth overflow"))?,
            )?;
            fields.insert(key, value);
            self.skip_whitespace()?;
            if self.consume_if('}')? {
                return Ok(JsonValue::Object(fields));
            }
            self.consume_char(',')?;
            self.skip_whitespace()?;
        }
    }

    fn parse_integer(&mut self) -> Result<u128, JsonError> {
        let mut value = 0_u128;
        match self.current() {
            Some('0') => {
                self.advance_char('0')?;
                if matches!(self.current(), Some('0'..='9')) {
                    return Err(self.error("JSON numbers cannot contain leading zeroes"));
                }
                return Ok(value);
            },
            Some('1'..='9') => {},
            Some(_) | None => return Err(self.error("expected a JSON integer")),
        }

        while let Some(digit @ '0'..='9') = self.current() {
            let Some(digit_value) = digit.to_digit(10) else {
                return Err(self.error("invalid JSON integer digit"));
            };
            let digit_value = u128::from(digit_value);
            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(digit_value))
                .ok_or_else(|| self.error("JSON integer exceeds u128"))?;
            self.advance_char(digit)?;
        }

        match self.current() {
            Some('.') | Some('e') | Some('E') => {
                Err(self.error("only integer JSON numbers are supported"))
            },
            Some(_) | None => Ok(value),
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.consume_char('"')?;
        let mut value = String::new();
        loop {
            let Some(character) = self.current() else {
                return Err(self.error("unterminated JSON string"));
            };
            match character {
                '"' => {
                    self.advance_char(character)?;
                    return Ok(value);
                },
                '\\' => {
                    self.advance_char(character)?;
                    let escaped = self.parse_escape()?;
                    self.append_string_character(&mut value, escaped)?;
                },
                '\u{0000}'..='\u{001F}' => {
                    return Err(self.error("JSON strings cannot contain control characters"));
                },
                _ => {
                    self.append_string_character(&mut value, character)?;
                    self.advance_char(character)?;
                },
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, JsonError> {
        let Some(escape) = self.current() else {
            return Err(self.error("unterminated JSON escape"));
        };
        match escape {
            '"' | '\\' | '/' => {
                self.advance_char(escape)?;
                Ok(escape)
            },
            'b' => {
                self.advance_char(escape)?;
                Ok('\u{0008}')
            },
            'f' => {
                self.advance_char(escape)?;
                Ok('\u{000C}')
            },
            'n' => {
                self.advance_char(escape)?;
                Ok('\n')
            },
            'r' => {
                self.advance_char(escape)?;
                Ok('\r')
            },
            't' => {
                self.advance_char(escape)?;
                Ok('\t')
            },
            'u' => {
                self.advance_char(escape)?;
                self.parse_unicode_escape()
            },
            _ => Err(self.error("invalid JSON escape")),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, JsonError> {
        let first = self.parse_hex_quad()?;
        if (0xD800..=0xDBFF).contains(&first) {
            self.consume_char('\\')?;
            self.consume_char('u')?;
            let second = self.parse_hex_quad()?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(self.error("high surrogate must be followed by a low surrogate"));
            }
            let code_point =
                0x1_0000 + (((u32::from(first) - 0xD800) << 10) | (u32::from(second) - 0xDC00));
            return char::from_u32(code_point)
                .ok_or_else(|| self.error("invalid JSON Unicode surrogate pair"));
        }
        if (0xDC00..=0xDFFF).contains(&first) {
            return Err(self.error("unexpected JSON low surrogate"));
        }

        char::from_u32(u32::from(first)).ok_or_else(|| self.error("invalid JSON Unicode escape"))
    }

    fn parse_hex_quad(&mut self) -> Result<u16, JsonError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let Some(character) = self.current() else {
                return Err(self.error("incomplete JSON Unicode escape"));
            };
            let Some(digit) = character.to_digit(16) else {
                return Err(self.error("invalid JSON Unicode escape"));
            };
            value = value
                .checked_mul(16)
                .and_then(|current| current.checked_add(digit as u16))
                .ok_or_else(|| self.error("JSON Unicode escape overflow"))?;
            self.advance_char(character)?;
        }
        Ok(value)
    }

    fn append_string_character(
        &self,
        value: &mut String,
        character: char,
    ) -> Result<(), JsonError> {
        let encoded_bytes = character.len_utf8();
        let next_length = value
            .len()
            .checked_add(encoded_bytes)
            .ok_or_else(|| self.error("JSON string length overflow"))?;
        if next_length > MAX_STRING_BYTES {
            return Err(self.error(format!(
                "JSON string exceeds the {MAX_STRING_BYTES}-byte limit"
            )));
        }
        value
            .try_reserve_exact(encoded_bytes)
            .map_err(|_| self.error("cannot reserve JSON string storage"))?;
        value.push(character);
        Ok(())
    }

    fn ensure_container_depth(&self, depth: usize) -> Result<(), JsonError> {
        if depth >= MAX_DEPTH {
            return Err(self.error(format!("JSON nesting exceeds the {MAX_DEPTH}-level limit")));
        }
        Ok(())
    }

    fn consume_literal(&mut self, literal: &str) -> Result<(), JsonError> {
        if self
            .remaining()
            .is_some_and(|remaining| remaining.starts_with(literal))
        {
            self.advance_bytes(literal.len())
        } else {
            Err(self.error(format!("expected JSON literal `{literal}`")))
        }
    }

    fn consume_if(&mut self, expected: char) -> Result<bool, JsonError> {
        if self.current() == Some(expected) {
            self.advance_char(expected)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn consume_char(&mut self, expected: char) -> Result<(), JsonError> {
        match self.current() {
            Some(actual) if actual == expected => self.advance_char(actual),
            _ => Err(self.error(format!("expected `{expected}`"))),
        }
    }

    fn skip_whitespace(&mut self) -> Result<(), JsonError> {
        while matches!(self.current(), Some(' ' | '\n' | '\r' | '\t')) {
            let Some(character) = self.current() else {
                return Ok(());
            };
            self.advance_char(character)?;
        }
        Ok(())
    }

    fn current(&self) -> Option<char> {
        self.remaining()?.chars().next()
    }

    fn remaining(&self) -> Option<&str> {
        self.input.get(self.position..)
    }

    fn advance_char(&mut self, character: char) -> Result<(), JsonError> {
        self.advance_bytes(character.len_utf8())
    }

    fn advance_bytes(&mut self, bytes: usize) -> Result<(), JsonError> {
        let position = self
            .position
            .checked_add(bytes)
            .ok_or_else(|| self.error("JSON offset overflow"))?;
        if self.input.get(position..).is_none() {
            return Err(self.error("unexpected end of JSON input"));
        }
        self.position = position;
        Ok(())
    }

    fn error(&self, detail: impl fmt::Display) -> JsonError {
        JsonError::new(format!(
            "JSON parse error at byte {}: {detail}",
            self.position
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        JsonError, JsonValue, MAX_COLLECTION_ITEMS, MAX_DEPTH, MAX_INPUT_BYTES, MAX_STRING_BYTES,
        parse, reject_unknown_fields, take_required,
    };

    #[test]
    fn parses_typed_json_and_supports_strict_object_fields() -> Result<(), JsonError> {
        let value = parse(r#"{"name":"positron","enabled":true,"count":42,"items":[null]}"#)?;
        let mut object = value.into_object("evidence")?;

        assert!(matches!(
            take_required(&mut object, "enabled")?,
            JsonValue::Boolean(true)
        ));
        assert!(matches!(
            take_required(&mut object, "count")?,
            JsonValue::Integer(42)
        ));
        assert!(
            matches!(take_required(&mut object, "items")?, JsonValue::Array(items) if items.len() == 1)
        );
        assert!(
            matches!(take_required(&mut object, "name")?, JsonValue::String(name) if name == "positron")
        );
        reject_unknown_fields(object, "evidence")
    }

    #[test]
    fn rejects_duplicate_object_keys() {
        assert!(parse(r#"{"gate":"first","gate":"second"}"#).is_err());
    }

    #[test]
    fn rejects_malformed_or_unsupported_json() {
        for input in [
            "",
            "[1,]",
            r#"{"field":}"#,
            r#""\uD800""#,
            "01",
            "-1",
            "1.0",
        ] {
            assert!(parse(input).is_err(), "input must be rejected: {input}");
        }
    }

    #[test]
    fn enforces_depth_and_collection_bounds() {
        let accepted_depth = format!("{}0{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(&accepted_depth).is_ok());

        let excessive_depth = format!(
            "{}0{}",
            "[".repeat(MAX_DEPTH + 1),
            "]".repeat(MAX_DEPTH + 1)
        );
        assert!(parse(&excessive_depth).is_err());

        let excessive_array = format!(
            "[{}]",
            std::iter::repeat_n("0", MAX_COLLECTION_ITEMS + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(parse(&excessive_array).is_err());
    }

    #[test]
    fn enforces_input_and_string_bounds() {
        let excessive_input = format!("\"{}\"", "a".repeat(MAX_INPUT_BYTES));
        assert!(parse(&excessive_input).is_err());

        let excessive_string = format!("\"{}\"", "a".repeat(MAX_STRING_BYTES + 1));
        assert!(parse(&excessive_string).is_err());
    }
}
