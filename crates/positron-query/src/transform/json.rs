use positron_domain::value::{CandidateAttributeValue, CandidateKeyValue};

use super::{
    MAX_TRANSFORM_DEPTH, MAX_TRANSFORM_ENTRIES, MAX_TRANSFORM_INPUT_BYTES, TransformObserver,
    unsupported,
};
use crate::{QueryFailure, QueryFailureCode};

struct JsonParser<'source, 'observer, O> {
    source: &'source str,
    offset: usize,
    observer: &'observer mut O,
}

pub(super) fn parse(
    source: &str,
    observer: &mut impl TransformObserver,
) -> Result<CandidateAttributeValue, QueryFailure> {
    JsonParser::new(source, observer)?.parse()
}

impl<'source, 'observer, O: TransformObserver> JsonParser<'source, 'observer, O> {
    fn new(source: &'source str, observer: &'observer mut O) -> Result<Self, QueryFailure> {
        if source.len() > MAX_TRANSFORM_INPUT_BYTES {
            return Err(unsupported());
        }
        Ok(Self {
            source,
            offset: 0,
            observer,
        })
    }

    fn parse(mut self) -> Result<CandidateAttributeValue, QueryFailure> {
        self.skip_whitespace()?;
        let value = self.value(0)?;
        self.skip_whitespace()?;
        if self.offset == self.source.len() {
            Ok(value)
        } else {
            Err(unsupported())
        }
    }

    fn value(&mut self, depth: u16) -> Result<CandidateAttributeValue, QueryFailure> {
        self.observer.step()?;
        if depth > MAX_TRANSFORM_DEPTH {
            return Err(unsupported());
        }
        match self.peek() {
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(CandidateAttributeValue::null())
            },
            Some(b't') => {
                self.literal(b"true")?;
                Ok(CandidateAttributeValue::boolean(true))
            },
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(CandidateAttributeValue::boolean(false))
            },
            Some(b'"') => Ok(CandidateAttributeValue::string(self.string()?)),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(byte) if byte == b'-' || byte.is_ascii_digit() => self.number(),
            Some(_) | None => Err(unsupported()),
        }
    }

    fn array(&mut self, depth: u16) -> Result<CandidateAttributeValue, QueryFailure> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        self.skip_whitespace()?;
        if self.take(b']')? {
            return Ok(CandidateAttributeValue::array(values));
        }
        loop {
            if values.len() >= MAX_TRANSFORM_ENTRIES {
                return Err(unsupported());
            }
            values
                .try_reserve(1)
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            values.push(self.value(depth.checked_add(1).ok_or_else(unsupported)?)?);
            self.skip_whitespace()?;
            if self.take(b']')? {
                return Ok(CandidateAttributeValue::array(values));
            }
            self.expect(b',')?;
            self.skip_whitespace()?;
        }
    }

    fn object(&mut self, depth: u16) -> Result<CandidateAttributeValue, QueryFailure> {
        self.expect(b'{')?;
        let mut values = Vec::new();
        self.skip_whitespace()?;
        if self.take(b'}')? {
            return Ok(CandidateAttributeValue::key_value_list(values));
        }
        loop {
            if values.len() >= MAX_TRANSFORM_ENTRIES {
                return Err(unsupported());
            }
            let key = self.string()?;
            self.skip_whitespace()?;
            self.expect(b':')?;
            self.skip_whitespace()?;
            let value = self.value(depth.checked_add(1).ok_or_else(unsupported)?)?;
            values
                .try_reserve(1)
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            values.push(CandidateKeyValue::new(key, value));
            self.skip_whitespace()?;
            if self.take(b'}')? {
                return Ok(CandidateAttributeValue::key_value_list(values));
            }
            self.expect(b',')?;
            self.skip_whitespace()?;
        }
    }

    fn number(&mut self) -> Result<CandidateAttributeValue, QueryFailure> {
        let start = self.offset;
        if self.take(b'-')? && self.peek().is_none_or(|byte| !byte.is_ascii_digit()) {
            return Err(unsupported());
        }
        if self.take(b'0')? {
            if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(unsupported());
            }
        } else {
            self.digits()?;
        }
        let floating = self.take(b'.')?;
        if floating {
            self.digits()?;
        }
        if self.take(b'e')? || self.take(b'E')? {
            let _ = self.take(b'+')? || self.take(b'-')?;
            self.digits()?;
        }
        let source = self
            .source
            .get(start..self.offset)
            .ok_or_else(unsupported)?;
        if floating || source.contains(['e', 'E']) {
            let value = source.parse::<f64>().map_err(|_| unsupported())?;
            if !value.is_finite() {
                return Err(unsupported());
            }
            Ok(CandidateAttributeValue::floating_point_bits(
                value.to_bits(),
            ))
        } else {
            match source.parse::<i64>() {
                Ok(value) => Ok(CandidateAttributeValue::signed_integer(value)),
                Err(_) => {
                    let value = source.parse::<f64>().map_err(|_| unsupported())?;
                    if !value.is_finite() {
                        return Err(unsupported());
                    }
                    Ok(CandidateAttributeValue::floating_point_bits(
                        value.to_bits(),
                    ))
                },
            }
        }
    }

    fn string(&mut self) -> Result<String, QueryFailure> {
        self.expect(b'"')?;
        let mut value = String::new();
        value
            .try_reserve(
                self.source
                    .len()
                    .saturating_sub(self.offset)
                    .min(MAX_TRANSFORM_INPUT_BYTES),
            )
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        loop {
            self.observer.step()?;
            let byte = self.next()?.ok_or_else(unsupported)?;
            match byte {
                b'"' => return Ok(value),
                b'\\' => match self.next()?.ok_or_else(unsupported)? {
                    b'"' => value.push('"'),
                    b'\\' => value.push('\\'),
                    b'/' => value.push('/'),
                    b'b' => value.push('\u{0008}'),
                    b'f' => value.push('\u{000c}'),
                    b'n' => value.push('\n'),
                    b'r' => value.push('\r'),
                    b't' => value.push('\t'),
                    b'u' => self.unicode_escape(&mut value)?,
                    _ => return Err(unsupported()),
                },
                byte if byte.is_ascii() && byte < 0x20 => return Err(unsupported()),
                _byte => {
                    let start = self.offset.checked_sub(1).ok_or_else(unsupported)?;
                    let character = self.source.get(start..).ok_or_else(unsupported)?;
                    let character = character.chars().next().ok_or_else(unsupported)?;
                    let end = start
                        .checked_add(character.len_utf8())
                        .ok_or_else(unsupported)?;
                    if end > self.source.len() {
                        return Err(unsupported());
                    }
                    self.offset = end;
                    value.push(character);
                },
            }
        }
    }

    fn unicode_escape(&mut self, value: &mut String) -> Result<(), QueryFailure> {
        let first = self.hex_quad()?;
        if (0xD800..=0xDBFF).contains(&first) {
            if self.next()? != Some(b'\\') || self.next()? != Some(b'u') {
                return Err(unsupported());
            }
            let second = self.hex_quad()?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(unsupported());
            }
            let codepoint =
                0x1_0000 + (u32::from(first) - 0xD800) * 0x400 + (u32::from(second) - 0xDC00);
            let character = char::from_u32(codepoint).ok_or_else(unsupported)?;
            value.push(character);
        } else {
            if (0xDC00..=0xDFFF).contains(&first) {
                return Err(unsupported());
            }
            let character = char::from_u32(u32::from(first)).ok_or_else(unsupported)?;
            value.push(character);
        }
        Ok(())
    }

    fn hex_quad(&mut self) -> Result<u16, QueryFailure> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let byte = self.next()?.ok_or_else(unsupported)?;
            let digit = (byte as char).to_digit(16).ok_or_else(unsupported)?;
            value = value
                .checked_mul(16)
                .and_then(|value| value.checked_add(u16::try_from(digit).ok()?))
                .ok_or_else(unsupported)?;
        }
        Ok(value)
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), QueryFailure> {
        for byte in expected {
            if self.next()? != Some(*byte) {
                return Err(unsupported());
            }
        }
        Ok(())
    }

    fn digits(&mut self) -> Result<(), QueryFailure> {
        let start = self.offset;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.observer.step()?;
            self.offset = self.offset.checked_add(1).ok_or_else(unsupported)?;
        }
        (self.offset > start).then_some(()).ok_or_else(unsupported)
    }

    fn skip_whitespace(&mut self) -> Result<(), QueryFailure> {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.observer.step()?;
            self.offset = self.offset.checked_add(1).ok_or_else(unsupported)?;
        }
        Ok(())
    }

    fn expect(&mut self, expected: u8) -> Result<(), QueryFailure> {
        (self.next()? == Some(expected))
            .then_some(())
            .ok_or_else(unsupported)
    }

    fn take(&mut self, expected: u8) -> Result<bool, QueryFailure> {
        if self.peek() == Some(expected) {
            self.observer.step()?;
            self.offset = self.offset.checked_add(1).ok_or_else(unsupported)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn next(&mut self) -> Result<Option<u8>, QueryFailure> {
        self.observer.step()?;
        let Some(value) = self.source.as_bytes().get(self.offset).copied() else {
            return Ok(None);
        };
        self.offset = self.offset.checked_add(1).ok_or_else(unsupported)?;
        Ok(Some(value))
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }
}
