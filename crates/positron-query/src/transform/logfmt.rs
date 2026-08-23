use positron_domain::value::{CandidateAttributeValue, CandidateKeyValue};

use super::{
    MAX_TRANSFORM_ENTRIES, MAX_TRANSFORM_INPUT_BYTES, PARSER_ENTRY_BYTES, TransformObserver,
    copy_text, reserve_string_capacity, reserve_vec_capacity, unsupported,
};
use crate::QueryFailure;

struct LogfmtParser<'source, 'observer, O> {
    source: &'source str,
    offset: usize,
    observer: &'observer mut O,
}

pub(super) fn parse(
    source: &str,
    observer: &mut impl TransformObserver,
) -> Result<CandidateAttributeValue, QueryFailure> {
    LogfmtParser::new(source, observer)?.parse()
}

impl<'source, 'observer, O: TransformObserver> LogfmtParser<'source, 'observer, O> {
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
        let mut values = Vec::new();
        while self.skip_whitespace()? {
            if values.len() >= MAX_TRANSFORM_ENTRIES {
                return Err(unsupported());
            }
            let key_start = self.offset;
            while self
                .peek()
                .is_some_and(|byte| !byte.is_ascii_whitespace() && byte != b'=')
            {
                self.step()?;
                self.offset = self.offset.checked_add(1).ok_or_else(unsupported)?;
            }
            if self.offset == key_start {
                return Err(unsupported());
            }
            let key = copy_text(
                self.source
                    .get(key_start..self.offset)
                    .ok_or_else(unsupported)?,
                self.observer,
            )?;
            self.expect(b'=')?;
            let quoted = self.peek() == Some(b'"');
            let value = if quoted {
                CandidateAttributeValue::string(self.quoted()?)
            } else {
                let value_start = self.offset;
                while self.peek().is_some_and(|byte| !byte.is_ascii_whitespace()) {
                    self.step()?;
                    self.offset = self.offset.checked_add(1).ok_or_else(unsupported)?;
                }
                let source = self
                    .source
                    .get(value_start..self.offset)
                    .ok_or_else(unsupported)?;
                if source.contains('=') {
                    return Err(unsupported());
                }
                parse_bare(source, self.observer)?
            };
            if quoted && self.peek().is_some_and(|byte| !byte.is_ascii_whitespace()) {
                return Err(unsupported());
            }
            self.observer.step()?;
            reserve_vec_capacity(&mut values, 1, PARSER_ENTRY_BYTES, self.observer)?;
            values.push(CandidateKeyValue::new(key, value));
        }
        Ok(CandidateAttributeValue::key_value_list(values))
    }

    fn quoted(&mut self) -> Result<String, QueryFailure> {
        self.expect(b'"')?;
        let mut value = String::new();
        loop {
            let byte = self.next()?.ok_or_else(unsupported)?;
            match byte {
                b'"' => return Ok(value),
                b'\\' => match self.next()?.ok_or_else(unsupported)? {
                    b'"' => self.push_character(&mut value, '"')?,
                    b'\\' => self.push_character(&mut value, '\\')?,
                    b'n' => self.push_character(&mut value, '\n')?,
                    b'r' => self.push_character(&mut value, '\r')?,
                    b't' => self.push_character(&mut value, '\t')?,
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
                    self.push_character(&mut value, character)?;
                },
            }
        }
    }

    fn push_character(&mut self, value: &mut String, character: char) -> Result<(), QueryFailure> {
        reserve_string_capacity(value, character.len_utf8(), self.observer)?;
        value.push(character);
        Ok(())
    }

    fn skip_whitespace(&mut self) -> Result<bool, QueryFailure> {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.step()?;
            self.offset = self.offset.checked_add(1).ok_or_else(unsupported)?;
        }
        Ok(self.peek().is_some())
    }

    fn expect(&mut self, expected: u8) -> Result<(), QueryFailure> {
        if self.next()? == Some(expected) {
            Ok(())
        } else {
            Err(unsupported())
        }
    }

    fn next(&mut self) -> Result<Option<u8>, QueryFailure> {
        self.step()?;
        let Some(value) = self.source.as_bytes().get(self.offset).copied() else {
            return Ok(None);
        };
        self.offset = self.offset.checked_add(1).ok_or_else(unsupported)?;
        Ok(Some(value))
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }

    fn step(&mut self) -> Result<(), QueryFailure> {
        self.observer.step()
    }
}

fn parse_bare(
    source: &str,
    observer: &mut impl TransformObserver,
) -> Result<CandidateAttributeValue, QueryFailure> {
    match source {
        "null" => Ok(CandidateAttributeValue::null()),
        "true" => Ok(CandidateAttributeValue::boolean(true)),
        "false" => Ok(CandidateAttributeValue::boolean(false)),
        _ => {
            if let Ok(value) = source.parse::<i64>() {
                return Ok(CandidateAttributeValue::signed_integer(value));
            }
            if let Ok(value) = source.parse::<f64>()
                && value.is_finite()
            {
                return Ok(CandidateAttributeValue::floating_point_bits(
                    value.to_bits(),
                ));
            }
            if source.is_empty() {
                Ok(CandidateAttributeValue::string(String::new()))
            } else {
                Ok(CandidateAttributeValue::string(copy_text(
                    source, observer,
                )?))
            }
        },
    }
}
