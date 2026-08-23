use positron_domain::value::{CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile};

use crate::{QueryFailure, QueryFailureCode};

const HEX_PREFIX: &str = "0x";

pub(crate) fn parse_body(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<positron_domain::value::ValidatedAttributeValue, QueryFailure> {
    let scratch = value_scratch_reservation(memory, source)?;
    let candidate = if source.starts_with('"') {
        CandidateAttributeValue::string(Cursor::new(source, memory)?.parse_legacy_string()?)
    } else {
        Cursor::new(source, memory)?.parse_complete()?
    };
    let value = candidate
        .validate_log_body(ValueLimitProfile::release_1_system_maximum())
        .map_err(map_domain_failure)?;
    drop(scratch);
    Ok(value)
}

pub(crate) fn parse_attribute(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<positron_domain::value::ValidatedAttributeValue, QueryFailure> {
    let scratch = value_scratch_reservation(memory, source)?;
    let value = Cursor::new(source, memory)?
        .parse_complete()?
        .validate_attribute(ValueLimitProfile::release_1_system_maximum())
        .map_err(map_domain_failure)?;
    drop(scratch);
    Ok(value)
}

pub(crate) fn parse_search_string(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<positron_domain::value::ValidatedAttributeValue, QueryFailure> {
    let scratch = value_scratch_reservation(memory, source)?;
    let value =
        CandidateAttributeValue::string(Cursor::new(source, memory)?.parse_legacy_string()?)
            .validate_log_body(ValueLimitProfile::release_1_system_maximum())
            .map_err(map_domain_failure)?;
    drop(scratch);
    Ok(value)
}

struct Cursor<'source> {
    remaining: &'source str,
    maximum_depth: u16,
    memory: crate::planning_memory::PlanningMemory,
}

impl<'source> Cursor<'source> {
    fn new(
        source: &'source str,
        memory: &crate::planning_memory::PlanningMemory,
    ) -> Result<Self, QueryFailure> {
        let limits = ValueLimitProfile::release_1_system_maximum().system_limits();
        Ok(Self {
            remaining: source,
            maximum_depth: limits.dynamic_value().nesting_depth().value(),
            memory: memory.clone(),
        })
    }

    fn parse_complete(mut self) -> Result<CandidateAttributeValue, QueryFailure> {
        let value = self.parse_value(0)?;
        if self.remaining.is_empty() {
            Ok(value)
        } else {
            Err(unsupported())
        }
    }

    fn parse_legacy_string(mut self) -> Result<String, QueryFailure> {
        let value = self.parse_quoted()?;
        if self.remaining.is_empty() {
            Ok(value)
        } else {
            Err(unsupported())
        }
    }

    fn parse_value(&mut self, depth: u16) -> Result<CandidateAttributeValue, QueryFailure> {
        if depth > self.maximum_depth {
            return Err(unsupported());
        }
        if self.take_prefix("null") {
            return Ok(CandidateAttributeValue::null());
        }
        if self.take_prefix("bool(") {
            let value = if self.take_prefix("true") {
                true
            } else if self.take_prefix("false") {
                false
            } else {
                return Err(unsupported());
            };
            self.expect(')')?;
            return Ok(CandidateAttributeValue::boolean(value));
        }
        if self.take_prefix("int(") {
            let source = self.take_until(')')?;
            if !canonical_integer(source) {
                return Err(unsupported());
            }
            let value = source.parse().map_err(|_| unsupported())?;
            self.expect(')')?;
            return Ok(CandidateAttributeValue::signed_integer(value));
        }
        if self.take_prefix("float_bits(") {
            let source = self.take_until(')')?;
            let bits = parse_fixed_hex(source, 16)?;
            self.expect(')')?;
            return Ok(CandidateAttributeValue::floating_point_bits(bits));
        }
        if self.take_prefix("string(") {
            let value = self.parse_quoted()?;
            self.expect(')')?;
            return Ok(CandidateAttributeValue::string(value));
        }
        if self.take_prefix("bytes(") {
            let source = self.take_until(')')?;
            let value = parse_bytes(source, &self.memory)?;
            self.expect(')')?;
            return Ok(CandidateAttributeValue::bytes(value));
        }
        if self.take_prefix("array(") {
            let next_depth = depth.checked_add(1).ok_or_else(unsupported)?;
            let values = self.parse_array(next_depth)?;
            return Ok(CandidateAttributeValue::array(values));
        }
        if self.take_prefix("kv(") {
            let next_depth = depth.checked_add(1).ok_or_else(unsupported)?;
            let values = self.parse_key_values(next_depth)?;
            return Ok(CandidateAttributeValue::key_value_list(values));
        }
        Err(unsupported())
    }

    fn parse_array(&mut self, depth: u16) -> Result<Vec<CandidateAttributeValue>, QueryFailure> {
        let mut values = crate::planning_memory::PlanningVec::with_capacity(&self.memory, 0)?;
        if self.take_prefix(")") {
            return Ok(values.into_vec());
        }
        loop {
            values.push(self.parse_value(depth)?)?;
            if self.take_prefix(")") {
                return Ok(values.into_vec());
            }
            self.expect(',')?;
        }
    }

    fn parse_key_values(&mut self, depth: u16) -> Result<Vec<CandidateKeyValue>, QueryFailure> {
        let mut values = crate::planning_memory::PlanningVec::with_capacity(&self.memory, 0)?;
        if self.take_prefix(")") {
            return Ok(values.into_vec());
        }
        loop {
            let key = self.parse_quoted()?;
            self.expect('=')?;
            let value = self.parse_value(depth)?;
            values.push(CandidateKeyValue::new(key, value))?;
            if self.take_prefix(")") {
                return Ok(values.into_vec());
            }
            self.expect(',')?;
        }
    }

    fn parse_quoted(&mut self) -> Result<String, QueryFailure> {
        self.expect('"')?;
        let mut decoded = String::new();
        let reservation = self.memory.reserve(
            u64::try_from(self.remaining.len().min(4_096))
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
        )?;
        if decoded
            .try_reserve_exact(self.remaining.len().min(4_096))
            .is_err()
        {
            return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
        }
        loop {
            let character = self.next_character().ok_or_else(unsupported)?;
            match character {
                '"' => {
                    drop(reservation);
                    return Ok(decoded);
                },
                '\\' => {
                    let escaped = self.next_character().ok_or_else(unsupported)?;
                    if !matches!(escaped, '"' | '\\' | '|') {
                        return Err(unsupported());
                    }
                    decoded.push(escaped);
                },
                _ => decoded.push(character),
            }
        }
    }

    fn take_until(&mut self, delimiter: char) -> Result<&'source str, QueryFailure> {
        let index = self.remaining.find(delimiter).ok_or_else(unsupported)?;
        let taken = self.remaining.get(..index).ok_or_else(unsupported)?;
        self.remaining = self.remaining.get(index..).ok_or_else(unsupported)?;
        Ok(taken)
    }

    fn expect(&mut self, expected: char) -> Result<(), QueryFailure> {
        if self.next_character() == Some(expected) {
            Ok(())
        } else {
            Err(unsupported())
        }
    }

    fn take_prefix(&mut self, prefix: &str) -> bool {
        let Some(remaining) = self.remaining.strip_prefix(prefix) else {
            return false;
        };
        self.remaining = remaining;
        true
    }

    fn next_character(&mut self) -> Option<char> {
        let character = self.remaining.chars().next()?;
        self.remaining = self.remaining.get(character.len_utf8()..)?;
        Some(character)
    }
}

fn canonical_integer(source: &str) -> bool {
    !(source.is_empty()
        || source.starts_with('+')
        || source.starts_with('0') && source.len() > 1
        || source.starts_with("-0") && source.len() > 2)
}

fn parse_fixed_hex(source: &str, digits: usize) -> Result<u64, QueryFailure> {
    let hex = source.strip_prefix(HEX_PREFIX).ok_or_else(unsupported)?;
    if hex.len() != digits
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(unsupported());
    }
    u64::from_str_radix(hex, 16).map_err(|_| unsupported())
}

fn parse_bytes(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<Vec<u8>, QueryFailure> {
    let hex = source.strip_prefix(HEX_PREFIX).ok_or_else(unsupported)?;
    if hex.len() % 2 != 0
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(unsupported());
    }
    let mut bytes = Vec::new();
    let reservation = memory.reserve(
        u64::try_from(hex.len() / 2).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
    )?;
    bytes
        .try_reserve_exact(hex.len() / 2)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let mut digits = hex.chars();
    while let Some(high) = digits.next() {
        let low = digits.next().ok_or_else(unsupported)?;
        let high = high.to_digit(16).ok_or_else(unsupported)?;
        let low = low.to_digit(16).ok_or_else(unsupported)?;
        bytes.push(u8::try_from((high << 4) | low).map_err(|_| unsupported())?);
    }
    drop(reservation);
    Ok(bytes)
}

fn value_scratch_reservation(
    memory: &crate::planning_memory::PlanningMemory,
    source: &str,
) -> Result<crate::planning_memory::PlanningReservation, QueryFailure> {
    let bytes = u64::try_from(source.len())
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
        .checked_mul(64)
        .ok_or_else(|| QueryFailure::budget_exhausted(crate::QueryBudgetDimension::MemoryBytes))?;
    memory.reserve(bytes)
}

fn map_domain_failure(failure: positron_domain::outcome::DomainFailure) -> QueryFailure {
    if failure.code() == positron_domain::outcome::DomainFailureCode::AllocationUnavailable {
        QueryFailure::new(QueryFailureCode::ResourceExhausted)
    } else {
        unsupported()
    }
}

const fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}
