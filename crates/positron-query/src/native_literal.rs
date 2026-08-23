use positron_domain::value::{CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile};

use crate::{QueryFailure, QueryFailureCode};

const HEX_PREFIX: &str = "0x";

pub(crate) fn parse_body(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<positron_domain::value::ValidatedAttributeValue, QueryFailure> {
    let (candidate, reservation) = if source.starts_with('"') {
        let (value, reservation) = Cursor::new(source, memory)?.parse_legacy_string()?;
        (CandidateAttributeValue::string(value), reservation)
    } else {
        Cursor::new(source, memory)?.parse_complete()?
    };
    validate_body(candidate, reservation, memory)
}

#[cfg(test)]
pub(crate) fn parse_attribute(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<positron_domain::value::ValidatedAttributeValue, QueryFailure> {
    let (value, reservation, retained) = parse_attribute_with_reservation(source, memory)?;
    memory.retain_reservation(reservation, retained)?;
    Ok(value)
}

pub(crate) fn parse_attribute_with_reservation(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<
    (
        positron_domain::value::ValidatedAttributeValue,
        crate::planning_memory::PlanningReservation,
        u64,
    ),
    QueryFailure,
> {
    let (candidate, reservation) = Cursor::new(source, memory)?.parse_complete()?;
    let mut observer = crate::planning_observer::PlanningValueObserver::new(reservation);
    let transfer = candidate
        .validate_attribute_observed_with_facts(
            ValueLimitProfile::release_1_system_maximum(),
            &mut observer,
        )
        .map_err(map_observed_failure)?;
    let retained = u64::try_from(transfer.retained_heap_bytes())
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    Ok((transfer.into_value(), observer.into_reservation(), retained))
}

pub(crate) fn parse_search_string(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<positron_domain::value::ValidatedAttributeValue, QueryFailure> {
    let (value, reservation) = Cursor::new(source, memory)?.parse_legacy_string()?;
    validate_body(CandidateAttributeValue::string(value), reservation, memory)
}

fn validate_body(
    candidate: CandidateAttributeValue,
    reservation: crate::planning_memory::PlanningReservation,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<positron_domain::value::ValidatedAttributeValue, QueryFailure> {
    let mut observer = crate::planning_observer::PlanningValueObserver::new(reservation);
    let transfer = candidate
        .validate_log_body_observed_with_facts(
            ValueLimitProfile::release_1_system_maximum(),
            &mut observer,
        )
        .map_err(map_observed_failure)?;
    let retained = u64::try_from(transfer.retained_heap_bytes())
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    memory.retain_reservation(observer.into_reservation(), retained)?;
    Ok(transfer.into_value())
}

struct Cursor<'source> {
    remaining: &'source str,
    maximum_depth: u16,
    memory: crate::planning_memory::PlanningMemory,
    reservation: crate::planning_memory::PlanningReservation,
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
            reservation: memory.reserve(0)?,
        })
    }

    fn parse_complete(
        mut self,
    ) -> Result<
        (
            CandidateAttributeValue,
            crate::planning_memory::PlanningReservation,
        ),
        QueryFailure,
    > {
        let value = self.parse_value(0)?;
        if self.remaining.is_empty() {
            Ok((value, self.reservation))
        } else {
            Err(unsupported())
        }
    }

    fn parse_legacy_string(
        mut self,
    ) -> Result<(String, crate::planning_memory::PlanningReservation), QueryFailure> {
        let value = self.parse_quoted()?;
        if self.remaining.is_empty() {
            Ok((value, self.reservation))
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
            let (value, reservation) = parse_bytes(source, &self.memory)?;
            self.reservation.merge(reservation)?;
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
            let (values, reservation) = values.into_vec_with_reservation();
            self.reservation.merge(reservation)?;
            return Ok(values);
        }
        loop {
            values.push(self.parse_value(depth)?)?;
            if self.take_prefix(")") {
                let (values, reservation) = values.into_vec_with_reservation();
                self.reservation.merge(reservation)?;
                return Ok(values);
            }
            self.expect(',')?;
        }
    }

    fn parse_key_values(&mut self, depth: u16) -> Result<Vec<CandidateKeyValue>, QueryFailure> {
        let mut values = crate::planning_memory::PlanningVec::with_capacity(&self.memory, 0)?;
        if self.take_prefix(")") {
            let (values, reservation) = values.into_vec_with_reservation();
            self.reservation.merge(reservation)?;
            return Ok(values);
        }
        loop {
            let key = self.parse_quoted()?;
            self.expect('=')?;
            let value = self.parse_value(depth)?;
            values.push(CandidateKeyValue::new(key, value))?;
            if self.take_prefix(")") {
                let (values, reservation) = values.into_vec_with_reservation();
                self.reservation.merge(reservation)?;
                return Ok(values);
            }
            self.expect(',')?;
        }
    }

    fn parse_quoted(&mut self) -> Result<String, QueryFailure> {
        self.expect('"')?;
        let (value, remaining, reservation) =
            crate::quoted::parse_after_open(self.remaining, &self.memory)?;
        self.remaining = remaining;
        self.reservation.merge(reservation)?;
        Ok(value)
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
) -> Result<(Vec<u8>, crate::planning_memory::PlanningReservation), QueryFailure> {
    let hex = source.strip_prefix(HEX_PREFIX).ok_or_else(unsupported)?;
    if hex.len() % 2 != 0
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(unsupported());
    }
    let mut bytes = Vec::new();
    let decoded_bytes =
        u64::try_from(hex.len() / 2).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    let mut reservation = memory.reserve(decoded_bytes)?;
    bytes
        .try_reserve_exact(hex.len() / 2)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let capacity = u64::try_from(bytes.capacity())
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    reservation.reconcile(capacity)?;
    let mut digits = hex.chars();
    while let Some(high) = digits.next() {
        let low = digits.next().ok_or_else(unsupported)?;
        let high = high.to_digit(16).ok_or_else(unsupported)?;
        let low = low.to_digit(16).ok_or_else(unsupported)?;
        bytes.push(u8::try_from((high << 4) | low).map_err(|_| unsupported())?);
    }
    Ok((bytes, reservation))
}

fn map_domain_failure(failure: positron_domain::outcome::DomainFailure) -> QueryFailure {
    if failure.code() == positron_domain::outcome::DomainFailureCode::AllocationUnavailable {
        QueryFailure::new(QueryFailureCode::ResourceExhausted)
    } else {
        unsupported()
    }
}

fn map_observed_failure(
    failure: positron_domain::value::ObservedValueFailure<QueryFailure>,
) -> QueryFailure {
    match failure {
        positron_domain::value::ObservedValueFailure::Domain(failure) => {
            map_domain_failure(failure)
        },
        positron_domain::value::ObservedValueFailure::Observer(failure) => failure,
    }
}

const fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_literals_transfer_their_actual_vector_capacity() {
        let memory = crate::planning_memory::PlanningMemory::new(64);
        let (bytes, reservation) = parse_bytes("0x00ff", &memory).expect("bytes");
        assert_eq!(bytes, [0, 255]);
        assert_eq!(reservation.bytes(), bytes.capacity() as u64);
    }

    #[test]
    fn attribute_validation_maps_collection_capacity_refusal() {
        let source = format!("array({})", ["null"; 1_025].join(","));
        let memory = crate::planning_memory::PlanningMemory::new(u64::MAX);
        let failure = parse_attribute(&source, &memory).expect_err("entry bound");
        assert_eq!(failure.code(), QueryFailureCode::UnsupportedQuery);
    }
}
