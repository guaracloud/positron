use crate::planning_memory::{PlanningMemory, PlanningReservation};
use crate::{QueryFailure, QueryFailureCode};

pub(crate) fn parse_after_open<'source>(
    source: &'source str,
    memory: &PlanningMemory,
) -> Result<(String, &'source str, PlanningReservation), QueryFailure> {
    let mut decoded_bytes = 0_usize;
    let mut end = None;
    let mut escaped = false;
    for (index, character) in source.char_indices() {
        if escaped {
            if !matches!(character, '"' | '\\' | '|') {
                return Err(unsupported());
            }
            decoded_bytes = decoded_bytes
                .checked_add(character.len_utf8())
                .ok_or_else(unsupported)?;
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            end = Some(index);
            break;
        } else {
            decoded_bytes = decoded_bytes
                .checked_add(character.len_utf8())
                .ok_or_else(unsupported)?;
        }
    }
    let end = end.ok_or_else(unsupported)?;
    let remaining = source.get(end + 1..).ok_or_else(unsupported)?;
    let mut value = String::new();
    let decoded_capacity = decoded_bytes;
    let decoded_bytes = u64::try_from(decoded_capacity)
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    let mut reservation = memory.reserve(decoded_bytes)?;
    value
        .try_reserve_exact(decoded_capacity)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let capacity = u64::try_from(value.capacity())
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    reservation.reconcile(capacity)?;

    let mut escaped = false;
    for character in source[..end].chars() {
        if escaped {
            value.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            value.push(character);
        }
    }
    Ok((value, remaining, reservation))
}

const fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_scanner_rejects_unknown_escape_and_keeps_decoded_capacity() {
        let memory = PlanningMemory::new(64);
        assert!(parse_after_open(r#"bad\q" tail"#, &memory).is_err());
        let (value, remaining, reservation) =
            parse_after_open(r#"a\"b" tail"#, &memory).expect("quoted value");
        assert_eq!(value, "a\"b");
        assert_eq!(remaining, " tail");
        assert_eq!(reservation.bytes(), value.capacity() as u64);
    }
}
