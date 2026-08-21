use positron_domain::value::{CandidateAttributeValue, CandidateKeyValue};

use super::super::{CodecLimits, Input, bounded_vec};
use crate::log_store::LogStoreFailure;

pub(in crate::log_store::codec) fn decode(
    input: &mut Input<'_>,
    depth: u8,
    value_bytes: usize,
    limits: CodecLimits,
    _version: u16,
) -> Result<CandidateAttributeValue, LogStoreFailure> {
    match decode_mode(input, depth, value_bytes, limits, DecodeMode::Build)? {
        DecodedValue::Built(value) => Ok(value),
        DecodedValue::Validated(_) => Err(LogStoreFailure::malformed_block()),
    }
}

pub(in crate::log_store::codec) fn validate(
    input: &mut Input<'_>,
    depth: u8,
    value_bytes: usize,
    limits: CodecLimits,
) -> Result<ValueSummary, LogStoreFailure> {
    match decode_mode(input, depth, value_bytes, limits, DecodeMode::ValidateOnly)? {
        DecodedValue::Built(_) => Err(LogStoreFailure::malformed_block()),
        DecodedValue::Validated(summary) => Ok(summary),
    }
}

#[derive(Clone, Copy)]
enum DecodeMode {
    Build,
    ValidateOnly,
}

enum DecodedValue {
    Built(CandidateAttributeValue),
    Validated(ValueSummary),
}

#[derive(Clone, Copy)]
pub(in crate::log_store::codec) struct ValueSummary {
    value_bytes: usize,
    decoded_bytes: usize,
}

impl ValueSummary {
    pub(in crate::log_store::codec) const fn decoded_bytes(self) -> usize {
        self.decoded_bytes
    }
}

fn decode_mode(
    input: &mut Input<'_>,
    depth: u8,
    value_bytes: usize,
    limits: CodecLimits,
    mode: DecodeMode,
) -> Result<DecodedValue, LogStoreFailure> {
    input.observe_component()?;
    let decoded = match input.u8()? {
        0 => scalar(mode_value(mode, CandidateAttributeValue::null()), 0),
        1 => {
            let value = match input.u8()? {
                0 => false,
                1 => true,
                _ => return Err(LogStoreFailure::malformed_block()),
            };
            scalar(mode_value(mode, CandidateAttributeValue::boolean(value)), 1)
        },
        2 => scalar(
            mode_value(mode, CandidateAttributeValue::signed_integer(input.i64()?)),
            8,
        ),
        3 => scalar(
            mode_value(
                mode,
                CandidateAttributeValue::floating_point_bits(input.u64()?),
            ),
            8,
        ),
        4 => sequence(input, value_bytes, mode, true)?,
        5 => sequence(input, value_bytes, mode, false)?,
        6 => decode_array(input, depth, value_bytes, limits, mode)?,
        7 => decode_key_value_list(input, depth, value_bytes, limits, mode)?,
        _ => return Err(LogStoreFailure::malformed_block()),
    };
    if let DecodedValue::Validated(summary) = decoded
        && summary.value_bytes > value_bytes
    {
        return Err(LogStoreFailure::malformed_block());
    }
    Ok(decoded)
}

fn decode_array(
    input: &mut Input<'_>,
    depth: u8,
    value_bytes: usize,
    limits: CodecLimits,
    mode: DecodeMode,
) -> Result<DecodedValue, LogStoreFailure> {
    let next = depth
        .checked_sub(1)
        .ok_or_else(LogStoreFailure::malformed_block)?;
    let count = input.count(limits.array_entries)?;
    let mut values = match mode {
        DecodeMode::Build => Some(bounded_vec(count)?),
        DecodeMode::ValidateOnly => None,
    };
    let mut summary = ValueSummary {
        value_bytes: 0,
        decoded_bytes: 0,
    };
    for _ in 0..count {
        let value = decode_mode(input, next, value_bytes, limits, mode)?;
        match (&mut values, value) {
            (Some(values), DecodedValue::Built(value)) => values.push(value),
            (None, DecodedValue::Validated(value)) => {
                summary.value_bytes = checked_add(summary.value_bytes, value.value_bytes)?;
                summary.decoded_bytes = checked_add(summary.decoded_bytes, value.decoded_bytes)?;
            },
            _ => return Err(LogStoreFailure::malformed_block()),
        }
    }
    match values {
        Some(values) => Ok(DecodedValue::Built(CandidateAttributeValue::array(values))),
        None => Ok(DecodedValue::Validated(summary)),
    }
}

fn decode_key_value_list(
    input: &mut Input<'_>,
    depth: u8,
    value_bytes: usize,
    limits: CodecLimits,
    mode: DecodeMode,
) -> Result<DecodedValue, LogStoreFailure> {
    let next = depth
        .checked_sub(1)
        .ok_or_else(LogStoreFailure::malformed_block)?;
    let count = input.count(limits.key_value_list_entries)?;
    let mut values = match mode {
        DecodeMode::Build => Some(bounded_vec(count)?),
        DecodeMode::ValidateOnly => None,
    };
    let mut summary = ValueSummary {
        value_bytes: 0,
        decoded_bytes: 0,
    };
    for _ in 0..count {
        let key = input.string_slice(limits.key_bytes)?;
        if key.is_empty() {
            return Err(LogStoreFailure::malformed_block());
        }
        let value = decode_mode(input, next, value_bytes, limits, mode)?;
        match (&mut values, value) {
            (Some(values), DecodedValue::Built(value)) => {
                values.push(CandidateKeyValue::new(try_string(key)?, value));
            },
            (None, DecodedValue::Validated(value)) => {
                summary.value_bytes = checked_add(summary.value_bytes, value.value_bytes)?;
                summary.decoded_bytes = checked_add(summary.decoded_bytes, key.len())?;
                summary.decoded_bytes = checked_add(summary.decoded_bytes, value.decoded_bytes)?;
            },
            _ => return Err(LogStoreFailure::malformed_block()),
        }
    }
    match values {
        Some(values) => Ok(DecodedValue::Built(
            CandidateAttributeValue::key_value_list(values),
        )),
        None => Ok(DecodedValue::Validated(summary)),
    }
}

fn mode_value(mode: DecodeMode, value: CandidateAttributeValue) -> DecodedValue {
    match mode {
        DecodeMode::Build => DecodedValue::Built(value),
        DecodeMode::ValidateOnly => DecodedValue::Validated(ValueSummary {
            value_bytes: 0,
            decoded_bytes: 0,
        }),
    }
}

fn scalar(value: DecodedValue, bytes: usize) -> DecodedValue {
    match value {
        DecodedValue::Built(value) => DecodedValue::Built(value),
        DecodedValue::Validated(_) => DecodedValue::Validated(ValueSummary {
            value_bytes: bytes,
            decoded_bytes: bytes,
        }),
    }
}

fn sequence(
    input: &mut Input<'_>,
    maximum: usize,
    mode: DecodeMode,
    utf8: bool,
) -> Result<DecodedValue, LogStoreFailure> {
    let bytes = input.bytes_slice(maximum)?;
    if utf8 {
        let value = std::str::from_utf8(bytes).map_err(|_| LogStoreFailure::malformed_block())?;
        return match mode {
            DecodeMode::Build => Ok(DecodedValue::Built(CandidateAttributeValue::string(
                try_string(value)?,
            ))),
            DecodeMode::ValidateOnly => Ok(DecodedValue::Validated(ValueSummary {
                value_bytes: bytes.len(),
                decoded_bytes: bytes.len(),
            })),
        };
    }
    match mode {
        DecodeMode::Build => {
            let mut value = Vec::new();
            value
                .try_reserve_exact(bytes.len())
                .map_err(|_| LogStoreFailure::resource_exhausted())?;
            value.extend_from_slice(bytes);
            Ok(DecodedValue::Built(CandidateAttributeValue::bytes(value)))
        },
        DecodeMode::ValidateOnly => Ok(DecodedValue::Validated(ValueSummary {
            value_bytes: bytes.len(),
            decoded_bytes: bytes.len(),
        })),
    }
}

fn try_string(source: &str) -> Result<String, LogStoreFailure> {
    let mut value = String::new();
    value
        .try_reserve_exact(source.len())
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    value.push_str(source);
    Ok(value)
}

fn checked_add(left: usize, right: usize) -> Result<usize, LogStoreFailure> {
    left.checked_add(right)
        .ok_or_else(LogStoreFailure::malformed_block)
}
