use positron_domain::value::{
    AttributeValueKind, CandidateAttributeValue, CandidateKeyValue, MarkerAction,
};

use super::super::{CodecLimits, Input, bounded_vec};
use crate::log_store::LogStoreFailure;

pub(in crate::log_store::codec) fn decode(
    input: &mut Input<'_>,
    depth: u8,
    value_bytes: usize,
    limits: CodecLimits,
    version: u16,
) -> Result<CandidateAttributeValue, LogStoreFailure> {
    match decode_mode(
        input,
        depth,
        value_bytes,
        limits,
        version,
        DecodeMode::Build,
    )? {
        DecodedValue::Built(value) => Ok(value),
        DecodedValue::Validated(_) => Err(LogStoreFailure::malformed_block()),
    }
}

pub(in crate::log_store::codec) fn validate(
    input: &mut Input<'_>,
    depth: u8,
    value_bytes: usize,
    limits: CodecLimits,
    version: u16,
) -> Result<ValueSummary, LogStoreFailure> {
    match decode_mode(
        input,
        depth,
        value_bytes,
        limits,
        version,
        DecodeMode::ValidateOnly,
    )? {
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
    marker: bool,
    policy_root: bool,
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
    version: u16,
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
        6 => decode_array(input, depth, value_bytes, limits, version, mode)?,
        7 => decode_key_value_list(input, depth, value_bytes, limits, version, mode)?,
        8 if version >= 3 => decode_marker(input, depth, value_bytes, limits, version, mode)?,
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
    version: u16,
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
        marker: false,
        policy_root: false,
    };
    for _ in 0..count {
        let value = decode_mode(input, next, value_bytes, limits, version, mode)?;
        match (&mut values, value) {
            (Some(values), DecodedValue::Built(value)) => values.push(value),
            (None, DecodedValue::Validated(value)) => {
                summary.value_bytes = checked_add(summary.value_bytes, value.value_bytes)?;
                summary.decoded_bytes = checked_add(summary.decoded_bytes, value.decoded_bytes)?;
                summary.marker |= value.marker;
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
    version: u16,
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
        marker: false,
        policy_root: false,
    };
    for _ in 0..count {
        let key = input.string_slice(limits.key_bytes)?;
        if key.is_empty() {
            return Err(LogStoreFailure::malformed_block());
        }
        let value = decode_mode(input, next, value_bytes, limits, version, mode)?;
        match (&mut values, value) {
            (Some(values), DecodedValue::Built(value)) => {
                values.push(CandidateKeyValue::new(try_string(key)?, value));
            },
            (None, DecodedValue::Validated(value)) => {
                summary.value_bytes = checked_add(summary.value_bytes, value.value_bytes)?;
                summary.decoded_bytes = checked_add(summary.decoded_bytes, key.len())?;
                summary.decoded_bytes = checked_add(summary.decoded_bytes, value.decoded_bytes)?;
                summary.marker |= value.marker;
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
            marker: false,
            policy_root: false,
        }),
    }
}

fn decode_marker(
    input: &mut Input<'_>,
    depth: u8,
    value_bytes: usize,
    limits: CodecLimits,
    version: u16,
    mode: DecodeMode,
) -> Result<DecodedValue, LogStoreFailure> {
    let action = match input.u8()? {
        0 => MarkerAction::Removed,
        1 => MarkerAction::Redacted,
        2 => MarkerAction::TruncatedBytes,
        3 => MarkerAction::TruncatedElements,
        _ => return Err(LogStoreFailure::malformed_block()),
    };
    let original_kind = match input.u8()? {
        0 => AttributeValueKind::Null,
        1 => AttributeValueKind::Boolean,
        2 => AttributeValueKind::SignedInteger,
        3 => AttributeValueKind::FloatingPoint,
        4 => AttributeValueKind::String,
        5 => AttributeValueKind::Bytes,
        6 => AttributeValueKind::Array,
        7 => AttributeValueKind::KeyValueList,
        _ => return Err(LogStoreFailure::malformed_block()),
    };
    match action {
        MarkerAction::Removed | MarkerAction::Redacted => Ok(match mode {
            DecodeMode::Build => DecodedValue::Built(CandidateAttributeValue::redaction_marker(
                original_kind,
                action,
            )),
            DecodeMode::ValidateOnly => DecodedValue::Validated(ValueSummary {
                value_bytes: 0,
                decoded_bytes: 0,
                marker: true,
                policy_root: true,
            }),
        }),
        MarkerAction::TruncatedBytes | MarkerAction::TruncatedElements => {
            let child = decode_mode(input, depth, value_bytes, limits, version, mode)?;
            match child {
                DecodedValue::Built(child) => {
                    if candidate_kind(&child) != original_kind
                        || candidate_has_marker(&child)
                        || !valid_truncation(action, original_kind)
                    {
                        return Err(LogStoreFailure::malformed_block());
                    }
                    Ok(DecodedValue::Built(CandidateAttributeValue::truncated(
                        child, action,
                    )))
                },
                DecodedValue::Validated(summary) => {
                    if summary.policy_root || !valid_truncation(action, original_kind) {
                        return Err(LogStoreFailure::malformed_block());
                    }
                    Ok(DecodedValue::Validated(ValueSummary {
                        value_bytes: summary.value_bytes,
                        decoded_bytes: summary.decoded_bytes,
                        marker: true,
                        policy_root: true,
                    }))
                },
            }
        },
    }
}

fn candidate_kind(value: &CandidateAttributeValue) -> AttributeValueKind {
    match value {
        CandidateAttributeValue::Null => AttributeValueKind::Null,
        CandidateAttributeValue::Boolean(_) => AttributeValueKind::Boolean,
        CandidateAttributeValue::SignedInteger(_) => AttributeValueKind::SignedInteger,
        CandidateAttributeValue::FloatingPointBits(_) => AttributeValueKind::FloatingPoint,
        CandidateAttributeValue::String(_) => AttributeValueKind::String,
        CandidateAttributeValue::Bytes(_) => AttributeValueKind::Bytes,
        CandidateAttributeValue::Array(_) => AttributeValueKind::Array,
        CandidateAttributeValue::KeyValueList(_) => AttributeValueKind::KeyValueList,
        CandidateAttributeValue::Marker(_) => AttributeValueKind::Marker,
        CandidateAttributeValue::Truncated { value, .. } => candidate_kind(value),
    }
}

fn candidate_has_marker(value: &CandidateAttributeValue) -> bool {
    matches!(
        value,
        CandidateAttributeValue::Marker(_) | CandidateAttributeValue::Truncated { .. }
    )
}

fn valid_truncation(action: MarkerAction, kind: AttributeValueKind) -> bool {
    matches!(
        (action, kind),
        (
            MarkerAction::TruncatedBytes,
            AttributeValueKind::String | AttributeValueKind::Bytes
        ) | (
            MarkerAction::TruncatedElements,
            AttributeValueKind::Array | AttributeValueKind::KeyValueList
        )
    )
}

fn scalar(value: DecodedValue, bytes: usize) -> DecodedValue {
    match value {
        DecodedValue::Built(value) => DecodedValue::Built(value),
        DecodedValue::Validated(_) => DecodedValue::Validated(ValueSummary {
            value_bytes: bytes,
            decoded_bytes: bytes,
            marker: false,
            policy_root: false,
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
                marker: false,
                policy_root: false,
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
            marker: false,
            policy_root: false,
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
