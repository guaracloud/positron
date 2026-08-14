use positron_domain::value::{
    AttributeValueKind, CandidateAttributeValue, CandidateKeyValue, PolicyValueMarker,
    ValidatedAttributeValue,
};

use super::limits::CodecLimits;
use super::size::bounded_add;
use super::{Input, bounded_vec, put_bytes, put_count};
use crate::log_store::LogStoreFailure;

pub(super) fn encoded_length(
    value: &ValidatedAttributeValue,
    depth: u8,
) -> Result<usize, LogStoreFailure> {
    if let Some(retained) = value.truncated_value() {
        let next = depth
            .checked_sub(1)
            .ok_or_else(LogStoreFailure::limit_exceeded)?;
        return bounded_add(1, encoded_length(retained, next)?);
    }
    Ok(match value.kind() {
        AttributeValueKind::Null => 1,
        AttributeValueKind::Boolean => 2,
        AttributeValueKind::SignedInteger | AttributeValueKind::FloatingPoint => 9,
        AttributeValueKind::String => bounded_add(
            5,
            value
                .as_str()
                .ok_or_else(LogStoreFailure::invalid_input)?
                .len(),
        )?,
        AttributeValueKind::Bytes => bounded_add(
            5,
            value
                .as_bytes()
                .ok_or_else(LogStoreFailure::invalid_input)?
                .len(),
        )?,
        AttributeValueKind::Array => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(LogStoreFailure::limit_exceeded)?;
            let count = value
                .array_len()
                .ok_or_else(LogStoreFailure::invalid_input)?;
            (0..count).try_fold(3_usize, |total, index| {
                bounded_add(
                    total,
                    encoded_length(
                        value
                            .array_entry(index)
                            .ok_or_else(LogStoreFailure::invalid_input)?,
                        next,
                    )?,
                )
            })?
        },
        AttributeValueKind::KeyValueList => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(LogStoreFailure::limit_exceeded)?;
            let count = value
                .key_value_list_len()
                .ok_or_else(LogStoreFailure::invalid_input)?;
            (0..count).try_fold(3_usize, |total, index| {
                let entry = value
                    .key_value_entry(index)
                    .ok_or_else(LogStoreFailure::invalid_input)?;
                let total = bounded_add(total, 4)?;
                let total = bounded_add(total, entry.key().len())?;
                bounded_add(total, encoded_length(entry.value(), next)?)
            })?
        },
        AttributeValueKind::PolicyMarker => 1,
    })
}

pub(super) fn encode(
    output: &mut Vec<u8>,
    value: &ValidatedAttributeValue,
    depth: u8,
) -> Result<(), LogStoreFailure> {
    if let Some(retained) = value.truncated_value() {
        output.push(10);
        let next = depth
            .checked_sub(1)
            .ok_or_else(LogStoreFailure::limit_exceeded)?;
        return encode(output, retained, next);
    }
    match value.kind() {
        AttributeValueKind::Null => output.push(0),
        AttributeValueKind::Boolean => {
            output.push(1);
            output.push(u8::from(
                value
                    .as_boolean()
                    .ok_or_else(LogStoreFailure::invalid_input)?,
            ));
        },
        AttributeValueKind::SignedInteger => {
            output.push(2);
            output.extend_from_slice(
                &value
                    .as_signed_integer()
                    .ok_or_else(LogStoreFailure::invalid_input)?
                    .to_be_bytes(),
            );
        },
        AttributeValueKind::FloatingPoint => {
            output.push(3);
            output.extend_from_slice(
                &value
                    .as_floating_point_bits()
                    .ok_or_else(LogStoreFailure::invalid_input)?
                    .to_be_bytes(),
            );
        },
        AttributeValueKind::String => {
            output.push(4);
            put_bytes(
                output,
                value
                    .as_str()
                    .ok_or_else(LogStoreFailure::invalid_input)?
                    .as_bytes(),
            )?;
        },
        AttributeValueKind::Bytes => {
            output.push(5);
            put_bytes(
                output,
                value
                    .as_bytes()
                    .ok_or_else(LogStoreFailure::invalid_input)?,
            )?;
        },
        AttributeValueKind::Array => encode_array(output, value, depth)?,
        AttributeValueKind::KeyValueList => encode_key_value_list(output, value, depth)?,
        AttributeValueKind::PolicyMarker => output.push(
            match value
                .policy_marker()
                .ok_or_else(LogStoreFailure::invalid_input)?
            {
                PolicyValueMarker::Removed => 8,
                PolicyValueMarker::Redacted => 9,
            },
        ),
    }
    Ok(())
}

fn encode_array(
    output: &mut Vec<u8>,
    value: &ValidatedAttributeValue,
    depth: u8,
) -> Result<(), LogStoreFailure> {
    let next = depth
        .checked_sub(1)
        .ok_or_else(LogStoreFailure::limit_exceeded)?;
    output.push(6);
    let count = value
        .array_len()
        .ok_or_else(LogStoreFailure::invalid_input)?;
    put_count(output, count)?;
    for index in 0..count {
        encode(
            output,
            value
                .array_entry(index)
                .ok_or_else(LogStoreFailure::invalid_input)?,
            next,
        )?;
    }
    Ok(())
}

fn encode_key_value_list(
    output: &mut Vec<u8>,
    value: &ValidatedAttributeValue,
    depth: u8,
) -> Result<(), LogStoreFailure> {
    let next = depth
        .checked_sub(1)
        .ok_or_else(LogStoreFailure::limit_exceeded)?;
    output.push(7);
    let count = value
        .key_value_list_len()
        .ok_or_else(LogStoreFailure::invalid_input)?;
    put_count(output, count)?;
    for index in 0..count {
        let entry = value
            .key_value_entry(index)
            .ok_or_else(LogStoreFailure::invalid_input)?;
        put_bytes(output, entry.key().as_bytes())?;
        encode(output, entry.value(), next)?;
    }
    Ok(())
}

pub(super) fn decode(
    input: &mut Input<'_>,
    depth: u8,
    value_bytes: usize,
    limits: CodecLimits,
    version: u16,
) -> Result<CandidateAttributeValue, LogStoreFailure> {
    Ok(match input.u8()? {
        0 => CandidateAttributeValue::null(),
        1 => CandidateAttributeValue::boolean(match input.u8()? {
            0 => false,
            1 => true,
            _ => return Err(LogStoreFailure::malformed_block()),
        }),
        2 => CandidateAttributeValue::signed_integer(input.i64()?),
        3 => CandidateAttributeValue::floating_point_bits(input.u64()?),
        4 => CandidateAttributeValue::string(input.string(value_bytes)?),
        5 => CandidateAttributeValue::bytes(input.bytes(value_bytes)?),
        6 => CandidateAttributeValue::array(decode_array(
            input,
            depth,
            value_bytes,
            limits,
            version,
        )?),
        7 => CandidateAttributeValue::key_value_list(decode_key_value_list(
            input,
            depth,
            value_bytes,
            limits,
            version,
        )?),
        8 if version >= 3 => CandidateAttributeValue::policy_marker(PolicyValueMarker::Removed),
        9 if version >= 3 => CandidateAttributeValue::policy_marker(PolicyValueMarker::Redacted),
        10 if version >= 3 => CandidateAttributeValue::truncated(decode(
            input,
            depth
                .checked_sub(1)
                .ok_or_else(LogStoreFailure::malformed_block)?,
            value_bytes,
            limits,
            version,
        )?),
        _ => return Err(LogStoreFailure::malformed_block()),
    })
}

fn decode_array(
    input: &mut Input<'_>,
    depth: u8,
    value_bytes: usize,
    limits: CodecLimits,
    version: u16,
) -> Result<Vec<CandidateAttributeValue>, LogStoreFailure> {
    let next = depth
        .checked_sub(1)
        .ok_or_else(LogStoreFailure::malformed_block)?;
    let count = input.count(limits.array_entries)?;
    let mut values = bounded_vec(count)?;
    for _ in 0..count {
        values.push(decode(input, next, value_bytes, limits, version)?);
    }
    Ok(values)
}

fn decode_key_value_list(
    input: &mut Input<'_>,
    depth: u8,
    value_bytes: usize,
    limits: CodecLimits,
    version: u16,
) -> Result<Vec<CandidateKeyValue>, LogStoreFailure> {
    let next = depth
        .checked_sub(1)
        .ok_or_else(LogStoreFailure::malformed_block)?;
    let count = input.count(limits.key_value_list_entries)?;
    let mut values = bounded_vec(count)?;
    for _ in 0..count {
        values.push(CandidateKeyValue::new(
            input.string(limits.key_bytes)?,
            decode(input, next, value_bytes, limits, version)?,
        ));
    }
    Ok(values)
}
