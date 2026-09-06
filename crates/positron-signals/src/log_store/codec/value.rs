use positron_domain::value::{AttributeValueKind, MarkerAction, ValidatedAttributeValue};

use super::size::bounded_add;
use super::{put_bytes, put_count};
use crate::log_store::LogStoreFailure;

mod decode;

pub(in crate::log_store::codec) use decode::{decode, validate};

pub(super) fn encoded_length(
    value: &ValidatedAttributeValue,
    depth: u8,
) -> Result<usize, LogStoreFailure> {
    if value.marker_action().is_some() {
        return Ok(3);
    }
    if value.truncation_action().is_some() {
        let child = value
            .truncated_value()
            .ok_or_else(LogStoreFailure::invalid_input)?;
        return bounded_add(3, encoded_length(child, depth)?);
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
        AttributeValueKind::Marker => return Err(LogStoreFailure::invalid_input()),
    })
}

pub(super) fn encode(
    output: &mut Vec<u8>,
    value: &ValidatedAttributeValue,
    depth: u8,
) -> Result<(), LogStoreFailure> {
    if let Some(action) = value.marker_action() {
        output.push(8);
        output.push(marker_action_tag(action)?);
        output.push(native_kind_tag(
            value
                .marker_original_kind()
                .ok_or_else(LogStoreFailure::invalid_input)?,
        )?);
        return Ok(());
    }
    if let Some(action) = value.truncation_action() {
        let child = value
            .truncated_value()
            .ok_or_else(LogStoreFailure::invalid_input)?;
        output.push(8);
        output.push(marker_action_tag(action)?);
        output.push(native_kind_tag(child.kind())?);
        return encode(output, child, depth);
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
        AttributeValueKind::Marker => return Err(LogStoreFailure::invalid_input()),
    }
    Ok(())
}

fn marker_action_tag(action: MarkerAction) -> Result<u8, LogStoreFailure> {
    match action {
        MarkerAction::Removed => Ok(0),
        MarkerAction::Redacted => Ok(1),
        MarkerAction::TruncatedBytes => Ok(2),
        MarkerAction::TruncatedElements => Ok(3),
    }
}

fn native_kind_tag(kind: AttributeValueKind) -> Result<u8, LogStoreFailure> {
    match kind {
        AttributeValueKind::Null => Ok(0),
        AttributeValueKind::Boolean => Ok(1),
        AttributeValueKind::SignedInteger => Ok(2),
        AttributeValueKind::FloatingPoint => Ok(3),
        AttributeValueKind::String => Ok(4),
        AttributeValueKind::Bytes => Ok(5),
        AttributeValueKind::Array => Ok(6),
        AttributeValueKind::KeyValueList => Ok(7),
        AttributeValueKind::Marker => Err(LogStoreFailure::invalid_input()),
    }
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
