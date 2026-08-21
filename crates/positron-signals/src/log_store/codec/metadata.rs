use crate::log_store::{LogMetadata, LogStoreFailure};

use super::{CodecLimits, Input, put_bytes, put_i32, put_u32};

pub(super) fn encode(output: &mut Vec<u8>, metadata: &LogMetadata) -> Result<(), LogStoreFailure> {
    put_i32(output, metadata.severity_number());
    put_bytes(output, metadata.severity_text().as_bytes())?;
    put_bytes(output, metadata.event_name().as_bytes())?;
    encode_optional_id(output, metadata.trace_id().as_ref());
    encode_optional_id(output, metadata.span_id().as_ref());
    put_u32(output, metadata.flags());
    put_u32(output, metadata.dropped_attributes_count());
    put_u32(output, metadata.resource_dropped_attributes_count());
    put_bytes(output, metadata.resource_schema_url().as_bytes())?;
    put_bytes(output, metadata.scope_name().as_bytes())?;
    put_bytes(output, metadata.scope_version().as_bytes())?;
    put_u32(output, metadata.scope_dropped_attributes_count());
    put_bytes(output, metadata.scope_schema_url().as_bytes())?;
    Ok(())
}

pub(super) fn decode(
    input: &mut Input<'_>,
    limits: CodecLimits,
) -> Result<LogMetadata, LogStoreFailure> {
    let severity_number = input.i32()?;
    let severity_text = input.string(limits.record_bytes)?;
    let event_name = input.string(limits.record_bytes)?;
    let trace_id = decode_optional_id(input)?;
    let span_id = decode_optional_id(input)?;
    let flags = input.u32()?;
    let dropped_attributes_count = input.u32()?;
    let resource_dropped_attributes_count = input.u32()?;
    let resource_schema_url = input.string(limits.record_bytes)?;
    let scope_name = input.string(limits.record_bytes)?;
    let scope_version = input.string(limits.record_bytes)?;
    let scope_dropped_attributes_count = input.u32()?;
    let scope_schema_url = input.string(limits.record_bytes)?;
    Ok(LogMetadata::new_with_event_name(
        severity_number,
        severity_text,
        event_name,
        trace_id,
        span_id,
        flags,
        dropped_attributes_count,
        resource_dropped_attributes_count,
        resource_schema_url,
        scope_name,
        scope_version,
        scope_dropped_attributes_count,
        scope_schema_url,
    ))
}

pub(super) fn skip(input: &mut Input<'_>, limits: CodecLimits) -> Result<(), LogStoreFailure> {
    input.take(4)?;
    input.skip_string(limits.record_bytes)?;
    input.skip_string(limits.record_bytes)?;
    skip_optional_id::<16>(input)?;
    skip_optional_id::<8>(input)?;
    input.take(12)?;
    input.skip_string(limits.record_bytes)?;
    input.skip_string(limits.record_bytes)?;
    input.skip_string(limits.record_bytes)?;
    input.take(4)?;
    input.skip_string(limits.record_bytes)
}

pub(super) fn encoded_length(metadata: &LogMetadata) -> Result<usize, LogStoreFailure> {
    let fixed = 46_usize
        .checked_add(metadata.trace_id().map_or(0, |_| 16))
        .and_then(|bytes| bytes.checked_add(metadata.span_id().map_or(0, |_| 8)))
        .ok_or_else(LogStoreFailure::limit_exceeded)?;
    [
        metadata.severity_text().len(),
        metadata.event_name().len(),
        metadata.resource_schema_url().len(),
        metadata.scope_name().len(),
        metadata.scope_version().len(),
        metadata.scope_schema_url().len(),
    ]
    .into_iter()
    .try_fold(fixed, |total, bytes| {
        total
            .checked_add(bytes)
            .ok_or_else(LogStoreFailure::limit_exceeded)
    })
}

fn encode_optional_id<const N: usize>(output: &mut Vec<u8>, value: Option<&[u8; N]>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(value);
        },
        None => output.push(0),
    }
}

fn decode_optional_id<const N: usize>(
    input: &mut Input<'_>,
) -> Result<Option<[u8; N]>, LogStoreFailure> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.array()?)),
        _ => Err(LogStoreFailure::malformed_block()),
    }
}

fn skip_optional_id<const N: usize>(input: &mut Input<'_>) -> Result<(), LogStoreFailure> {
    match input.u8()? {
        0 => Ok(()),
        1 => input.take(N).map(|_| ()),
        _ => Err(LogStoreFailure::malformed_block()),
    }
}
