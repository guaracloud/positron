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
    let fields = decode_fields(input, limits)?;
    Ok(LogMetadata::new_with_event_name(
        fields.severity_number,
        try_string(fields.severity_text)?,
        try_string(fields.event_name)?,
        fields.trace_id,
        fields.span_id,
        fields.flags,
        fields.dropped_attributes_count,
        fields.resource_dropped_attributes_count,
        try_string(fields.resource_schema_url)?,
        try_string(fields.scope_name)?,
        try_string(fields.scope_version)?,
        fields.scope_dropped_attributes_count,
        try_string(fields.scope_schema_url)?,
    ))
}

pub(super) fn validate(
    input: &mut Input<'_>,
    limits: CodecLimits,
) -> Result<usize, LogStoreFailure> {
    let fields = decode_fields(input, limits)?;
    fields.decoded_size_bytes()
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

struct DecodedFields<'a> {
    severity_number: i32,
    severity_text: &'a str,
    event_name: &'a str,
    trace_id: Option<[u8; 16]>,
    span_id: Option<[u8; 8]>,
    flags: u32,
    dropped_attributes_count: u32,
    resource_dropped_attributes_count: u32,
    resource_schema_url: &'a str,
    scope_name: &'a str,
    scope_version: &'a str,
    scope_dropped_attributes_count: u32,
    scope_schema_url: &'a str,
}

impl DecodedFields<'_> {
    fn decoded_size_bytes(&self) -> Result<usize, LogStoreFailure> {
        [
            self.severity_text.len(),
            self.event_name.len(),
            self.resource_schema_url.len(),
            self.scope_name.len(),
            self.scope_version.len(),
            self.scope_schema_url.len(),
        ]
        .into_iter()
        .try_fold(0_usize, |total, bytes| {
            total
                .checked_add(bytes)
                .ok_or_else(LogStoreFailure::malformed_block)
        })
    }
}

fn decode_fields<'a>(
    input: &mut Input<'a>,
    limits: CodecLimits,
) -> Result<DecodedFields<'a>, LogStoreFailure> {
    Ok(DecodedFields {
        severity_number: input.i32()?,
        severity_text: input.string_slice(limits.record_bytes)?,
        event_name: input.string_slice(limits.record_bytes)?,
        trace_id: decode_optional_id(input)?,
        span_id: decode_optional_id(input)?,
        flags: input.u32()?,
        dropped_attributes_count: input.u32()?,
        resource_dropped_attributes_count: input.u32()?,
        resource_schema_url: input.string_slice(limits.record_bytes)?,
        scope_name: input.string_slice(limits.record_bytes)?,
        scope_version: input.string_slice(limits.record_bytes)?,
        scope_dropped_attributes_count: input.u32()?,
        scope_schema_url: input.string_slice(limits.record_bytes)?,
    })
}

fn try_string(source: &str) -> Result<String, LogStoreFailure> {
    let mut value = String::new();
    value
        .try_reserve_exact(source.len())
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    value.push_str(source);
    Ok(value)
}
