use positron_domain::identity::TenantAttribution;
use positron_domain::value::ValueLimitProfile;
use positron_kernel::ResourceReservation;
use prost::Message;

use crate::{NativeLogBatch, ReceiveFailure};

use super::{ensure_record_bytes, native_record, retained_bytes};
use crate::loki_push::proto::PushRequest;

pub(crate) fn protobuf_batch<'authority>(
    attribution: TenantAttribution,
    protobuf: Vec<u8>,
    profile: ValueLimitProfile,
    capacity: Option<ResourceReservation<'authority>>,
) -> Result<NativeLogBatch<'authority>, ReceiveFailure> {
    let decoded =
        PushRequest::decode(protobuf.as_slice()).map_err(|_| ReceiveFailure::MalformedPayload)?;
    if !decoded.format.is_empty() && decoded.format != "loki" {
        return Err(ReceiveFailure::UnsupportedValue);
    }
    let limits = profile.system_limits();
    let record_limit = usize::try_from(limits.request().records().value())
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let attribute_limit = usize::try_from(limits.request().aggregate_attributes().value())
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let record_bytes_limit = usize::try_from(limits.record().decoded_bytes().value())
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let mut records = Vec::new();
    let mut attributes = 0_usize;
    for stream in decoded.streams {
        let labels = parse_labels(&stream.labels)?;
        for entry in stream.entries {
            if records.len() == record_limit {
                return Err(ReceiveFailure::ValueLimitExceeded);
            }
            if !entry.parsed.is_empty() {
                return Err(ReceiveFailure::UnsupportedValue);
            }
            let timestamp = entry.timestamp.ok_or(ReceiveFailure::MalformedPayload)?;
            let nanos = i64::from(timestamp.nanos);
            if !(0..1_000_000_000).contains(&nanos) {
                return Err(ReceiveFailure::TimestampOutOfRange);
            }
            let timestamp = timestamp
                .seconds
                .checked_mul(1_000_000_000)
                .and_then(|seconds| seconds.checked_add(nanos))
                .ok_or(ReceiveFailure::TimestampOutOfRange)?;
            let metadata = entry
                .structured_metadata
                .into_iter()
                .map(|pair| (pair.name, pair.value))
                .collect::<Vec<_>>();
            attributes = attributes
                .checked_add(labels.len())
                .and_then(|count| count.checked_add(metadata.len()))
                .filter(|count| *count <= attribute_limit)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            ensure_record_bytes(&labels, &metadata, &entry.line, record_bytes_limit)?;
            records.push(native_record(timestamp, &entry.line, &labels, &metadata)?);
        }
    }
    let retained = retained_bytes(&records)?;
    NativeLogBatch::new(
        attribution,
        records,
        profile,
        u64::try_from(retained).map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
        capacity,
    )
}

fn parse_labels(source: &str) -> Result<Vec<(String, String)>, ReceiveFailure> {
    let source = source.trim();
    let inner = source
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .ok_or(ReceiveFailure::MalformedPayload)?;
    let mut remaining = inner;
    let mut labels = Vec::new();
    while !remaining.trim().is_empty() {
        remaining = remaining.trim_start();
        let equals = remaining
            .find('=')
            .ok_or(ReceiveFailure::MalformedPayload)?;
        let name = remaining[..equals].trim();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'.'))
        {
            return Err(ReceiveFailure::MalformedPayload);
        }
        remaining = remaining[(equals + 1)..].trim_start();
        let quoted = quoted_value_length(remaining)?;
        let value = serde_json::from_str::<String>(&remaining[..quoted])
            .map_err(|_| ReceiveFailure::MalformedPayload)?;
        labels.push((name.to_owned(), value));
        remaining = remaining[quoted..].trim_start();
        if remaining.is_empty() {
            break;
        }
        remaining = remaining
            .strip_prefix(',')
            .ok_or(ReceiveFailure::MalformedPayload)?;
    }
    Ok(labels)
}

fn quoted_value_length(source: &str) -> Result<usize, ReceiveFailure> {
    if !source.starts_with('"') {
        return Err(ReceiveFailure::MalformedPayload);
    }
    let mut escaped = false;
    for (index, byte) in source.bytes().enumerate().skip(1) {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Ok(index + 1);
        }
    }
    Err(ReceiveFailure::MalformedPayload)
}
