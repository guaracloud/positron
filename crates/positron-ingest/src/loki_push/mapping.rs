use std::collections::BTreeMap;

use positron_domain::identity::TenantAttribution;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, ValueLimitProfile};
use positron_kernel::ResourceReservation;
use serde_json::{Map, Value};

use crate::{NativeLogAttribute, NativeLogBatch, NativeLogCandidate, ReceiveFailure};

mod protobuf;

pub(super) use protobuf::protobuf_batch;

pub(super) fn json_batch<'authority>(
    attribution: TenantAttribution,
    json: Vec<u8>,
    profile: ValueLimitProfile,
    capacity: Option<ResourceReservation<'authority>>,
) -> Result<NativeLogBatch<'authority>, ReceiveFailure> {
    let decoded: Value =
        serde_json::from_slice(&json).map_err(|_| ReceiveFailure::MalformedPayload)?;
    let root = object(&decoded)?;
    let streams = array(required(root, "streams")?)?;
    let limits = profile.system_limits();
    let record_limit = usize::try_from(limits.request().records().value())
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let attribute_limit = usize::try_from(limits.request().aggregate_attributes().value())
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let record_bytes_limit = usize::try_from(limits.record().decoded_bytes().value())
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let mut records = Vec::new();
    let mut attributes = 0_usize;
    for stream in streams {
        let stream = object(stream)?;
        let labels = string_map(required(stream, "stream")?)?;
        let values = array(required(stream, "values")?)?;
        for value in values {
            if records.len() == record_limit {
                return Err(ReceiveFailure::ValueLimitExceeded);
            }
            let fields = array(value)?;
            if !(2..=3).contains(&fields.len()) {
                return Err(ReceiveFailure::MalformedPayload);
            }
            let timestamp = string(fields.first().ok_or(ReceiveFailure::MalformedPayload)?)?
                .parse::<i64>()
                .map_err(|_| ReceiveFailure::TimestampOutOfRange)?;
            let line = string(fields.get(1).ok_or(ReceiveFailure::MalformedPayload)?)?;
            let metadata = match fields.get(2) {
                Some(value) => string_map(value)?,
                None => Vec::new(),
            };
            let record_attributes = labels
                .len()
                .checked_add(metadata.len())
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            attributes = attributes
                .checked_add(record_attributes)
                .filter(|count| *count <= attribute_limit)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            ensure_record_bytes(&labels, &metadata, line, record_bytes_limit)?;
            records.push(native_record(timestamp, line, &labels, &metadata)?);
        }
    }
    let retained = retained_bytes(&records)?;
    NativeLogBatch::new(
        attribution,
        records,
        profile,
        u64::try_from(retained).map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
        capacity,
        crate::PolicyReceiver::LokiPush,
    )
}

fn native_record(
    timestamp: i64,
    line: &str,
    stream: &[(String, String)],
    metadata: &[(String, String)],
) -> Result<NativeLogCandidate, ReceiveFailure> {
    let mut groups = BTreeMap::<(AttributeNamespace, String), Vec<CandidateAttributeValue>>::new();
    for (namespace, source) in [
        (AttributeNamespace::Stream, stream),
        (AttributeNamespace::Record, metadata),
    ] {
        for (key, value) in source {
            groups
                .entry((namespace, key.clone()))
                .or_default()
                .push(CandidateAttributeValue::string(value.clone()));
        }
    }
    let trace_id = correlated_identifier::<16>(stream, metadata, "trace_id");
    let span_id = correlated_identifier::<8>(stream, metadata, "span_id");
    let attributes = groups
        .into_iter()
        .map(|((namespace, key), occurrences)| NativeLogAttribute::new(namespace, key, occurrences))
        .collect();
    Ok(NativeLogCandidate::new(
        Some(timestamp),
        None,
        Some(CandidateAttributeValue::string(line.to_owned())),
        attributes,
        positron_signals::LogMetadata::new(
            0,
            String::new(),
            trace_id,
            span_id,
            0,
            0,
            0,
            String::new(),
            String::new(),
            String::new(),
            0,
            String::new(),
        ),
    ))
}

fn correlated_identifier<const N: usize>(
    stream: &[(String, String)],
    metadata: &[(String, String)],
    key: &str,
) -> Option<[u8; N]> {
    let mut found = None;
    for value in stream
        .iter()
        .chain(metadata)
        .filter_map(|(candidate, value)| (candidate == key).then_some(value))
    {
        let Some(decoded) = decode_hex_identifier(value) else {
            continue;
        };
        if found.is_some_and(|current| current != decoded) {
            return None;
        }
        found = Some(decoded);
    }
    found
}

fn decode_hex_identifier<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.saturating_mul(2) {
        return None;
    }
    let mut decoded = [0_u8; N];
    for (destination, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = hex(*pair.first()?)?;
        let low = hex(*pair.get(1)?)?;
        *destination = (high << 4) | low;
    }
    if decoded.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(decoded)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn ensure_record_bytes(
    stream: &[(String, String)],
    metadata: &[(String, String)],
    line: &str,
    maximum: usize,
) -> Result<(), ReceiveFailure> {
    let bytes = stream
        .iter()
        .chain(metadata)
        .try_fold(line.len(), |bytes, (key, value)| {
            bytes.checked_add(key.len())?.checked_add(value.len())
        })
        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
    if bytes > maximum {
        return Err(ReceiveFailure::ValueLimitExceeded);
    }
    Ok(())
}

fn retained_bytes(records: &[NativeLogCandidate]) -> Result<usize, ReceiveFailure> {
    records
        .iter()
        .try_fold(std::mem::size_of_val(records), |bytes, record| {
            let bytes = record
                .attributes()
                .iter()
                .try_fold(bytes, |bytes, attribute| {
                    let occurrence_bytes = attribute
                        .occurrences()
                        .iter()
                        .try_fold(0_usize, |bytes, value| {
                            bytes.checked_add(candidate_string_bytes(value))
                        })?;
                    bytes
                        .checked_add(std::mem::size_of::<NativeLogAttribute>())?
                        .checked_add(attribute.key().len())?
                        .checked_add(occurrence_bytes)
                })?;
            bytes.checked_add(record.body().map_or(0, candidate_string_bytes))
        })
        .ok_or(ReceiveFailure::ValueLimitExceeded)
}

fn candidate_string_bytes(value: &CandidateAttributeValue) -> usize {
    match value {
        CandidateAttributeValue::String(value) => value.len(),
        _ => 0,
    }
}

fn required<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, ReceiveFailure> {
    object.get(key).ok_or(ReceiveFailure::MalformedPayload)
}

fn object(value: &Value) -> Result<&Map<String, Value>, ReceiveFailure> {
    value.as_object().ok_or(ReceiveFailure::MalformedPayload)
}

fn array(value: &Value) -> Result<&Vec<Value>, ReceiveFailure> {
    value.as_array().ok_or(ReceiveFailure::MalformedPayload)
}

fn string(value: &Value) -> Result<&str, ReceiveFailure> {
    value.as_str().ok_or(ReceiveFailure::MalformedPayload)
}

fn string_map(value: &Value) -> Result<Vec<(String, String)>, ReceiveFailure> {
    object(value)?
        .iter()
        .map(|(key, value)| Ok((key.clone(), string(value)?.to_owned())))
        .collect()
}
