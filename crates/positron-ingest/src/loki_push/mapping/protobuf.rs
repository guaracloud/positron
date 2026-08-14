use positron_domain::identity::TenantAttribution;
use positron_domain::value::ValueLimitProfile;
use positron_kernel::ResourceReservation;
use prost::Message;

use crate::{NativeLogBatch, ReceiveFailure};

use super::{ensure_record_bytes, native_record, retained_bytes};
use crate::loki_push::preflight::labels::parse_label_set;
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
        let labels = parse_label_set(
            &stream.labels,
            usize::try_from(limits.dynamic_value().attributes_per_namespace().value())
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
            usize::try_from(limits.dynamic_value().key_path_bytes().value())
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
            usize::try_from(limits.dynamic_value().individual_value_bytes().value())
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
        )?;
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
