use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use positron_domain::identity::TenantAttribution;
use positron_domain::value::ValueLimitProfile;
use prost::Message;

use super::bounds::decoded_record_bytes;
use super::mapping::{candidate_value, checked_timestamp, grouped_attributes};
use super::{NativeLogBatch, NativeLogCandidate, ReceiveFailure};

pub(super) fn native_batch(
    attribution: TenantAttribution,
    decoded: ExportLogsServiceRequest,
    value_limit_profile: ValueLimitProfile,
) -> Result<NativeLogBatch, ReceiveFailure> {
    let mut records = Vec::new();
    let mut attribute_count = 0_usize;
    let mut decoded_batch_bytes = 0_usize;
    let encoded_record_limit = usize::try_from(
        value_limit_profile
            .effective_limits()
            .record()
            .encoded_bytes()
            .value(),
    )
    .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let structural_nesting_depth = value_limit_profile
        .system_limits()
        .dynamic_value()
        .nesting_depth()
        .value();
    let structural_decoded_record_bytes = usize::try_from(
        value_limit_profile
            .system_limits()
            .record()
            .decoded_bytes()
            .value(),
    )
    .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let structural_decoded_batch_bytes = usize::try_from(
        value_limit_profile
            .system_limits()
            .request()
            .decompressed_bytes()
            .value(),
    )
    .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let structural_record_limit = usize::try_from(
        value_limit_profile
            .system_limits()
            .request()
            .records()
            .value(),
    )
    .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let structural_attribute_limit = usize::try_from(
        value_limit_profile
            .system_limits()
            .request()
            .aggregate_attributes()
            .value(),
    )
    .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    for resource_logs in decoded.resource_logs {
        let resource = resource_logs
            .resource
            .map_or_else(Vec::new, |value| value.attributes);
        for scope_logs in resource_logs.scope_logs {
            let scope = scope_logs
                .scope
                .map_or_else(Vec::new, |value| value.attributes);
            for log in scope_logs.log_records {
                if records.len() == structural_record_limit
                    || log.encoded_len() > encoded_record_limit
                {
                    return Err(ReceiveFailure::ValueLimitExceeded);
                }
                let decoded_record_bytes = decoded_record_bytes(
                    &resource,
                    &scope,
                    &log,
                    structural_nesting_depth,
                    structural_decoded_record_bytes,
                )?;
                decoded_batch_bytes = decoded_batch_bytes
                    .checked_add(decoded_record_bytes)
                    .filter(|bytes| *bytes <= structural_decoded_batch_bytes)
                    .ok_or(ReceiveFailure::ValueLimitExceeded)?;
                attribute_count = attribute_count
                    .checked_add(resource.len())
                    .and_then(|count| count.checked_add(scope.len()))
                    .and_then(|count| count.checked_add(log.attributes.len()))
                    .filter(|count| *count <= structural_attribute_limit)
                    .ok_or(ReceiveFailure::ValueLimitExceeded)?;
                let body = log
                    .body
                    .map(|value| candidate_value(value, structural_nesting_depth))
                    .transpose()?;
                let attributes = grouped_attributes(
                    &resource,
                    &scope,
                    &log.attributes,
                    structural_nesting_depth,
                )?;
                records.push(NativeLogCandidate {
                    event_time_unix_nanos: Some(checked_timestamp(log.time_unix_nano)?),
                    observed_time_unix_nanos: Some(checked_timestamp(log.observed_time_unix_nano)?),
                    body,
                    attributes,
                });
            }
        }
    }
    Ok(NativeLogBatch {
        attribution,
        records,
        value_limit_profile,
    })
}
