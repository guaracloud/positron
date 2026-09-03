use std::collections::BTreeMap;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::trace::v1::Span as OtlpSpan;
use opentelemetry_proto::tonic::trace::v1::span::SpanKind as OtlpSpanKind;
use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, CandidateAttributeValue,
    CandidateKeyValue, ValueLimitProfile,
};
use positron_signals::{
    SamplingDecision, SpanAttributeSet, SpanEvent, SpanKind, SpanLink, SpanObservation,
    SpanObservationDetails, SpanResourceMetadata, SpanScopeMetadata, SpanStatus, SpanStatusCode,
};
use prost::Message;

use super::{TraceReceiveFailure, checked_identifier, checked_timestamp, default_policy};

pub(super) fn native_records(
    decoded: ExportTraceServiceRequest,
    profile: ValueLimitProfile,
) -> Result<(Vec<SpanObservation>, u64), TraceReceiveFailure> {
    let max_records = usize::try_from(profile.effective_limits().request().records().value())
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    let record_count = decoded
        .resource_spans
        .iter()
        .try_fold(0_usize, |total, resource| {
            resource.scope_spans.iter().try_fold(total, |total, scope| {
                total
                    .checked_add(scope.spans.len())
                    .filter(|count| *count <= max_records)
            })
        })
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(record_count)
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    let mut decoded_bytes = 0_u64;
    let max_decoded = usize::try_from(
        profile
            .system_limits()
            .request()
            .decompressed_bytes()
            .value(),
    )
    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    for resource_spans in decoded.resource_spans {
        let resource_schema_url = resource_spans.schema_url;
        let (resource, resource_dropped_attributes_count, entity_refs) =
            resource_spans.resource.map_or_else(
                || (Vec::new(), 0, Vec::new()),
                |resource| {
                    (
                        resource.attributes,
                        resource.dropped_attributes_count,
                        resource.entity_refs,
                    )
                },
            );
        if !entity_refs.is_empty() {
            return Err(TraceReceiveFailure::UnsupportedValue);
        }
        for scope_spans in resource_spans.scope_spans {
            let scope_schema_url = scope_spans.schema_url;
            let (scope_name, scope_version, scope, scope_dropped_attributes_count) =
                scope_spans.scope.map_or_else(
                    || (String::new(), String::new(), Vec::new(), 0),
                    |scope| {
                        (
                            scope.name,
                            scope.version,
                            scope.attributes,
                            scope.dropped_attributes_count,
                        )
                    },
                );
            for span in scope_spans.spans {
                if records.len() >= max_records {
                    return Err(TraceReceiveFailure::ValueLimitExceeded);
                }
                decoded_bytes = decoded_bytes
                    .checked_add(
                        u64::try_from(span.encoded_len())
                            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
                    )
                    .filter(|bytes| {
                        usize::try_from(*bytes)
                            .ok()
                            .is_some_and(|value| value <= max_decoded)
                    })
                    .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
                let attributes = grouped_attributes(&resource, &scope, &span.attributes, profile)?;
                let trace_id = checked_identifier::<16>(&span.trace_id)?;
                let span_id = checked_identifier::<8>(&span.span_id)?;
                let parent_span_id = if span.parent_span_id.is_empty() {
                    None
                } else {
                    Some(checked_identifier::<8>(&span.parent_span_id)?)
                };
                let start_time = event_time(span.start_time_unix_nano)?;
                let end_time = event_time(span.end_time_unix_nano)?;
                if end_time
                    .instant()
                    .zip(start_time.instant())
                    .is_some_and(|(end, start)| end.value() < start.value())
                {
                    return Err(TraceReceiveFailure::MalformedPayload);
                }
                let kind = match OtlpSpanKind::try_from(span.kind) {
                    Ok(OtlpSpanKind::Unspecified) => SpanKind::Unspecified,
                    Ok(OtlpSpanKind::Internal) => SpanKind::Internal,
                    Ok(OtlpSpanKind::Server) => SpanKind::Server,
                    Ok(OtlpSpanKind::Client) => SpanKind::Client,
                    Ok(OtlpSpanKind::Producer) => SpanKind::Producer,
                    Ok(OtlpSpanKind::Consumer) => SpanKind::Consumer,
                    Err(_) => return Err(TraceReceiveFailure::MalformedPayload),
                };
                let sampling = if span.flags == 0 {
                    SamplingDecision::Unknown
                } else if span.flags & 1 == 1 {
                    SamplingDecision::Sampled
                } else {
                    SamplingDecision::NotSampled
                };
                let details = details(
                    &span,
                    SpanDetailMetadata {
                        resource_dropped_attributes_count,
                        resource_schema_url: &resource_schema_url,
                        scope_name: &scope_name,
                        scope_version: &scope_version,
                        scope_dropped_attributes_count,
                        scope_schema_url: &scope_schema_url,
                    },
                    profile,
                )?;
                let observation = SpanObservation::checked_native_with_details(
                    trace_id,
                    span_id,
                    parent_span_id,
                    span.name,
                    start_time,
                    end_time,
                    attributes,
                    kind,
                    sampling,
                    default_policy()?,
                    details,
                )
                .map_err(|failure| match failure.code() {
                    positron_signals::TraceStoreFailureCode::LimitExceeded => {
                        TraceReceiveFailure::ValueLimitExceeded
                    },
                    _ => TraceReceiveFailure::MalformedPayload,
                })?;
                records.push(observation);
            }
        }
    }
    Ok((records, decoded_bytes))
}

fn event_time(value: u64) -> Result<EventTime, TraceReceiveFailure> {
    let timestamp = checked_timestamp(value)?;
    let quality = if timestamp == 0 {
        SourceTimeQuality::Zero
    } else {
        SourceTimeQuality::Usable
    };
    EventTime::received(UnixNanoseconds::new(timestamp), quality)
        .map_err(|_| TraceReceiveFailure::TimestampOutOfRange)
}

fn grouped_attributes(
    resource: &[KeyValue],
    scope: &[KeyValue],
    record: &[KeyValue],
    profile: ValueLimitProfile,
) -> Result<Vec<positron_domain::value::AttributeOccurrenceSet>, TraceReceiveFailure> {
    let mut groups = BTreeMap::<(AttributeNamespace, String), Vec<CandidateAttributeValue>>::new();
    for (namespace, attributes) in [
        (AttributeNamespace::Resource, resource),
        (AttributeNamespace::InstrumentationScope, scope),
        (AttributeNamespace::Record, record),
    ] {
        for attribute in attributes {
            if attribute.key_strindex != 0 {
                return Err(TraceReceiveFailure::UnsupportedValue);
            }
            let value = attribute
                .value
                .clone()
                .map_or_else(|| Ok(CandidateAttributeValue::null()), candidate_value)?;
            groups
                .entry((namespace, attribute.key.clone()))
                .or_default()
                .push(value);
        }
    }
    groups
        .into_iter()
        .map(|((namespace, key), values)| {
            AttributeOccurrenceSetCandidate::new(namespace, key, values)
                .validate(profile)
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)
        })
        .collect()
}

#[derive(Clone, Copy)]
struct SpanDetailMetadata<'a> {
    resource_dropped_attributes_count: u32,
    resource_schema_url: &'a str,
    scope_name: &'a str,
    scope_version: &'a str,
    scope_dropped_attributes_count: u32,
    scope_schema_url: &'a str,
}

fn details(
    span: &OtlpSpan,
    metadata: SpanDetailMetadata<'_>,
    profile: ValueLimitProfile,
) -> Result<SpanObservationDetails, TraceReceiveFailure> {
    let events = span
        .events
        .iter()
        .map(|event| {
            SpanEvent::checked(
                event_time(event.time_unix_nano)?,
                event.name.clone(),
                span_detail_attributes(&event.attributes, profile)?,
                event.dropped_attributes_count,
            )
            .map_err(map_detail_failure)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let links = span
        .links
        .iter()
        .map(|link| {
            SpanLink::checked(
                checked_identifier::<16>(&link.trace_id)?,
                checked_identifier::<8>(&link.span_id)?,
                link.trace_state.clone(),
                link.flags,
                span_detail_attributes(&link.attributes, profile)?,
                link.dropped_attributes_count,
            )
            .map_err(map_detail_failure)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let status = span.status.clone().unwrap_or_default();
    let status_code =
        match opentelemetry_proto::tonic::trace::v1::status::StatusCode::try_from(status.code) {
            Ok(opentelemetry_proto::tonic::trace::v1::status::StatusCode::Unset) => {
                SpanStatusCode::Unset
            },
            Ok(opentelemetry_proto::tonic::trace::v1::status::StatusCode::Ok) => SpanStatusCode::Ok,
            Ok(opentelemetry_proto::tonic::trace::v1::status::StatusCode::Error) => {
                SpanStatusCode::Error
            },
            Err(_) => return Err(TraceReceiveFailure::MalformedPayload),
        };
    let status = SpanStatus::checked(status_code, status.message).map_err(map_detail_failure)?;
    SpanObservationDetails::checked(
        span.trace_state.clone(),
        span.flags,
        status,
        events,
        links,
        span.dropped_attributes_count,
        span.dropped_events_count,
        span.dropped_links_count,
        SpanResourceMetadata::checked(
            metadata.resource_dropped_attributes_count,
            metadata.resource_schema_url.to_owned(),
        )
        .map_err(map_detail_failure)?,
        SpanScopeMetadata::checked(
            metadata.scope_name.to_owned(),
            metadata.scope_version.to_owned(),
            metadata.scope_dropped_attributes_count,
            metadata.scope_schema_url.to_owned(),
        )
        .map_err(map_detail_failure)?,
    )
    .map_err(map_detail_failure)
}

fn span_detail_attributes(
    attributes: &[KeyValue],
    profile: ValueLimitProfile,
) -> Result<Vec<SpanAttributeSet>, TraceReceiveFailure> {
    let mut groups = BTreeMap::<String, Vec<CandidateAttributeValue>>::new();
    for attribute in attributes {
        if attribute.key_strindex != 0 {
            return Err(TraceReceiveFailure::UnsupportedValue);
        }
        let value = attribute
            .value
            .clone()
            .map_or_else(|| Ok(CandidateAttributeValue::null()), candidate_value)?;
        groups.entry(attribute.key.clone()).or_default().push(value);
    }
    groups
        .into_iter()
        .map(|(key, values)| {
            SpanAttributeSet::checked(key, values, profile).map_err(map_detail_failure)
        })
        .collect()
}

fn map_detail_failure(failure: positron_signals::TraceStoreFailure) -> TraceReceiveFailure {
    match failure.code() {
        positron_signals::TraceStoreFailureCode::LimitExceeded => {
            TraceReceiveFailure::ValueLimitExceeded
        },
        positron_signals::TraceStoreFailureCode::ResourceExhausted => {
            TraceReceiveFailure::CapacityUnavailable
        },
        _ => TraceReceiveFailure::MalformedPayload,
    }
}

fn candidate_value(value: AnyValue) -> Result<CandidateAttributeValue, TraceReceiveFailure> {
    let Some(value) = value.value else {
        return Ok(CandidateAttributeValue::null());
    };
    match value {
        any_value::Value::StringValue(value) => Ok(CandidateAttributeValue::string(value)),
        any_value::Value::BoolValue(value) => Ok(CandidateAttributeValue::boolean(value)),
        any_value::Value::IntValue(value) => Ok(CandidateAttributeValue::signed_integer(value)),
        any_value::Value::DoubleValue(value) => Ok(CandidateAttributeValue::floating_point_bits(
            value.to_bits(),
        )),
        any_value::Value::BytesValue(value) => Ok(CandidateAttributeValue::bytes(value)),
        any_value::Value::StringValueStrindex(_) => Err(TraceReceiveFailure::UnsupportedValue),
        any_value::Value::ArrayValue(value) => value
            .values
            .into_iter()
            .map(candidate_value)
            .collect::<Result<Vec<_>, _>>()
            .map(CandidateAttributeValue::array),
        any_value::Value::KvlistValue(value) => value
            .values
            .into_iter()
            .map(|entry| {
                let value = entry
                    .value
                    .map_or_else(|| Ok(CandidateAttributeValue::null()), candidate_value)?;
                Ok(CandidateKeyValue::new(entry.key, value))
            })
            .collect::<Result<Vec<_>, TraceReceiveFailure>>()
            .map(CandidateAttributeValue::key_value_list),
    }
}
