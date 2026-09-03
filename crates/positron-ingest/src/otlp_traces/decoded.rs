use std::collections::BTreeMap;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::trace::v1::Span as OtlpSpan;
use opentelemetry_proto::tonic::trace::v1::span::SpanKind as OtlpSpanKind;
use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    AttributeNamespace, CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile,
};
use positron_policy::{NativePolicyAttribute, NativeTraceCandidate, TracePolicyEvaluation};
use positron_signals::{
    SamplingDecision, SpanAttributeSet, SpanEvent, SpanKind, SpanLink, SpanObservation,
    SpanObservationDetails, SpanResourceMetadata, SpanScopeMetadata, SpanStatus, SpanStatusCode,
};
use prost::Message;

use super::{TraceReceiveFailure, checked_identifier, checked_timestamp};

/// A bounded native span draft that has not crossed policy or Signal Store
/// semantic validation. OTLP-specific details are already converted to the
/// immutable native detail types; policy sees only generic attributes.
#[derive(Debug)]
pub(super) struct NativeSpanDraft {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    name: String,
    start_time: EventTime,
    end_time: EventTime,
    attributes: Vec<NativePolicyAttribute>,
    kind: SpanKind,
    sampling: SamplingDecision,
    details: SpanObservationDetails,
    estimated_bytes: u64,
}

impl NativeSpanDraft {
    pub(super) fn evaluate(
        self,
        policy: &positron_policy::IngestPolicy,
        receiver: crate::PolicyReceiver,
        profile: ValueLimitProfile,
    ) -> Result<Option<SpanObservation>, TraceReceiveFailure> {
        let Self {
            trace_id,
            span_id,
            parent_span_id,
            name,
            start_time,
            end_time,
            attributes,
            kind,
            sampling,
            details,
            estimated_bytes: _,
        } = self;
        let candidate = NativeTraceCandidate::new(attributes);
        let evaluation = policy
            .evaluate_trace(candidate, receiver)
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let TracePolicyEvaluation::Accepted(evaluated) = evaluation else {
            return Ok(None);
        };
        let (attributes, provenance) = evaluated.into_parts();
        SpanObservation::checked_native_with_policy_attributes(
            trace_id,
            span_id,
            parent_span_id,
            name,
            start_time,
            end_time,
            attributes,
            kind,
            sampling,
            provenance,
            details,
            profile,
        )
        .map(Some)
        .map_err(super::map_store_failure)
    }

    pub(super) const fn estimated_bytes(&self) -> u64 {
        self.estimated_bytes
    }
}

pub(super) fn native_records(
    decoded: ExportTraceServiceRequest,
    profile: ValueLimitProfile,
) -> Result<(Vec<NativeSpanDraft>, [usize; 3]), TraceReceiveFailure> {
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
    let mut rejections = [0_usize; 3];
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
        let has_entity_refs = !entity_refs.is_empty();
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
                if has_entity_refs {
                    super::increment_rejection(
                        &mut rejections,
                        crate::IngestFailureCode::InvalidRecord,
                    );
                    continue;
                }
                match native_draft(
                    span,
                    &resource,
                    &scope,
                    SpanDetailMetadata {
                        resource_dropped_attributes_count,
                        resource_schema_url: &resource_schema_url,
                        scope_name: &scope_name,
                        scope_version: &scope_version,
                        scope_dropped_attributes_count,
                        scope_schema_url: &scope_schema_url,
                    },
                    profile,
                ) {
                    Ok(draft) => records.push(draft),
                    Err(failure) => {
                        super::increment_rejection(&mut rejections, rejection_code(failure))
                    },
                }
            }
        }
    }
    Ok((records, rejections))
}

fn native_draft(
    span: OtlpSpan,
    resource: &[KeyValue],
    scope: &[KeyValue],
    metadata: SpanDetailMetadata<'_>,
    profile: ValueLimitProfile,
) -> Result<NativeSpanDraft, TraceReceiveFailure> {
    let mut estimated_bytes = u64::try_from(span.encoded_len())
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
        .checked_add(512)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    for values in [resource, scope] {
        estimated_bytes = estimated_bytes
            .checked_add(key_values_encoded_bytes(values)?)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    }
    estimated_bytes = estimated_bytes
        .checked_add(
            u64::try_from(
                metadata
                    .resource_schema_url
                    .len()
                    .saturating_add(metadata.scope_name.len())
                    .saturating_add(metadata.scope_version.len())
                    .saturating_add(metadata.scope_schema_url.len()),
            )
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
        )
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let attributes = grouped_attributes(resource, scope, &span.attributes)?;
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
    let details = details(&span, metadata, profile)?;
    Ok(NativeSpanDraft {
        trace_id,
        span_id,
        parent_span_id,
        name: span.name,
        start_time,
        end_time,
        attributes,
        kind,
        sampling,
        details,
        estimated_bytes,
    })
}

fn key_values_encoded_bytes(values: &[KeyValue]) -> Result<u64, TraceReceiveFailure> {
    values.iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(
                u64::try_from(value.encoded_len())
                    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
            )
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
    })
}

fn rejection_code(failure: TraceReceiveFailure) -> crate::IngestFailureCode {
    match failure {
        TraceReceiveFailure::ValueLimitExceeded => crate::IngestFailureCode::ValueLimitExceeded,
        _ => crate::IngestFailureCode::InvalidRecord,
    }
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
) -> Result<Vec<NativePolicyAttribute>, TraceReceiveFailure> {
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
        .map(|((namespace, key), values)| Ok(NativePolicyAttribute::new(namespace, key, values)))
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
