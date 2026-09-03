use std::collections::BTreeMap;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::trace::v1::Span as OtlpSpan;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, ValueLimitProfile};
use positron_policy::NativePolicyAttribute;
use prost::Message;

use super::super::TraceReceiveFailure;
use super::{NativeSpanDetailDraft, NativeSpanDraft, SpanDetailMetadata};

pub(crate) fn native_records(
    decoded: ExportTraceServiceRequest,
    profile: &ValueLimitProfile,
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
                match native_draft(
                    span,
                    &resource,
                    &scope,
                    SpanDetailMetadata {
                        resource_dropped_attributes_count,
                        resource_schema_url: resource_schema_url.clone(),
                        scope_name: scope_name.clone(),
                        scope_version: scope_version.clone(),
                        scope_dropped_attributes_count,
                        scope_schema_url: scope_schema_url.clone(),
                        has_entity_refs,
                    },
                    profile,
                ) {
                    Ok(draft) => records.push(draft),
                    Err(failure) => {
                        super::super::increment_rejection(&mut rejections, rejection_code(failure))
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
    metadata: SpanDetailMetadata,
    profile: &ValueLimitProfile,
) -> Result<NativeSpanDraft, TraceReceiveFailure> {
    validate_raw_span(&span, &metadata, profile)?;
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
    let attributes = grouped_attributes(resource, scope, &span.attributes, profile)?;
    let details = NativeSpanDetailDraft {
        trace_state: span.trace_state,
        flags: span.flags,
        status: span.status,
        events: span.events,
        links: span.links,
        dropped_attributes_count: span.dropped_attributes_count,
        dropped_events_count: span.dropped_events_count,
        dropped_links_count: span.dropped_links_count,
        metadata: metadata.clone(),
    };
    Ok(NativeSpanDraft {
        trace_id: span.trace_id,
        span_id: span.span_id,
        parent_span_id: span.parent_span_id,
        name: span.name,
        start_time_unix_nano: span.start_time_unix_nano,
        end_time_unix_nano: span.end_time_unix_nano,
        attributes,
        kind: span.kind,
        flags: span.flags,
        details,
        has_entity_refs: metadata.has_entity_refs,
        estimated_bytes,
    })
}

fn validate_raw_span(
    span: &OtlpSpan,
    metadata: &SpanDetailMetadata,
    profile: &ValueLimitProfile,
) -> Result<(), TraceReceiveFailure> {
    check_text(&span.name, profile)?;
    check_text(&span.trace_state, profile)?;
    check_text(&metadata.resource_schema_url, profile)?;
    check_text(&metadata.scope_name, profile)?;
    check_text(&metadata.scope_version, profile)?;
    check_text(&metadata.scope_schema_url, profile)?;

    let detail_limit = usize::try_from(profile.effective_limits().request().records().value())
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    if span.events.len() > detail_limit || span.links.len() > detail_limit {
        return Err(TraceReceiveFailure::ValueLimitExceeded);
    }
    if let Some(status) = &span.status {
        check_text(&status.message, profile)?;
    }
    for event in &span.events {
        check_text(&event.name, profile)?;
        validate_detail_attribute_keys(&event.attributes, profile)?;
    }
    for link in &span.links {
        check_text(&link.trace_state, profile)?;
        validate_detail_attribute_keys(&link.attributes, profile)?;
    }
    Ok(())
}

fn validate_detail_attribute_keys(
    attributes: &[KeyValue],
    profile: &ValueLimitProfile,
) -> Result<(), TraceReceiveFailure> {
    let attribute_limit = usize::try_from(
        profile
            .effective_limits()
            .dynamic_value()
            .attributes_per_namespace()
            .value(),
    )
    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    if attributes.len() > attribute_limit {
        return Err(TraceReceiveFailure::ValueLimitExceeded);
    }
    for attribute in attributes {
        if attribute.key_strindex != 0 {
            return Err(TraceReceiveFailure::UnsupportedValue);
        }
        check_text(&attribute.key, profile)?;
    }
    Ok(())
}

fn check_text(value: &str, profile: &ValueLimitProfile) -> Result<(), TraceReceiveFailure> {
    let maximum = usize::try_from(
        profile
            .effective_limits()
            .dynamic_value()
            .key_path_bytes()
            .value(),
    )
    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    if value.len() > maximum {
        return Err(TraceReceiveFailure::ValueLimitExceeded);
    }
    Ok(())
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

pub(crate) fn native_kind(value: i32) -> Result<positron_signals::SpanKind, TraceReceiveFailure> {
    use opentelemetry_proto::tonic::trace::v1::span::SpanKind as OtlpSpanKind;
    use positron_signals::SpanKind;

    match OtlpSpanKind::try_from(value) {
        Ok(OtlpSpanKind::Unspecified) => Ok(SpanKind::Unspecified),
        Ok(OtlpSpanKind::Internal) => Ok(SpanKind::Internal),
        Ok(OtlpSpanKind::Server) => Ok(SpanKind::Server),
        Ok(OtlpSpanKind::Client) => Ok(SpanKind::Client),
        Ok(OtlpSpanKind::Producer) => Ok(SpanKind::Producer),
        Ok(OtlpSpanKind::Consumer) => Ok(SpanKind::Consumer),
        Err(_) => Err(TraceReceiveFailure::MalformedPayload),
    }
}

pub(crate) fn sampling_decision(flags: u32) -> positron_signals::SamplingDecision {
    use positron_signals::SamplingDecision;

    if flags == 0 {
        SamplingDecision::Unknown
    } else if flags & 1 == 1 {
        SamplingDecision::Sampled
    } else {
        SamplingDecision::NotSampled
    }
}

fn grouped_attributes(
    resource: &[KeyValue],
    scope: &[KeyValue],
    record: &[KeyValue],
    profile: &ValueLimitProfile,
) -> Result<Vec<NativePolicyAttribute>, TraceReceiveFailure> {
    let limits = profile.effective_limits();
    let attribute_limit =
        usize::try_from(limits.dynamic_value().attributes_per_namespace().value())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    let mut groups = BTreeMap::<(AttributeNamespace, String), Vec<CandidateAttributeValue>>::new();
    for (namespace, attributes) in [
        (AttributeNamespace::Resource, resource),
        (AttributeNamespace::InstrumentationScope, scope),
        (AttributeNamespace::Record, record),
    ] {
        if attributes.len() > attribute_limit {
            return Err(TraceReceiveFailure::ValueLimitExceeded);
        }
        for attribute in attributes {
            if attribute.key_strindex != 0 {
                return Err(TraceReceiveFailure::UnsupportedValue);
            }
            check_text(&attribute.key, profile)?;
            let value = attribute.value.clone().map_or_else(
                || Ok(CandidateAttributeValue::null()),
                |value| {
                    super::materialize::candidate_value(
                        value,
                        profile,
                        limits.dynamic_value().nesting_depth().value(),
                    )
                },
            )?;
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
