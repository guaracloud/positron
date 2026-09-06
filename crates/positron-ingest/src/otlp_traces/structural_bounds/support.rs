use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;

pub(crate) const MAX_CONTAINERS: usize = 1_024;
pub(crate) const MAX_RECORDS: usize = 1_024;
pub(crate) const MAX_ATTRIBUTES: usize = 4_096;
pub(crate) const MAX_BYTES: usize = 1_048_576;

pub(crate) fn attribution() -> positron_domain::identity::TenantAttribution {
    positron_domain::identity::TenantAttribution::new(
        positron_domain::identity::PrincipalId::from_bytes([1; 16]).expect("principal"),
        positron_domain::identity::Scope::Ingest,
        positron_domain::identity::TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution")
}

pub(crate) fn request(resource_spans: Vec<ResourceSpans>) -> Vec<u8> {
    ExportTraceServiceRequest { resource_spans }.encode_to_vec()
}

pub(crate) fn span() -> Span {
    Span {
        trace_id: vec![1; 16],
        span_id: vec![2; 8],
        name: "span".to_owned(),
        ..Span::default()
    }
}

pub(crate) fn one_scope(spans: Vec<Span>) -> ResourceSpans {
    ResourceSpans {
        scope_spans: vec![ScopeSpans {
            spans,
            ..ScopeSpans::default()
        }],
        ..ResourceSpans::default()
    }
}

pub(crate) fn attribute(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(value),
        ..KeyValue::default()
    }
}

pub(crate) fn attributes(count: usize, prefix: &str) -> Vec<KeyValue> {
    (0..count)
        .map(|index| attribute(&format!("{prefix}-{index}"), AnyValue::default()))
        .collect()
}
