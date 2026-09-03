use super::{AuthenticatedOtlpTracesRequest, OtlpTracesReceiver, TraceReceiveFailure};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::value::{
    ByteLimit, DynamicValueLimits, ValueLimitProfile, ValueLimitProfileCandidate, ValueLimitSet,
};
use prost::Message;

fn attribution() -> positron_domain::identity::TenantAttribution {
    positron_domain::identity::TenantAttribution::new(
        positron_domain::identity::PrincipalId::from_bytes([1; 16]).expect("principal"),
        positron_domain::identity::Scope::Ingest,
        positron_domain::identity::TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution")
}

fn decode(span: Span) -> Result<super::NativeSpanBatch<'static>, TraceReceiveFailure> {
    decode_with_profile(span, ValueLimitProfile::release_1_system_maximum())
}

fn decode_with_profile(
    span: Span,
    profile: ValueLimitProfile,
) -> Result<super::NativeSpanBatch<'static>, TraceReceiveFailure> {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![span],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    OtlpTracesReceiver::with_value_limit_profile(profile).decode(
        AuthenticatedOtlpTracesRequest::test_only_protobuf(attribution(), request.encode_to_vec()),
    )
}

fn tenant_profile_with_key_limit(key_path_bytes: u64) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    let dynamic = maximum.effective_limits().dynamic_value();
    let lowered = DynamicValueLimits::new(
        dynamic.individual_value_bytes(),
        dynamic.attributes_per_namespace(),
        ByteLimit::new(u32::try_from(key_path_bytes).expect("test key bound"))
            .expect("non-zero test key bound"),
        dynamic.nesting_depth(),
        dynamic.array_entries(),
        dynamic.key_value_list_entries(),
    );
    ValueLimitProfileCandidate::new(
        maximum.system_limits(),
        Some(ValueLimitSet::new(
            maximum.effective_limits().request(),
            positron_domain::value::RecordLimits::new(
                maximum.effective_limits().record().encoded_bytes(),
                ByteLimit::new(4).expect("non-zero test record bound"),
                maximum.effective_limits().record().log_body_bytes(),
            ),
            lowered,
        )),
    )
    .validate()
    .expect("tenant profile lowers the system ceiling")
}

fn valid_span() -> Span {
    Span {
        trace_id: vec![1; 16],
        span_id: vec![2; 8],
        name: "operation".to_owned(),
        start_time_unix_nano: 10,
        end_time_unix_nano: 20,
        ..Span::default()
    }
}

#[test]
fn detail_attributes_reject_indexed_event_and_link_values() {
    let mut event = valid_span();
    event.events.push(Event {
        name: "exception".to_owned(),
        attributes: vec![KeyValue {
            key: "indexed-event".to_owned(),
            key_strindex: 1,
            ..KeyValue::default()
        }],
        ..Event::default()
    });
    let result = decode(event).expect("invalid event is a per-span rejection");
    assert_eq!(result.records().len(), 0);
    assert_eq!(result.rejections(), [0, 1, 0]);

    let mut link = valid_span();
    link.links.push(Link {
        trace_id: vec![3; 16],
        span_id: vec![4; 8],
        attributes: vec![KeyValue {
            key: "indexed-link".to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValueStrindex(1)),
            }),
            ..KeyValue::default()
        }],
        ..Link::default()
    });
    let result = decode(link).expect("invalid link is a per-span rejection");
    assert_eq!(result.records().len(), 0);
    assert_eq!(result.rejections(), [0, 1, 0]);
}

#[test]
fn empty_event_names_are_malformed_instead_of_dropped() {
    let mut span = valid_span();
    span.events.push(Event::default());
    let result = decode(span).expect("invalid event is a per-span rejection");
    assert_eq!(result.records().len(), 0);
    assert_eq!(result.rejections(), [0, 1, 0]);
}

#[test]
fn lowered_tenant_profile_applies_to_event_detail_names() {
    let mut span = valid_span();
    span.name = "s".to_owned();
    span.events.push(Event {
        name: "12345".to_owned(),
        ..Event::default()
    });

    let result = decode_with_profile(span, tenant_profile_with_key_limit(65_536));
    let result = result.expect("deterministic per-span detail limit is a partial rejection");

    assert!(result.records().is_empty());
    assert_eq!(result.rejections(), [0, 0, 1]);
}
