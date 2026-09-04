use std::error::Error;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::time::{SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    ByteLimit, CollectionLimit, DynamicValueLimits, NestingLimit, RecordLimits, ValueLimitProfile,
    ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{
    AuthenticatedOtlpTracesRequest, OtlpGrpcTransportEvidence, OtlpTracesReceiver,
    OtlpTracesRequestEncoding, TraceReceiveFailure,
};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use positron_signals::TraceStore;
use prost::Message;

#[path = "../otlp_trace_admission/support.rs"]
mod support;

mod accounting;
mod policy;
mod transport;

fn request_with_event_names(exact_name: &str, over_name: &str) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![span_with_event(exact_name), span_with_event(over_name)],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
}

fn span_with_event(name: &str) -> Span {
    Span {
        trace_id: vec![1; 16],
        span_id: vec![name.len() as u8; 8],
        name: "span".to_owned(),
        events: vec![Event {
            name: name.to_owned(),
            ..Event::default()
        }],
        ..Span::default()
    }
}

fn request_with_attribute(key: &str, value: &str) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![1; 16],
                    span_id: vec![2; 8],
                    name: "profile-order".to_owned(),
                    attributes: vec![KeyValue {
                        key: key.to_owned(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(value.to_owned())),
                        }),
                        ..KeyValue::default()
                    }],
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
}

fn request_with_detail_attributes() -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![1; 16],
                    span_id: vec![2; 8],
                    name: "detail-attributes".to_owned(),
                    events: vec![Event {
                        name: "event".to_owned(),
                        attributes: vec![KeyValue {
                            key: "event.attribute".to_owned(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::BoolValue(true)),
                            }),
                            ..KeyValue::default()
                        }],
                        ..Event::default()
                    }],
                    links: vec![Link {
                        trace_id: vec![3; 16],
                        span_id: vec![4; 8],
                        attributes: vec![KeyValue {
                            key: "link.attribute".to_owned(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::BoolValue(true)),
                            }),
                            ..KeyValue::default()
                        }],
                        ..Link::default()
                    }],
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
}

fn profile_with_individual_value_bytes(bytes: u32) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    let dynamic = maximum.effective_limits().dynamic_value();
    let dynamic = DynamicValueLimits::new(
        ByteLimit::new(bytes).expect("valid value bound"),
        dynamic.attributes_per_namespace(),
        dynamic.key_path_bytes(),
        NestingLimit::new(dynamic.nesting_depth().value()).expect("valid depth"),
        CollectionLimit::new(dynamic.array_entries().value()).expect("valid arrays"),
        CollectionLimit::new(dynamic.key_value_list_entries().value()).expect("valid lists"),
    );
    ValueLimitProfileCandidate::new(
        maximum.system_limits(),
        Some(ValueLimitSet::new(
            maximum.effective_limits().request(),
            maximum.effective_limits().record(),
            dynamic,
        )),
    )
    .validate()
    .expect("lowered profile")
}

fn profile_with_record_limit(records: u32) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    ValueLimitProfileCandidate::new(
        maximum.system_limits(),
        Some(ValueLimitSet::new(
            positron_domain::value::RequestLimits::new(
                maximum.effective_limits().request().compressed_bytes(),
                maximum.effective_limits().request().decompressed_bytes(),
                CollectionLimit::new(records).expect("record bound"),
                maximum.effective_limits().request().aggregate_attributes(),
            ),
            maximum.effective_limits().record(),
            maximum.effective_limits().dynamic_value(),
        )),
    )
    .validate()
    .expect("lowered profile")
}

fn profile_with_aggregate_attributes(attributes: u32) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    ValueLimitProfileCandidate::new(
        maximum.system_limits(),
        Some(ValueLimitSet::new(
            positron_domain::value::RequestLimits::new(
                maximum.effective_limits().request().compressed_bytes(),
                maximum.effective_limits().request().decompressed_bytes(),
                maximum.effective_limits().request().records(),
                CollectionLimit::new(attributes).expect("aggregate attribute bound"),
            ),
            maximum.effective_limits().record(),
            maximum.effective_limits().dynamic_value(),
        )),
    )
    .validate()
    .expect("lowered profile")
}

fn profile_with_decompressed_bytes(bytes: u32) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    ValueLimitProfileCandidate::new(
        maximum.system_limits(),
        Some(ValueLimitSet::new(
            positron_domain::value::RequestLimits::new(
                maximum.effective_limits().request().compressed_bytes(),
                ByteLimit::new(bytes).expect("decompressed bound"),
                maximum.effective_limits().request().records(),
                maximum.effective_limits().request().aggregate_attributes(),
            ),
            maximum.effective_limits().record(),
            maximum.effective_limits().dynamic_value(),
        )),
    )
    .validate()
    .expect("lowered profile")
}

fn profile_with_compressed_bytes(bytes: u32) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    ValueLimitProfileCandidate::new(
        maximum.system_limits(),
        Some(ValueLimitSet::new(
            positron_domain::value::RequestLimits::new(
                ByteLimit::new(bytes).expect("compressed bound"),
                maximum.effective_limits().request().decompressed_bytes(),
                maximum.effective_limits().request().records(),
                maximum.effective_limits().request().aggregate_attributes(),
            ),
            maximum.effective_limits().record(),
            maximum.effective_limits().dynamic_value(),
        )),
    )
    .validate()
    .expect("lowered profile")
}

fn profile_with_encoded_record_bytes(bytes: u32) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    ValueLimitProfileCandidate::new(
        maximum.system_limits(),
        Some(ValueLimitSet::new(
            maximum.effective_limits().request(),
            RecordLimits::new(
                ByteLimit::new(bytes).expect("encoded record bound"),
                maximum.effective_limits().record().decoded_bytes(),
                maximum.effective_limits().record().log_body_bytes(),
            ),
            maximum.effective_limits().dynamic_value(),
        )),
    )
    .validate()
    .expect("lowered profile")
}

fn profile_with_encoded_and_individual_value_bytes(
    encoded_bytes: u32,
    individual_value_bytes: u32,
) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    let dynamic = maximum.effective_limits().dynamic_value();
    let dynamic = DynamicValueLimits::new(
        ByteLimit::new(individual_value_bytes).expect("value bound"),
        dynamic.attributes_per_namespace(),
        dynamic.key_path_bytes(),
        dynamic.nesting_depth(),
        dynamic.array_entries(),
        dynamic.key_value_list_entries(),
    );
    ValueLimitProfileCandidate::new(
        maximum.system_limits(),
        Some(ValueLimitSet::new(
            maximum.effective_limits().request(),
            RecordLimits::new(
                ByteLimit::new(encoded_bytes).expect("encoded record bound"),
                maximum.effective_limits().record().decoded_bytes(),
                maximum.effective_limits().record().log_body_bytes(),
            ),
            dynamic,
        )),
    )
    .validate()
    .expect("lowered profile")
}

fn profile_with_decoded_bytes(bytes: u32) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    ValueLimitProfileCandidate::new(
        maximum.system_limits(),
        Some(ValueLimitSet::new(
            maximum.effective_limits().request(),
            RecordLimits::new(
                maximum.effective_limits().record().encoded_bytes(),
                ByteLimit::new(bytes).expect("valid decoded bound"),
                maximum.effective_limits().record().log_body_bytes(),
            ),
            maximum.effective_limits().dynamic_value(),
        )),
    )
    .validate()
    .expect("lowered profile")
}
