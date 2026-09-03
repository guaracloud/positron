use super::*;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;

fn attribution() -> TenantAttribution {
    TenantAttribution::new(
        positron_domain::identity::PrincipalId::from_bytes([1; 16]).expect("principal"),
        positron_domain::identity::Scope::Ingest,
        positron_domain::identity::TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution")
}

#[test]
fn receiver_persists_only_provenance_minted_by_pinned_policy() {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "checkout".to_owned(),
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let policy = positron_policy::IngestPolicy::preserving(7).expect("preserving policy");
    let expected = policy.provenance();
    let batch = OtlpTracesReceiver::new()
        .decode_with_policy(
            AuthenticatedOtlpTracesRequest::test_only_protobuf(
                attribution(),
                request.encode_to_vec(),
            ),
            &policy,
        )
        .expect("trace payload should decode");
    assert_eq!(batch.records()[0].policy_provenance(), &expected);
}

#[test]
fn receiver_applies_pinned_generic_attribute_transform_before_native_validation() {
    let path = positron_policy::PolicyAttributePath::new(
        positron_domain::value::AttributeNamespace::Record,
        "secret",
    )
    .expect("path");
    let policy = positron_policy::IngestPolicy::compile(
        10,
        vec![
            positron_policy::PolicyRule::new(
                "redact-service",
                vec![positron_policy::PolicyPredicate::attribute_exists(
                    path.clone(),
                )],
                positron_policy::PolicyAction::Redact(positron_policy::PolicyTarget::attribute(
                    path,
                )),
            )
            .expect("rule"),
        ],
    )
    .expect("policy");
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "checkout".to_owned(),
                    attributes: vec![KeyValue {
                        key: "secret".to_owned(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("private".to_owned())),
                        }),
                        ..KeyValue::default()
                    }],
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let batch = OtlpTracesReceiver::new()
        .decode_with_policy(
            AuthenticatedOtlpTracesRequest::test_only_protobuf(
                attribution(),
                request.encode_to_vec(),
            ),
            &policy,
        )
        .expect("transformed trace should decode");
    let attribute = batch.records()[0]
        .attributes()
        .iter()
        .find(|attribute| attribute.key() == "secret")
        .expect("secret attribute");
    assert!(attribute.occurrence(0).is_some_and(|value| value.is_null()));
    assert_eq!(batch.records()[0].policy_provenance().generation(), 10);
}

#[test]
fn trace_policy_rejection_is_bounded_and_keeps_valid_siblings() {
    let path = positron_policy::PolicyAttributePath::new(
        positron_domain::value::AttributeNamespace::Resource,
        "service.name",
    )
    .expect("path");
    let policy = positron_policy::IngestPolicy::compile(
        7,
        vec![
            positron_policy::PolicyRule::new(
                "reject-service",
                vec![positron_policy::PolicyPredicate::attribute_exists(path)],
                positron_policy::PolicyAction::Reject,
            )
            .expect("rule"),
        ],
    )
    .expect("policy");
    let request = ExportTraceServiceRequest {
        resource_spans: vec![
            ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_owned(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("private".to_owned())),
                        }),
                        ..KeyValue::default()
                    }],
                    ..Resource::default()
                }),
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        trace_id: vec![0x11; 16],
                        span_id: vec![0x22; 8],
                        name: "rejected".to_owned(),
                        ..Span::default()
                    }],
                    ..ScopeSpans::default()
                }],
                ..ResourceSpans::default()
            },
            ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        trace_id: vec![0x33; 16],
                        span_id: vec![0x44; 8],
                        name: "accepted".to_owned(),
                        attributes: vec![KeyValue {
                            key: "other".to_owned(),
                            ..KeyValue::default()
                        }],
                        ..Span::default()
                    }],
                    ..ScopeSpans::default()
                }],
                ..ResourceSpans::default()
            },
        ],
    };
    let batch = OtlpTracesReceiver::new()
        .decode_with_policy(
            AuthenticatedOtlpTracesRequest::test_only_protobuf(
                attribution(),
                request.encode_to_vec(),
            ),
            &policy,
        )
        .expect("mixed trace policy result");
    assert_eq!(batch.records().len(), 1);
    assert_eq!(batch.rejections(), [1, 0, 0]);
    assert_eq!(batch.records()[0].name(), "accepted");
}

#[test]
fn all_trace_policy_rejections_leave_an_empty_durable_batch() {
    let policy = positron_policy::IngestPolicy::compile(
        8,
        vec![
            positron_policy::PolicyRule::new(
                "reject-all-traces",
                vec![positron_policy::PolicyPredicate::signal_store(
                    positron_domain::routing::SignalKind::Traces,
                )],
                positron_policy::PolicyAction::Reject,
            )
            .expect("rule"),
        ],
    )
    .expect("policy");
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "rejected".to_owned(),
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let batch = OtlpTracesReceiver::new()
        .decode_with_policy(
            AuthenticatedOtlpTracesRequest::test_only_protobuf(
                attribution(),
                request.encode_to_vec(),
            ),
            &policy,
        )
        .expect("all-rejected trace result");
    assert!(batch.records().is_empty());
    assert_eq!(batch.rejections(), [1, 0, 0]);
}

#[test]
fn policy_rejection_precedes_native_semantic_validation() {
    let policy = positron_policy::IngestPolicy::compile(
        9,
        vec![
            positron_policy::PolicyRule::new(
                "reject-trace",
                vec![positron_policy::PolicyPredicate::signal_store(
                    positron_domain::routing::SignalKind::Traces,
                )],
                positron_policy::PolicyAction::Reject,
            )
            .expect("rule"),
        ],
    )
    .expect("policy");
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    // This is intentionally invalid native input. Structural
                    // decode must still hand it to policy first.
                    trace_id: vec![0; 16],
                    span_id: vec![0; 8],
                    name: "rejected-before-native-validation".to_owned(),
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let batch = OtlpTracesReceiver::new()
        .decode_with_policy(
            AuthenticatedOtlpTracesRequest::test_only_protobuf(
                attribution(),
                request.encode_to_vec(),
            ),
            &policy,
        )
        .expect("policy rejection should be a per-span outcome");
    assert_eq!(batch.rejections(), [1, 0, 0]);
    assert!(batch.records().is_empty());
}
