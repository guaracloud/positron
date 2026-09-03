use std::error::Error;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::trace::v1::span::Event;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::time::{SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    ByteLimit, CollectionLimit, DynamicValueLimits, NestingLimit, RecordLimits, ValueLimitProfile,
    ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{
    AuthenticatedOtlpTracesRequest, OtlpTracesReceiver, OtlpTracesRequestEncoding,
};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use prost::Message;

#[path = "otlp_trace_admission/support.rs"]
mod support;

#[test]
fn lowered_profile_has_exact_and_one_over_detail_outcomes_on_http_protojson()
-> Result<(), Box<dyn Error>> {
    let roots = support::temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let governor = instance.resource_governor();
    let profile = profile_with_decoded_bytes(8);
    let request = request_with_event_names("1234", "12345");
    let body = serde_json::to_vec(&request)?;
    let baseline = governor.inspect()?.outstanding_total();
    let authenticated = AuthenticatedOtlpTracesRequest::otlp_http(
        context,
        governor,
        OtlpTracesRequestEncoding::Json,
        body,
    )?;
    let batch = OtlpTracesReceiver::with_value_limit_profile(profile).decode(authenticated)?;
    assert_eq!(batch.records().len(), 1);
    assert_eq!(batch.records()[0].details().events()[0].name(), "1234");
    drop(batch);
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);
    Ok(())
}

#[test]
fn lowered_profile_has_exact_and_one_over_detail_outcomes_on_decoded_grpc()
-> Result<(), Box<dyn Error>> {
    let roots = support::temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let governor = instance.resource_governor();
    let profile = profile_with_decoded_bytes(8);
    let baseline = governor.inspect()?.outstanding_total();
    let capacity = positron_ingest::reserve_trace_receiver_transport(context, governor)?;
    let authenticated =
        AuthenticatedOtlpTracesRequest::decoded_otlp_grpc_after_transport_admission(
            context,
            request_with_event_names("1234", "12345"),
            capacity,
        )?;
    let batch = OtlpTracesReceiver::with_value_limit_profile(profile).decode(authenticated)?;
    assert_eq!(batch.records().len(), 1);
    assert_eq!(batch.records()[0].details().events()[0].name(), "1234");
    drop(batch);
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);
    Ok(())
}

#[test]
fn contradictory_span_times_are_preserved_with_an_invalid_end_quality() -> Result<(), Box<dyn Error>>
{
    let roots = support::temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![1; 16],
                    span_id: vec![2; 8],
                    name: "contradictory".to_owned(),
                    start_time_unix_nano: 20,
                    end_time_unix_nano: 10,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let governor = instance.resource_governor();
    let authenticated = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        request.encode_to_vec(),
    )?;
    let batch = OtlpTracesReceiver::new().decode(authenticated)?;
    let observation = batch.records().first().ok_or("preserved observation")?;
    assert_eq!(
        observation.start_time().instant(),
        Some(UnixNanoseconds::new(20))
    );
    assert_eq!(
        observation.end_time().instant(),
        Some(UnixNanoseconds::new(10))
    );
    assert_eq!(
        observation.start_time().quality(),
        SourceTimeQuality::Usable
    );
    assert_eq!(
        observation.end_time().quality(),
        SourceTimeQuality::Contradictory
    );
    Ok(())
}

#[test]
fn policy_transform_runs_before_lowered_value_limit() -> Result<(), Box<dyn Error>> {
    let roots = support::temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let governor = instance.resource_governor();
    let path = positron_policy::PolicyAttributePath::new(
        positron_domain::value::AttributeNamespace::Record,
        "secret",
    )?;
    let policy = positron_policy::IngestPolicy::compile(
        11,
        vec![positron_policy::PolicyRule::new(
            "redact-secret",
            vec![positron_policy::PolicyPredicate::attribute_exists(
                path.clone(),
            )],
            positron_policy::PolicyAction::Redact(positron_policy::PolicyTarget::attribute(path)),
        )?],
    )?;
    let request = request_with_attribute("secret", "12345");
    let profile = profile_with_individual_value_bytes(4);
    let transformed = OtlpTracesReceiver::with_value_limit_profile(profile).decode_with_policy(
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            governor,
            request.encode_to_vec(),
        )?,
        &policy,
    )?;
    let value = transformed.records()[0].attributes()[0]
        .occurrence(0)
        .ok_or("redacted occurrence")?;
    assert!(value.is_null());

    let http = OtlpTracesReceiver::with_value_limit_profile(profile).decode_with_policy(
        AuthenticatedOtlpTracesRequest::otlp_http(
            context,
            governor,
            OtlpTracesRequestEncoding::Json,
            serde_json::to_vec(&request)?,
        )?,
        &policy,
    )?;
    assert!(
        http.records()[0].attributes()[0]
            .occurrence(0)
            .is_some_and(|value| value.is_null())
    );

    let preserving = positron_policy::IngestPolicy::preserving(12)?;
    let unchanged = OtlpTracesReceiver::with_value_limit_profile(profile).decode_with_policy(
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            instance.resource_governor(),
            request.encode_to_vec(),
        )?,
        &preserving,
    )?;
    assert!(unchanged.records().is_empty());
    Ok(())
}

#[test]
fn lowered_record_limit_is_applied_after_policy_on_decoded_grpc() -> Result<(), Box<dyn Error>> {
    let roots = support::temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let profile = profile_with_record_limit(1);
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![
                    Span {
                        trace_id: vec![1; 16],
                        span_id: vec![2; 8],
                        name: "first".to_owned(),
                        ..Span::default()
                    },
                    Span {
                        trace_id: vec![3; 16],
                        span_id: vec![4; 8],
                        name: "second".to_owned(),
                        ..Span::default()
                    },
                ],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let batch = OtlpTracesReceiver::with_value_limit_profile(profile).decode(
        AuthenticatedOtlpTracesRequest::decoded_otlp_grpc_after_transport_admission(
            context,
            request,
            positron_ingest::reserve_trace_receiver_transport(
                context,
                instance.resource_governor(),
            )?,
        )?,
    )?;
    assert_eq!(batch.records().len(), 1);
    assert_eq!(batch.records()[0].name(), "first");
    Ok(())
}

#[test]
fn lowered_decompressed_limit_is_applied_after_policy_on_decoded_grpc() -> Result<(), Box<dyn Error>>
{
    let roots = support::temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let profile = profile_with_decompressed_bytes(5);
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![
                    Span {
                        trace_id: vec![1; 16],
                        span_id: vec![2; 8],
                        name: "first".to_owned(),
                        ..Span::default()
                    },
                    Span {
                        trace_id: vec![3; 16],
                        span_id: vec![4; 8],
                        name: "second".to_owned(),
                        ..Span::default()
                    },
                ],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let batch = OtlpTracesReceiver::with_value_limit_profile(profile).decode(
        AuthenticatedOtlpTracesRequest::decoded_otlp_grpc_after_transport_admission(
            context,
            request,
            positron_ingest::reserve_trace_receiver_transport(
                context,
                instance.resource_governor(),
            )?,
        )?,
    )?;
    assert_eq!(batch.records().len(), 1);
    assert_eq!(batch.records()[0].name(), "first");
    Ok(())
}

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
