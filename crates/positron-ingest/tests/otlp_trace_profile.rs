use std::error::Error;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::span::Event;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::value::{
    ByteLimit, RecordLimits, ValueLimitProfile, ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{
    AuthenticatedOtlpTracesRequest, OtlpTracesReceiver, OtlpTracesRequestEncoding,
};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

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
