use super::*;

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
    let request = request_with_event_names("1234", "12345");
    let encoded = request.encoded_len();
    let authenticated =
        AuthenticatedOtlpTracesRequest::decoded_otlp_grpc_after_transport_admission(
            context,
            request,
            OtlpGrpcTransportEvidence::prevalidated(encoded + 5, encoded),
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
    let encoded = request.encoded_len();
    let batch = OtlpTracesReceiver::with_value_limit_profile(profile).decode(
        AuthenticatedOtlpTracesRequest::decoded_otlp_grpc_after_transport_admission(
            context,
            request,
            OtlpGrpcTransportEvidence::prevalidated(encoded + 5, encoded),
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
fn lowered_decompressed_limit_is_rejected_at_decoded_grpc_transport() -> Result<(), Box<dyn Error>>
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
    let encoded = request.encoded_len();
    let failure = OtlpTracesReceiver::with_value_limit_profile(profile)
        .decode(
            AuthenticatedOtlpTracesRequest::decoded_otlp_grpc_after_transport_admission(
                context,
                request,
                OtlpGrpcTransportEvidence::prevalidated(encoded + 5, encoded),
                positron_ingest::reserve_trace_receiver_transport(
                    context,
                    instance.resource_governor(),
                )?,
            )?,
        )
        .expect_err("lowered decompressed transport bound");
    assert_eq!(failure, TraceReceiveFailure::TransportLimitExceeded);
    Ok(())
}

#[test]
fn lowered_http_compressed_limit_is_applied_before_structural_decode() -> Result<(), Box<dyn Error>>
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
    let body = vec![0_u8; 6];
    let profile = profile_with_compressed_bytes(5);
    let failure = OtlpTracesReceiver::with_value_limit_profile(profile)
        .decode(AuthenticatedOtlpTracesRequest::otlp_http(
            context,
            instance.resource_governor(),
            OtlpTracesRequestEncoding::Protobuf,
            body,
        )?)
        .expect_err("lowered compressed transport bound");
    assert_eq!(failure, TraceReceiveFailure::TransportLimitExceeded);
    Ok(())
}
