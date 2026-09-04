use super::*;

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
    assert_eq!(transformed.records().len(), 1, "{transformed:?}");
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
    drop(http);
    drop(transformed);

    let maximum_transformed = OtlpTracesReceiver::new().decode_with_policy(
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            instance.resource_governor(),
            request.encode_to_vec(),
        )?,
        &policy,
    )?;
    let transformed_record = maximum_transformed
        .records()
        .first()
        .ok_or("maximum transformed record")?;
    let encoded_bytes = TraceStore::canonical_encoded_record_bytes(
        &ValueLimitProfile::release_1_system_maximum(),
        transformed_record,
    )?;
    assert_eq!(encoded_bytes, 198);
    drop(maximum_transformed);

    let exact = OtlpTracesReceiver::with_value_limit_profile(
        profile_with_encoded_and_individual_value_bytes(u32::try_from(encoded_bytes)?, 4),
    )
    .decode_with_policy(
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            instance.resource_governor(),
            request.encode_to_vec(),
        )?,
        &policy,
    )?;
    assert_eq!(exact.records().len(), 1);
    drop(exact);

    let one_under = OtlpTracesReceiver::with_value_limit_profile(
        profile_with_encoded_and_individual_value_bytes(u32::try_from(encoded_bytes - 1)?, 4),
    )
    .decode_with_policy(
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            instance.resource_governor(),
            request.encode_to_vec(),
        )?,
        &policy,
    )?;
    assert!(one_under.records().is_empty());
    drop(one_under);

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
