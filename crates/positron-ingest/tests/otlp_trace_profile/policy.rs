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
fn authenticated_reversed_span_with_explicit_zero_end_is_preserved() -> Result<(), Box<dyn Error>> {
    let roots = support::temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("missing ingest secret")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let request = explicit_zero_reversed_request();
    let batch =
        OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            instance.resource_governor(),
            request,
        )?)?;
    let observation = batch.records().first().ok_or("preserved observation")?;
    assert_eq!(observation.end_time().source_value(), Some(0));
    assert_eq!(
        observation.end_time().quality(),
        SourceTimeQuality::Contradictory
    );
    Ok(())
}

fn explicit_zero_reversed_request() -> Vec<u8> {
    let mut span = Vec::new();
    length_field(&mut span, 1, &[1; 16]);
    length_field(&mut span, 2, &[2; 8]);
    length_field(&mut span, 5, b"explicit-zero-end");
    fixed64_field(&mut span, 7, 10);
    fixed64_field(&mut span, 8, 0);

    let mut scope = Vec::new();
    length_field(&mut scope, 2, &span);
    let mut resource = Vec::new();
    length_field(&mut resource, 2, &scope);
    let mut request = Vec::new();
    length_field(&mut request, 1, &resource);
    request
}

fn length_field(output: &mut Vec<u8>, field: u32, value: &[u8]) {
    append_varint(output, u64::from((field << 3) | 2));
    append_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn fixed64_field(output: &mut Vec<u8>, field: u32, value: u64) {
    append_varint(output, u64::from((field << 3) | 1));
    output.extend_from_slice(&value.to_le_bytes());
}

fn append_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
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
    assert_eq!(
        value.marker_action(),
        Some(positron_domain::value::MarkerAction::Redacted)
    );
    assert_eq!(
        value.marker_original_kind(),
        Some(positron_domain::value::AttributeValueKind::String)
    );
    assert_eq!(value.as_str(), None);

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
            .is_some_and(|value| {
                value.marker_action() == Some(positron_domain::value::MarkerAction::Redacted)
                    && value.marker_original_kind()
                        == Some(positron_domain::value::AttributeValueKind::String)
                    && value.as_str().is_none()
            })
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
    // The redaction marker's v3 value frame is tag + action + original kind.
    // This fixture omits both span time scalars, so their source absence is
    // preserved without the eight-byte payloads used by explicit zeroes.
    assert_eq!(encoded_bytes, 184);
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
