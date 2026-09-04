use super::*;

#[test]
fn lowered_aggregate_attribute_limit_counts_event_and_link_occurrences()
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
    let exact = OtlpTracesReceiver::with_value_limit_profile(profile_with_aggregate_attributes(2))
        .decode(AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            governor,
            request_with_detail_attributes().encode_to_vec(),
        )?)?;
    assert_eq!(exact.records().len(), 1);
    drop(exact);

    let over = OtlpTracesReceiver::with_value_limit_profile(profile_with_aggregate_attributes(1))
        .decode(AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        request_with_detail_attributes().encode_to_vec(),
    )?)?;
    assert!(over.records().is_empty());
    Ok(())
}

#[test]
fn lowered_encoded_record_limit_is_applied_after_policy() -> Result<(), Box<dyn Error>> {
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
    let request = request_with_attribute("encoded", "value");
    let body = request.encode_to_vec();
    let maximum = ValueLimitProfile::release_1_system_maximum();
    let baseline = OtlpTracesReceiver::with_value_limit_profile(maximum).decode(
        AuthenticatedOtlpTracesRequest::otlp_http(
            context,
            instance.resource_governor(),
            OtlpTracesRequestEncoding::Protobuf,
            body.clone(),
        )?,
    )?;
    let record = baseline.records().first().ok_or("baseline record")?;
    let encoded_bytes = TraceStore::canonical_encoded_record_bytes(&maximum, record)?;
    assert_eq!(encoded_bytes, 191);
    drop(baseline);

    let exact = OtlpTracesReceiver::with_value_limit_profile(profile_with_encoded_record_bytes(
        u32::try_from(encoded_bytes)?,
    ))
    .decode(AuthenticatedOtlpTracesRequest::otlp_http(
        context,
        instance.resource_governor(),
        OtlpTracesRequestEncoding::Protobuf,
        body.clone(),
    )?)?;
    assert_eq!(exact.records().len(), 1);
    drop(exact);

    let one_over = OtlpTracesReceiver::with_value_limit_profile(profile_with_encoded_record_bytes(
        u32::try_from(encoded_bytes.saturating_sub(1))?,
    ))
    .decode(AuthenticatedOtlpTracesRequest::otlp_http(
        context,
        instance.resource_governor(),
        OtlpTracesRequestEncoding::Protobuf,
        body,
    )?)?;
    assert!(one_over.records().is_empty());
    Ok(())
}
