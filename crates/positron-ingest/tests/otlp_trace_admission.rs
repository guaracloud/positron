use std::error::Error;
use std::io::Write;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{
    AuthenticatedOtlpTracesRequest, OtlpGrpcTransportEvidence, OtlpTracesReceiver,
    OtlpTracesRequestEncoding, PolicyReceiver, TraceReceiveFailure,
    reserve_trace_receiver_transport,
};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use prost::Message;

#[path = "otlp_trace_admission/support.rs"]
mod support;

#[test]
fn authenticated_trace_constructors_cover_wire_variants_and_decoded_handoff()
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
    let protobuf = ExportTraceServiceRequest::default().encode_to_vec();
    let json = serde_json::to_vec(&ExportTraceServiceRequest::default())?;

    let grpc =
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(context, governor, protobuf.clone())?;
    assert_eq!(
        OtlpTracesReceiver::new().decode(grpc)?.receiver(),
        PolicyReceiver::OtlpGrpc
    );
    let grpc_gzip = AuthenticatedOtlpTracesRequest::otlp_grpc_gzip_protobuf(
        context,
        governor,
        gzip(&protobuf)?,
    )?;
    assert_eq!(
        OtlpTracesReceiver::new().decode(grpc_gzip)?.receiver(),
        PolicyReceiver::OtlpGrpc
    );

    for (encoding, body, expected) in [
        (
            OtlpTracesRequestEncoding::Protobuf,
            protobuf.clone(),
            PolicyReceiver::OtlpHttpProtobuf,
        ),
        (
            OtlpTracesRequestEncoding::GzipProtobuf,
            gzip(&protobuf)?,
            PolicyReceiver::OtlpHttpProtobuf,
        ),
        (
            OtlpTracesRequestEncoding::Json,
            json.clone(),
            PolicyReceiver::OtlpHttpJson,
        ),
        (
            OtlpTracesRequestEncoding::GzipJson,
            gzip(&json)?,
            PolicyReceiver::OtlpHttpJson,
        ),
    ] {
        let request = AuthenticatedOtlpTracesRequest::otlp_http(context, governor, encoding, body)?;
        assert_eq!(
            OtlpTracesReceiver::new().decode(request)?.receiver(),
            expected
        );
    }

    let capacity = positron_ingest::reserve_trace_receiver_transport(context, governor)?;
    let decoded = AuthenticatedOtlpTracesRequest::decoded_otlp_grpc_after_transport_admission(
        context,
        ExportTraceServiceRequest::default(),
        OtlpGrpcTransportEvidence::prevalidated(5, 0),
        capacity,
    )?;
    assert_eq!(
        OtlpTracesReceiver::new().decode(decoded)?.receiver(),
        PolicyReceiver::OtlpGrpc
    );
    Ok(())
}

#[test]
fn authenticated_trace_admission_enforces_exact_transport_limit_before_reservation()
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
    let limit = usize::try_from(
        positron_domain::value::ValueLimitProfile::release_1_system_maximum()
            .system_limits()
            .request()
            .compressed_bytes()
            .value(),
    )?;
    let baseline = governor.inspect()?.outstanding_reservations();

    let accepted =
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(context, governor, vec![0; limit])?;
    drop(accepted);
    assert_eq!(governor.inspect()?.outstanding_reservations(), baseline);

    assert_eq!(
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            governor,
            vec![0; limit.saturating_add(1)],
        )
        .err(),
        Some(TraceReceiveFailure::TransportLimitExceeded),
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), baseline);
    Ok(())
}

#[test]
fn non_ingest_authority_is_rejected_before_trace_reservation() -> Result<(), Box<dyn Error>> {
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
    let query_context = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query credential")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let governor = instance.resource_governor();
    assert_eq!(
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(query_context, governor, Vec::new())
            .err(),
        Some(TraceReceiveFailure::AuthenticationRejected),
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[test]
fn malformed_trace_decode_releases_transport_reservation_without_drift()
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
    let baseline = governor.inspect()?.outstanding_reservations();
    let request =
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(context, governor, vec![0x08, 0x00])?;
    assert!(governor.inspect()?.outstanding_reservations() > baseline);
    assert_eq!(
        OtlpTracesReceiver::new()
            .decode(request)
            .expect_err("known-field wire mismatch must fail"),
        TraceReceiveFailure::MalformedPayload
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), baseline);
    Ok(())
}

#[test]
fn encoded_trace_transport_limits_are_format_specific_and_release_admission()
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
    let limit = usize::try_from(
        positron_domain::value::ValueLimitProfile::release_1_system_maximum()
            .system_limits()
            .request()
            .compressed_bytes()
            .value(),
    )?;
    let baseline = governor.inspect()?.outstanding_total();

    for encoding in [
        OtlpTracesRequestEncoding::GzipProtobuf,
        OtlpTracesRequestEncoding::Json,
        OtlpTracesRequestEncoding::GzipJson,
    ] {
        let capacity = reserve_trace_receiver_transport(context, governor)?;
        let request = AuthenticatedOtlpTracesRequest::encoded_otlp_http_after_transport_admission(
            context,
            encoding,
            vec![0; limit.saturating_add(1)],
            capacity,
        )?;
        assert_eq!(
            OtlpTracesReceiver::new().decode(request).err(),
            Some(TraceReceiveFailure::TransportLimitExceeded),
            "oversized {encoding:?} body must be rejected before decompression or decoding",
        );
        assert_eq!(governor.inspect()?.outstanding_total(), baseline);
    }
    Ok(())
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes)?;
    encoder.finish()
}
