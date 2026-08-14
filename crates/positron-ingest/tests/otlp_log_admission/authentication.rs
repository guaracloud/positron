use std::error::Error;
use std::io::Write;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{
    AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, OtlpLogsRequestEncoding, PolicyReceiver,
    ReceiveFailure,
};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::support::temporary_roots;

#[test]
fn bearer_authentication_precedes_malformed_gzip_and_protobuf() -> Result<(), Box<dyn Error>> {
    let roots = temporary_roots()?;
    let data = roots.data();
    let secrets = roots.secrets();
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;

    let rejected = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    );
    assert!(rejected.is_err(), "system administrator cannot ingest");

    let invalid_bearer = format!("pos_{}", "00".repeat(32));
    assert!(
        instance
            .attribute(
                PresentedCredential::parse(&invalid_bearer)?,
                RequestedIntent::Ingest,
                CompatibilityHints::none(),
            )
            .is_err(),
        "invalid bearer is rejected before receiver work",
    );
    assert!(
        instance
            .attribute(
                PresentedCredential::parse(claim.ingest_secret().expect("ingest credential"))?,
                RequestedIntent::Ingest,
                CompatibilityHints::external_tenant_alias("other-tenant")?,
            )
            .is_err(),
        "conflicting external alias is rejected before receiver work",
    );

    let authorized = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().expect("ingest credential"))?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let governor = instance.resource_governor();
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    let request =
        AuthenticatedOtlpLogsRequest::otlp_grpc_gzip_protobuf(authorized, governor, vec![1, 2, 3])?;
    assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(request)
            .expect_err("authenticated malformed gzip"),
        ReceiveFailure::MalformedCompression,
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[test]
fn production_route_constructors_stamp_exact_identity_independent_of_compression()
-> Result<(), Box<dyn Error>> {
    let roots = temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let governor = instance.resource_governor();
    let protobuf = Vec::new();
    let json = br#"{"resourceLogs":[]}"#.to_vec();

    assert_receiver(
        AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(context, governor, protobuf.clone())?,
        PolicyReceiver::OtlpGrpc,
    )?;
    assert_receiver(
        AuthenticatedOtlpLogsRequest::otlp_grpc_gzip_protobuf(context, governor, gzip(&protobuf)?)?,
        PolicyReceiver::OtlpGrpc,
    )?;
    for (encoding, body, expected) in [
        (
            OtlpLogsRequestEncoding::Protobuf,
            protobuf.clone(),
            PolicyReceiver::OtlpHttpProtobuf,
        ),
        (
            OtlpLogsRequestEncoding::Json,
            json.clone(),
            PolicyReceiver::OtlpHttpJson,
        ),
        (
            OtlpLogsRequestEncoding::GzipProtobuf,
            gzip(&protobuf)?,
            PolicyReceiver::OtlpHttpProtobuf,
        ),
        (
            OtlpLogsRequestEncoding::GzipJson,
            gzip(&json)?,
            PolicyReceiver::OtlpHttpJson,
        ),
    ] {
        assert_receiver(
            AuthenticatedOtlpLogsRequest::otlp_http(context, governor, encoding, body)?,
            expected,
        )?;
    }
    for (encoding, body, expected) in [
        (
            OtlpLogsRequestEncoding::Protobuf,
            protobuf.clone(),
            PolicyReceiver::LokiOtlpProtobuf,
        ),
        (
            OtlpLogsRequestEncoding::Json,
            json.clone(),
            PolicyReceiver::LokiOtlpJson,
        ),
        (
            OtlpLogsRequestEncoding::GzipProtobuf,
            gzip(&protobuf)?,
            PolicyReceiver::LokiOtlpProtobuf,
        ),
        (
            OtlpLogsRequestEncoding::GzipJson,
            gzip(&json)?,
            PolicyReceiver::LokiOtlpJson,
        ),
    ] {
        assert_receiver(
            AuthenticatedOtlpLogsRequest::loki_otlp(context, governor, encoding, body)?,
            expected,
        )?;
    }
    Ok(())
}

fn assert_receiver(
    request: AuthenticatedOtlpLogsRequest<'_>,
    expected: PolicyReceiver,
) -> Result<(), ReceiveFailure> {
    let batch = OtlpLogsReceiver::new().decode(request)?;
    assert_eq!(batch.receiver(), expected);
    Ok(())
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes)?;
    encoder.finish()
}
