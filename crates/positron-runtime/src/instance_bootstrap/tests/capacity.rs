use std::sync::Arc;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::identity::{Scope, TenantId, TenantSlug};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration, TenantAdministration,
};
use positron_kernel::Catalog;
use prost::Message;

use super::super::{InitializationPlan, InstanceBootstrap, resources};
use super::support::Roots;
use crate::{BootstrapFailureCode, ServiceHandle};

#[test]
fn configured_three_tenant_capacity_serves_the_third_tenant_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize_with_max_registered_tenants(
        &paths,
        InitializationPlan::non_interactive(),
        3,
    )?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen_with_max_registered_tenants(&paths, 3)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let second = create_tenant(
        &initialized,
        system,
        [0x71; 16],
        "capacity-second",
        1,
        [0x81; 16],
    )?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let third = create_tenant(
        &initialized,
        system,
        [0x72; 16],
        "capacity-third",
        2,
        [0x82; 16],
    )?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let ingest = initialized.create_api_key_for_tenant(
        system,
        third,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x83; 16])?,
    )?;
    let ingest = ingest
        .secret()
        .ok_or("third tenant ingest credential")?
        .to_owned();
    drop(initialized);

    let reopened = Arc::new(InstanceBootstrap::reopen_with_max_registered_tenants(
        &paths, 3,
    )?);
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, log_request("third-tenant").encode_to_vec())?
            .accepted_records(),
        1
    );
    assert!(
        reopened
            .durable_identity()?
            .tenant_key_envelope(second)
            .is_ok()
    );
    Ok(())
}

#[test]
fn full_capacity_rejects_before_publication_and_lower_reopen_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize_with_max_registered_tenants(
        &paths,
        InitializationPlan::non_interactive(),
        2,
    )?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen_with_max_registered_tenants(&paths, 2)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let admitted = create_tenant(
        &initialized,
        system,
        [0x91; 16],
        "capacity-admitted",
        1,
        [0xa1; 16],
    )?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let rejected = initialized
        .create_tenant(
            system,
            TenantId::from_bytes([0x92; 16])?,
            TenantSlug::parse_canonical("capacity-rejected")?,
            "Capacity rejected",
            2_592_000,
            1,
            resources::initial_tenant_quota(),
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0xa2; 16])?,
        )
        .expect_err("a full configured governor must reject before publication");
    assert_eq!(rejected.code(), BootstrapFailureCode::ResourceUnavailable);

    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let registered = TenantAdministration::registered_tenant_ids(&catalog.pin()?)?;
    assert!(registered.contains(&admitted));
    assert!(!registered.contains(&TenantId::from_bytes([0x92; 16])?));
    drop(catalog);
    drop(initialized);

    let too_small = InstanceBootstrap::reopen_with_max_registered_tenants(&paths, 1)
        .expect_err("durable tenants above the configured slot capacity must not serve");
    assert_eq!(too_small.code(), BootstrapFailureCode::CorruptState);
    let recovered = InstanceBootstrap::reopen_with_max_registered_tenants(&paths, 2)?;
    assert!(
        recovered
            .durable_identity()?
            .tenant_key_envelope(admitted)
            .is_ok()
    );
    Ok(())
}

fn create_tenant(
    initialized: &super::super::InitializedInstance,
    system: positron_governance::AuthorizedContext,
    tenant_bytes: [u8; 16],
    slug: &str,
    expected_generation: u64,
    idempotency: [u8; 16],
) -> Result<TenantId, Box<dyn std::error::Error>> {
    let tenant = TenantId::from_bytes(tenant_bytes)?;
    let created = initialized
        .create_tenant(
            system,
            tenant,
            TenantSlug::parse_canonical(slug)?,
            "Configured capacity tenant",
            2_592_000,
            1,
            resources::initial_tenant_quota(),
            ResourceGeneration::new(expected_generation)?,
            AdministrativeIdempotencyKey::new(idempotency)?,
        )
        .map_err(|failure| format!("tenant creation: {failure:?}"))?;
    assert_eq!(created.tenant_id(), tenant);
    Ok(tenant)
}

fn log_request(body: &str) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(body.to_owned())),
                    }),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}
