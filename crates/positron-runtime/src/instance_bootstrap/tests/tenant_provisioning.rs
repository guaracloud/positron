use positron_domain::identity::TenantSlug;
use positron_domain::routing::SignalKind;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_ingest::IngestPolicy;
use positron_kernel::{Catalog, ResourceAmounts, ResourceDimension, WorkClaim, WorkKind};

use super::super::{InitializationPlan, InitializedInstance, InstanceBootstrap};
use super::support::Roots;
use super::tenant_policy::tenant_administrator;
use crate::{BootstrapFailure, BootstrapFailureCode};

#[test]
fn generated_tenant_selection_refuses_entropy_and_exhausted_collisions_without_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let audit_before = initialized.governance_audit_for_test()?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let before = catalog.pin()?;
    let collision = InitializedInstance::select_unregistered_tenant_for_test(&catalog, || {
        Ok(initialized.tenant)
    })
    .expect_err("eight colliding candidates must be exhausted");
    assert_eq!(collision.code(), BootstrapFailureCode::ResourceUnavailable);
    let entropy = InitializedInstance::select_unregistered_tenant_for_test(&catalog, || {
        Err(BootstrapFailure::new(
            BootstrapFailureCode::EntropyUnavailable,
        ))
    })
    .expect_err("entropy failure must precede every publication");
    assert_eq!(entropy.code(), BootstrapFailureCode::EntropyUnavailable);
    assert_eq!(catalog.pin()?.identity(), before.identity());
    drop(catalog);
    assert_eq!(initialized.governance_audit_for_test()?, audit_before);
    Ok(())
}

#[test]
fn system_administrator_creates_a_second_tenant_with_live_admission_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let created = initialized.create_tenant_generated(
        system,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("second-tenant")?,
            "Second tenant",
            2_592_000,
            1,
            [1; 11],
        ),
        AdministrativeIdempotencyKey::new([0x92; 16])?,
    )?;
    let tenant = created.tenant_id();
    assert_ne!(tenant, initialized.tenant);
    assert_eq!(created.resource_generation().get(), 2);
    let replay = initialized.create_tenant_generated(
        system,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("second-tenant")?,
            "Second tenant",
            2_592_000,
            1,
            [1; 11],
        ),
        AdministrativeIdempotencyKey::new([0x92; 16])?,
    )?;
    assert_eq!(
        replay, created,
        "exact retry preserves its committed outcome"
    );
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let snapshot = catalog.pin()?;
    let mut record = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot.object(identity)?.ok_or("catalog object")?;
        // Tenant creation is the canonical writer for the profile-bearing
        // secondary record. POSTNR02 remains a legacy lifecycle successor;
        // newly created tenants are emitted as POSTNR03.
        if bytes.starts_with(b"POSTNR03") {
            record = Some(bytes.to_vec());
            break;
        }
    }
    let record = record.ok_or("tenant creation record")?;
    let envelope_at = record
        .windows(8)
        .position(|window| window == b"POSTKE01")
        .ok_or("provisioned tenant KEK envelope")?;
    let envelope = record
        .get(envelope_at..)
        .ok_or("tenant KEK envelope bounds")?
        .to_vec();
    let has_initial_policy = snapshot.object_identities().into_iter().any(|identity| {
        snapshot
            .object(identity)
            .ok()
            .flatten()
            .and_then(|bytes| {
                IngestPolicy::decode_activated_object(tenant, bytes)
                    .ok()
                    .flatten()
            })
            .is_some()
    });
    drop(snapshot);
    drop(catalog);
    assert!(
        has_initial_policy,
        "tenant creation publishes its preserving initial policy"
    );
    assert_ne!(created.audit_position(), 0);
    assert!(
        initialized
            .governance_audit_for_test()?
            .iter()
            .any(|entry| {
                entry.position() == created.audit_position() && entry.action() == "tenant.create"
            })
    );
    drop(initialized);
    let reopened = InstanceBootstrap::reopen(&paths)?;
    let replay_after_reopen = reopened.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("second-tenant")?,
            "Second tenant",
            2_592_000,
            1,
            [1; 11],
        ),
        AdministrativeIdempotencyKey::new([0x92; 16])?,
    )?;
    assert_eq!(replay_after_reopen, created);
    let default_tenant_administrator = tenant_administrator(&reopened, claim.secret(), [0x93; 16])?;
    reopened.update_tenant_quota(
        default_tenant_administrator,
        reopened.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x94; 16])?,
        1,
        [1; 11],
    )?;
    let replay_after_unrelated_mutation = reopened.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("second-tenant")?,
            "Second tenant",
            2_592_000,
            1,
            [1; 11],
        ),
        AdministrativeIdempotencyKey::new([0x92; 16])?,
    )?;
    assert_eq!(replay_after_unrelated_mutation, created);
    let conflict = reopened
        .create_tenant(
            system,
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("second-tenant")?,
                "Changed tenant name",
                2_592_000,
                1,
                [1; 11],
            ),
            AdministrativeIdempotencyKey::new([0x92; 16])?,
        )
        .expect_err("changed retry must not replace the committed tenant");
    assert_eq!(
        conflict.code(),
        BootstrapFailureCode::ApiKeyIdempotencyConflict
    );
    let _protection = reopened.key.segment_key_from_tenant_envelope(
        reopened.instance,
        positron_kernel::SegmentScope::new(tenant, SignalKind::Logs, reopened.logs_shard),
        &envelope,
    )?;
    let reservation = reopened._authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    drop(reservation);
    Ok(())
}
