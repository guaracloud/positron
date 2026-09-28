use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use positron_domain::identity::Scope;
use positron_domain::routing::SignalKind;
use positron_domain::time::UnixNanoseconds;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::{
    Catalog, CatalogObject, CatalogProposal, FormatEpoch, LifecycleClockFailure,
    LifecycleClockPolicy, LifecycleClockSource, RetentionTimeAuthority, SegmentScope,
    TransactionId,
};

use super::super::{BootstrapFailureCode, InitializationPlan, InstanceBootstrap};
use super::support::Roots;

struct UncertainInstance {
    roots: Roots,
    instance: super::super::InitializedInstance,
    wall: Arc<Mutex<UnixNanoseconds>>,
    administrator: positron_governance::AuthorizedContext,
    reader: positron_governance::AuthorizedContext,
    expected_catalog: positron_kernel::CatalogGenerationId,
    expected_anchor: UnixNanoseconds,
    administrator_secret: String,
}

struct MutableWallClock(Arc<Mutex<UnixNanoseconds>>);

impl LifecycleClockSource for MutableWallClock {
    fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
        self.0
            .lock()
            .map(|value| *value)
            .map_err(|_| LifecycleClockFailure::Unavailable)
    }
}

fn current_catalog(
    instance: &super::super::InitializedInstance,
) -> Result<positron_kernel::CatalogGenerationId, Box<dyn std::error::Error>> {
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    Ok(catalog.pin()?.identity())
}

fn uncertain_instance() -> Result<UncertainInstance, Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let mut instance = InstanceBootstrap::reopen(&paths)?;
    let administrator_secret = claim.secret().to_owned();
    let administrator = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let reader = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query credential")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let wall = Arc::new(Mutex::new(UnixNanoseconds::new(1_000)));
    let retention = RetentionTimeAuthority::establish_with_source(
        MutableWallClock(Arc::clone(&wall)),
        LifecycleClockPolicy::new(10)?,
    )?;
    instance.install_retention_time_for_test(retention)?;
    *wall.lock().expect("wall lock") = UnixNanoseconds::new(500);
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    instance.retention_time.governance_time_seconds(scope)?;
    let expected_anchor = instance.retention_time.status().safe_anchor();
    let expected_catalog = current_catalog(&instance)?;
    Ok(UncertainInstance {
        roots,
        instance,
        wall,
        administrator,
        reader,
        expected_catalog,
        expected_anchor,
        administrator_secret,
    })
}

fn install_v1_acceptance_receipt(
    instance: &super::super::InitializedInstance,
) -> Result<(), Box<dyn std::error::Error>> {
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let snapshot = catalog.pin()?;
    let mut objects = Vec::new();
    let mut replaced = false;
    for identity in snapshot.object_identities() {
        let bytes = snapshot.object(identity)?.ok_or("catalog object")?;
        if bytes.starts_with(b"POSLCR02") {
            let mut v1 = bytes.get(..128).ok_or("v2 receipt bounds")?.to_vec();
            v1[..8].copy_from_slice(b"POSLCR01");
            objects.push(CatalogObject::new(v1)?);
            replaced = true;
        } else {
            objects.push(CatalogObject::new(bytes.to_vec())?);
        }
    }
    if !replaced {
        return Err("missing v2 acceptance receipt".into());
    }
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0xae; 16])?,
            snapshot.format_epoch().unwrap_or(FormatEpoch::CATALOG_V1),
            objects,
        )?,
        None,
    )?;
    Ok(())
}

#[test]
fn system_administrator_accepts_only_the_observed_discontinuity()
-> Result<(), Box<dyn std::error::Error>> {
    let UncertainInstance {
        roots: _roots,
        instance,
        wall,
        administrator,
        expected_catalog,
        expected_anchor,
        ..
    } = uncertain_instance().map_err(|failure| format!("uncertain fixture: {failure:?}"))?;
    let update = instance.accept_lifecycle_clock_discontinuity(
        administrator,
        expected_catalog,
        expected_anchor,
        AdministrativeIdempotencyKey::new([0xa1; 16])?,
    )?;
    assert!(update.audit_position() > 0);
    assert_eq!(
        instance.retention_time.status().state(),
        positron_kernel::LifecycleClockState::Certain
    );

    // The accepted correction tolerates the observed backward step, but an
    // independent later forward jump remains a new discontinuity.
    *wall.lock().expect("wall lock") = UnixNanoseconds::new(2_000);
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    instance.retention_time.governance_time_seconds(scope)?;
    assert_eq!(
        instance.retention_time.status().state(),
        positron_kernel::LifecycleClockState::ClockUncertain
    );
    assert_eq!(
        instance.retention_time.security_time_seconds(),
        Err(LifecycleClockFailure::ClockUncertain)
    );
    Ok(())
}

#[test]
fn stale_discontinuity_precondition_never_publishes_an_acceptance()
-> Result<(), Box<dyn std::error::Error>> {
    let UncertainInstance {
        roots: _roots,
        instance,
        wall: _wall,
        administrator,
        expected_catalog,
        expected_anchor,
        ..
    } = uncertain_instance()?;
    let failure = instance
        .accept_lifecycle_clock_discontinuity(
            administrator,
            expected_catalog,
            UnixNanoseconds::new(expected_anchor.value().checked_add(1).expect("range")),
            AdministrativeIdempotencyKey::new([0xa2; 16])?,
        )
        .expect_err("stale safe anchor must be rejected");
    assert_eq!(
        failure.code(),
        BootstrapFailureCode::LifecycleClockAcceptanceInvalidDiscontinuity
    );
    assert_eq!(
        instance.retention_time.status().state(),
        positron_kernel::LifecycleClockState::ClockUncertain
    );
    assert_eq!(current_catalog(&instance)?, expected_catalog);
    Ok(())
}

#[test]
fn acknowledgement_lost_acceptance_retry_installs_one_durable_result()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_after};

    let UncertainInstance {
        roots: _roots,
        instance,
        administrator,
        expected_catalog,
        expected_anchor,
        ..
    } = uncertain_instance()?;
    let key = AdministrativeIdempotencyKey::new([0xa3; 16])?;
    let first = with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        0,
        || {
            instance.accept_lifecycle_clock_discontinuity(
                administrator,
                expected_catalog,
                expected_anchor,
                key,
            )
        },
    );
    assert!(
        first.is_err(),
        "lost acknowledgement must not install live certainty"
    );
    assert_eq!(
        instance.retention_time.status().state(),
        positron_kernel::LifecycleClockState::ClockUncertain
    );

    let replay = instance
        .accept_lifecycle_clock_discontinuity(administrator, expected_catalog, expected_anchor, key)
        .expect("same-key replay must resolve a durable acceptance");
    assert!(replay.audit_position() > 0);
    assert_eq!(
        instance.retention_time.status().state(),
        positron_kernel::LifecycleClockState::Certain
    );
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let acceptance_audits = catalog
        .governance_audit_records()?
        .iter()
        .filter_map(|record| positron_governance::GovernanceAuditEntry::decode(record).ok())
        .filter(|entry| entry.action() == "lifecycle-clock.discontinuity.accept")
        .count();
    assert_eq!(acceptance_audits, 1);
    Ok(())
}

#[test]
fn v1_receipt_without_its_retained_audit_fails_closed_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let UncertainInstance {
        roots,
        mut instance,
        administrator,
        expected_catalog,
        expected_anchor,
        administrator_secret,
        ..
    } = uncertain_instance().map_err(|failure| format!("uncertain fixture: {failure:?}"))?;
    let paths = roots.paths();
    let acceptance_key = AdministrativeIdempotencyKey::new([0xac; 16])?;
    let accepted = instance
        .accept_lifecycle_clock_discontinuity(
            administrator,
            expected_catalog,
            expected_anchor,
            acceptance_key,
        )
        .map_err(|failure| format!("initial acceptance: {failure:?}"))?;
    let retention_administrator = instance
        .attribute(
            PresentedCredential::parse(&administrator_secret)?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
        .map_err(|failure| format!("retention administrator attribution: {failure:?}"))?;
    instance.install_retention_time_for_test(RetentionTimeAuthority::establish_with_source(
        MutableWallClock(Arc::new(Mutex::new(UnixNanoseconds::new(1_000_000_000)))),
        LifecycleClockPolicy::new(10)?,
    )?)?;
    instance
        .update_system_audit_retention(
            retention_administrator,
            NonZeroU64::new(1).ok_or("audit retention limit")?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xad; 16])?,
        )
        .map_err(|failure| format!("audit reclamation: {failure:?}"))?;
    install_v1_acceptance_receipt(&instance)?;
    drop(instance);

    let reopened = InstanceBootstrap::reopen(&paths)
        .map_err(|failure| format!("reopen after audit reclamation: {failure:?}"))?;
    let current_administrator = reopened
        .attribute(
            PresentedCredential::parse(&administrator_secret)?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
        .map_err(|failure| format!("current administrator attribution: {failure:?}"))?;
    let failure = reopened
        .accept_lifecycle_clock_discontinuity(
            current_administrator,
            expected_catalog,
            expected_anchor,
            acceptance_key,
        )
        .expect_err("a v1 receipt without its retained authenticated audit must not replay");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    assert!(accepted.audit_position() > 0);
    Ok(())
}

#[test]
fn data_plane_context_cannot_accept_a_clock_discontinuity() -> Result<(), Box<dyn std::error::Error>>
{
    let UncertainInstance {
        roots: _roots,
        instance,
        reader,
        expected_catalog,
        expected_anchor,
        ..
    } = uncertain_instance()?;
    let failure = instance
        .accept_lifecycle_clock_discontinuity(
            reader,
            expected_catalog,
            expected_anchor,
            AdministrativeIdempotencyKey::new([0xa4; 16])?,
        )
        .expect_err("query authority cannot accept a system clock discontinuity");
    assert_eq!(
        failure.code(),
        BootstrapFailureCode::LifecycleClockAcceptanceUnauthorized
    );
    assert_eq!(
        instance.retention_time.status().state(),
        positron_kernel::LifecycleClockState::ClockUncertain
    );
    assert_eq!(current_catalog(&instance)?, expected_catalog);
    Ok(())
}

#[test]
fn uncertain_lifecycle_anchor_cannot_extend_expiring_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let mut instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let expiring = instance.create_api_key(
        administrator,
        Scope::Query,
        Some(900),
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xae; 16])?,
    )?;
    let expiring_secret = expiring
        .secret()
        .ok_or("expiring query credential")?
        .to_owned();
    let wall = Arc::new(Mutex::new(UnixNanoseconds::new(800_000_000_000)));
    instance.install_retention_time_for_test(RetentionTimeAuthority::establish_with_source(
        MutableWallClock(Arc::clone(&wall)),
        LifecycleClockPolicy::new(10)?,
    )?)?;
    *wall.lock().map_err(|_| "wall clock")? = UnixNanoseconds::new(1_000_000_000_000);
    assert!(
        instance
            .attribute(
                PresentedCredential::parse(&expiring_secret)?,
                RequestedIntent::Query,
                CompatibilityHints::none(),
            )
            .is_err(),
        "the observed security clock is past the credential expiry"
    );
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    assert_eq!(instance.retention_time.governance_time_seconds(scope)?, 800);
    assert_eq!(
        instance.retention_time.status().state(),
        positron_kernel::LifecycleClockState::ClockUncertain
    );
    assert_eq!(
        instance.retention_time.security_time_seconds(),
        Err(LifecycleClockFailure::ClockUncertain)
    );
    instance.attribute(
        PresentedCredential::parse(
            claim
                .query_secret()
                .ok_or("non-expiring query credential")?,
        )?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    Ok(())
}

#[test]
fn malformed_existing_clock_anchor_refuses_acceptance_without_audit()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{CatalogObject, CatalogProposal, FormatEpoch, TransactionId};

    let UncertainInstance {
        roots: _roots,
        instance,
        administrator,
        expected_catalog,
        expected_anchor,
        ..
    } = uncertain_instance()?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let malformed = CatalogObject::new(b"PLIFCLK1\x02\x00".to_vec())?;
    catalog.commit(
        expected_catalog,
        CatalogProposal::new(
            TransactionId::new([0xa5; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![malformed],
        )?,
        None,
    )?;
    let corrupt_catalog = catalog.pin()?.identity();
    let failure = instance
        .accept_lifecycle_clock_discontinuity(
            administrator,
            corrupt_catalog,
            expected_anchor,
            AdministrativeIdempotencyKey::new([0xa6; 16])?,
        )
        .expect_err("malformed durable anchor must fence acceptance");
    assert!(matches!(
        failure.code(),
        BootstrapFailureCode::CatalogUnavailable | BootstrapFailureCode::CorruptState
    ));
    assert_eq!(
        instance.retention_time.status().state(),
        positron_kernel::LifecycleClockState::ClockUncertain
    );
    let acceptance_audits = catalog
        .governance_audit_records()?
        .iter()
        .filter_map(|record| positron_governance::GovernanceAuditEntry::decode(record).ok())
        .filter(|entry| entry.action() == "lifecycle-clock.discontinuity.accept")
        .count();
    assert_eq!(acceptance_audits, 0);
    Ok(())
}

#[test]
fn stale_catalog_precondition_never_accepts_the_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let UncertainInstance {
        roots: _roots,
        instance,
        administrator,
        expected_catalog,
        expected_anchor,
        ..
    } = uncertain_instance()?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    catalog.commit(
        expected_catalog,
        positron_kernel::CatalogProposal::new(
            positron_kernel::TransactionId::new([0xa8; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            vec![positron_kernel::CatalogObject::new(vec![0xa8])?],
        )?,
        None,
    )?;
    let failure = instance
        .accept_lifecycle_clock_discontinuity(
            administrator,
            expected_catalog,
            expected_anchor,
            AdministrativeIdempotencyKey::new([0xa7; 16])?,
        )
        .expect_err("stale catalog generation must be rejected");
    assert!(matches!(
        failure.code(),
        BootstrapFailureCode::LifecycleClockAcceptanceStaleCatalog
            | BootstrapFailureCode::CatalogUnavailable
            | BootstrapFailureCode::LifecycleClockAcceptanceInvalidDiscontinuity
            | BootstrapFailureCode::CorruptState
    ));
    assert_eq!(
        instance.retention_time.status().state(),
        positron_kernel::LifecycleClockState::ClockUncertain
    );
    Ok(())
}

#[test]
fn v1_receipt_replays_only_with_its_retained_authenticated_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let UncertainInstance {
        roots: _roots,
        instance,
        wall: _wall,
        administrator,
        expected_catalog,
        expected_anchor,
        ..
    } = uncertain_instance()?;
    let key = AdministrativeIdempotencyKey::new([0xc1; 16])?;
    let accepted = instance
        .accept_lifecycle_clock_discontinuity(administrator, expected_catalog, expected_anchor, key)
        .map_err(|failure| format!("initial acceptance: {failure:?}"))?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let snapshot = catalog.pin()?;
    let record = catalog
        .governance_audit_records()?
        .into_iter()
        .find(|record| record.transaction().to_bytes() == key.to_bytes())
        .ok_or("acceptance audit")?;
    let audit = positron_governance::GovernanceAuditEntry::decode(&record)
        .map_err(|_| "typed acceptance audit")?;
    let entry = audit.as_lifecycle_clock_acceptance().ok_or("clock audit")?;
    let mut receipt = Vec::new();
    receipt.extend_from_slice(b"POSLCR01");
    receipt.extend_from_slice(&entry.idempotency_key().to_bytes());
    receipt.extend_from_slice(&entry.actor_id().to_bytes());
    receipt.extend_from_slice(&entry.expected_catalog());
    receipt.extend_from_slice(&entry.safe_anchor().value().to_be_bytes());
    receipt.extend_from_slice(&entry.observed_wall_clock().value().to_be_bytes());
    receipt.extend_from_slice(&entry.observed_offset_nanoseconds().to_be_bytes());
    receipt.extend_from_slice(&entry.request_digest());
    assert_eq!(receipt.len(), 128);
    let mut objects = Vec::new();
    for identity in snapshot.object_identities() {
        objects.push(CatalogObject::new(
            snapshot.object(identity)?.ok_or("object")?.to_vec(),
        )?);
    }
    objects.push(CatalogObject::new(receipt)?);
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0xb0; 16])?,
            snapshot.format_epoch().unwrap_or(FormatEpoch::CATALOG_V1),
            objects,
        )?,
        None,
    )?;
    let view = Catalog::read_current_view(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let identity = positron_governance::Identity::open(view.snapshot()).map_err(|_| "identity")?;
    let request = positron_governance::LifecycleClockAcceptanceRequest::new(
        administrator,
        expected_catalog,
        key,
    );
    let (replay, _) = positron_governance::LifecycleClockAcceptanceAdministration::replay_retained(
        &view,
        &identity,
        request,
        expected_anchor,
    )?
    .ok_or("retained v1 replay")?;
    assert_eq!(replay.audit_position(), accepted.audit_position());
    assert!(replay.audit_position() > 0);
    Ok(())
}
