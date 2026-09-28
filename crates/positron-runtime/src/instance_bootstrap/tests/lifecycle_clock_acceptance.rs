use std::sync::{Arc, Mutex};

use positron_domain::routing::SignalKind;
use positron_domain::time::UnixNanoseconds;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
};
use positron_kernel::{
    Catalog, LifecycleClockFailure, LifecycleClockPolicy, LifecycleClockSource,
    RetentionTimeAuthority, SegmentScope,
};

use super::super::{BootstrapFailureCode, InitializationPlan, InstanceBootstrap};
use super::support::Roots;

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

fn uncertain_instance() -> Result<
    (
        Roots,
        super::super::InitializedInstance,
        Arc<Mutex<UnixNanoseconds>>,
        positron_governance::AuthorizedContext,
        positron_governance::AuthorizedContext,
        positron_kernel::CatalogGenerationId,
        UnixNanoseconds,
    ),
    Box<dyn std::error::Error>,
> {
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
    Ok((
        roots,
        instance,
        wall,
        administrator,
        reader,
        expected_catalog,
        expected_anchor,
    ))
}

#[test]
fn system_administrator_accepts_only_the_observed_discontinuity()
-> Result<(), Box<dyn std::error::Error>> {
    let (_roots, instance, wall, administrator, _reader, expected_catalog, expected_anchor) =
        uncertain_instance()?;
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
    Ok(())
}

#[test]
fn stale_discontinuity_precondition_never_publishes_an_acceptance()
-> Result<(), Box<dyn std::error::Error>> {
    let (_roots, instance, _wall, administrator, _reader, expected_catalog, expected_anchor) =
        uncertain_instance()?;
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

    let (_roots, instance, _wall, administrator, _reader, expected_catalog, expected_anchor) =
        uncertain_instance()?;
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
fn data_plane_context_cannot_accept_a_clock_discontinuity() -> Result<(), Box<dyn std::error::Error>>
{
    let (_roots, instance, _wall, _administrator, reader, expected_catalog, expected_anchor) =
        uncertain_instance()?;
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
fn malformed_existing_clock_anchor_refuses_acceptance_without_audit()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{CatalogObject, CatalogProposal, FormatEpoch, TransactionId};

    let (_roots, instance, _wall, administrator, _reader, expected_catalog, expected_anchor) =
        uncertain_instance()?;
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
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
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
    let (_roots, instance, _wall, administrator, _reader, expected_catalog, expected_anchor) =
        uncertain_instance()?;
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
    ));
    assert_eq!(
        instance.retention_time.status().state(),
        positron_kernel::LifecycleClockState::ClockUncertain
    );
    Ok(())
}
