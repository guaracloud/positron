use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{InitializationPlan, InstanceBootstrap};
use positron_domain::identity::Scope;
use positron_domain::identity::{TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CatalogFormatMigrationAdministration, CompatibilityHints,
    PresentedCredential, RequestedIntent, ResourceGeneration,
};
use positron_governance::{
    DurableOperationAdministration, DurableOperationFailure, DurableOperationRequest,
    DurableOperationStatus, DurableOperationTerminalError, Identity, IngestPolicyAdministration,
};
use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule};
use positron_kernel::Catalog;
use positron_kernel::FormatEpoch;
use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_after};
use positron_query::QueryCancellation;

use super::initialization::Roots;

#[test]
fn fresh_bootstrap_publishes_epoch_two_and_reopens() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(
        instance.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    let administrator = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;

    assert_eq!(administrator.scope(), Scope::SystemAdministration);
    drop(instance);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(
        reopened.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    assert!(
        reopened
            .attribute(
                PresentedCredential::parse(claim.secret())?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .is_ok()
    );
    Ok(())
}

#[test]
fn epoch_two_catalog_keeps_format_after_api_key_and_lifecycle_successors()
-> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        instance.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    instance.create_api_key(
        administrator()?,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe4; 16])?,
    )?;
    instance.transition_tenant_lifecycle(
        administrator()?,
        instance.default_tenant_id(),
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe5; 16])?,
    )?;
    assert_eq!(
        instance.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    drop(instance);
    assert_eq!(
        InstanceBootstrap::reopen(&paths)?.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    Ok(())
}

#[test]
fn epoch_two_catalog_keeps_format_after_quota_and_policy_successors() -> Result<(), Box<dyn Error>>
{
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        instance.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    instance.update_tenant_quota(
        administrator()?,
        instance.default_tenant_id(),
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe7; 16])?,
        1,
        [
            32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
        ],
    )?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let identity = Identity::open(&catalog.pin()?)?;
    let policy = IngestPolicyAdministration::open(&catalog, instance.default_tenant_id())?;
    policy.activate(
        &catalog,
        &identity,
        administrator()?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe8; 16])?,
        IngestPolicy::compile(
            2,
            vec![PolicyRule::new("v2", Vec::new(), PolicyAction::Accept)?],
        )?,
    )?;
    drop(catalog);
    assert_eq!(
        instance.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    drop(instance);
    assert_eq!(
        InstanceBootstrap::reopen(&paths)?.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    Ok(())
}

#[test]
fn epoch_two_prepared_tenant_creation_restarts_without_downgrade() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        instance.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let tenant = TenantId::from_bytes([0xea; 16])?;
    let key = AdministrativeIdempotencyKey::new([0xeb; 16])?;
    with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
        instance.create_tenant(
            administrator().expect("admin"),
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("v2-prepared").expect("slug"),
                "V2 prepared",
                2_592_000,
                1,
                [1; 11],
            ),
            key,
        )
    })
    .expect_err("pre-marker V2 creation must remain prepared");
    let manifest = roots
        .data
        .join("catalog/staging/ebebebebebebebebebebebebebebebeb/prepared.manifest");
    let staged = fs::read(&manifest)?;
    drop(instance);
    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(
        reopened.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    let changed = reopened.create_tenant(
        reopened.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("v2-prepared")?,
            "changed",
            2_592_000,
            1,
            [1; 11],
        ),
        key,
    );
    assert!(changed.is_err());
    assert_eq!(fs::read(&manifest)?, staged);
    let resumed = reopened.create_tenant(
        reopened.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("v2-prepared")?,
            "V2 prepared",
            2_592_000,
            1,
            [1; 11],
        ),
        key,
    )?;
    assert_eq!(resumed.tenant_id(), tenant);
    assert_eq!(
        reopened.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    Ok(())
}

#[test]
fn unauthorized_and_exact_replayed_migrations_do_not_close_data_admission()
-> Result<(), Box<dyn Error>> {
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let paths = fixture.paths()?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let unauthorized = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query credential")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let (ingest_closed_tx, ingest_closed_rx) = std::sync::mpsc::channel();
    let (query_closed_tx, query_closed_rx) = std::sync::mpsc::channel();
    instance.install_lifecycle_transition_observer(ingest_closed_tx)?;
    instance.install_lifecycle_query_transition_observer(query_closed_tx)?;
    let key = AdministrativeIdempotencyKey::new([0xed; 16])?;

    let unauthorized_failure = instance
        .migrate_catalog_to_epoch_two(unauthorized, key)
        .expect_err("query actor cannot migrate the Catalog");
    assert_eq!(
        unauthorized_failure.code(),
        crate::BootstrapFailureCode::ApiKeyUnauthorized
    );
    assert!(
        ingest_closed_rx.try_recv().is_err(),
        "unauthorized migration does not close ingest admission"
    );
    assert!(
        query_closed_rx.try_recv().is_err(),
        "unauthorized migration does not close query admission"
    );
    drop(
        instance
            .enter_ingest_finalization_for(instance.default_tenant_id())
            .expect("ingest remains admitted"),
    );
    drop(
        instance
            .enter_query_execution_for(instance.default_tenant_id(), QueryCancellation::new())
            .expect("query remains admitted"),
    );

    let administrator = || {
        instance.attribute(
            PresentedCredential::parse(claim.secret()).expect("administrator credential"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let first_administrator = administrator()?;
    let committed = instance.migrate_catalog_to_epoch_two(first_administrator, key)?;
    let (ingest_closed_tx, ingest_closed_rx) = std::sync::mpsc::channel();
    let (query_closed_tx, query_closed_rx) = std::sync::mpsc::channel();
    instance.install_lifecycle_transition_observer(ingest_closed_tx)?;
    instance.install_lifecycle_query_transition_observer(query_closed_tx)?;

    let replay_administrator = administrator()?;
    assert_eq!(
        instance.migrate_catalog_to_epoch_two(replay_administrator, key)?,
        committed,
        "exact replay resolves the committed migration"
    );
    assert!(
        ingest_closed_rx.try_recv().is_err(),
        "exact replay does not close fresh ingest admission"
    );
    assert!(
        query_closed_rx.try_recv().is_err(),
        "exact replay does not close fresh query admission"
    );
    drop(
        instance
            .enter_ingest_finalization_for(instance.default_tenant_id())
            .expect("ingest remains admitted after replay"),
    );
    drop(
        instance
            .enter_query_execution_for(instance.default_tenant_id(), QueryCancellation::new())
            .expect("query remains admitted after replay"),
    );
    Ok(())
}

#[test]
fn durable_format_migration_survives_restart_with_stable_terminal_operation()
-> Result<(), Box<dyn Error>> {
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let paths = fixture.paths()?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let key = AdministrativeIdempotencyKey::new([0xc4; 16])?;
    let operation = instance.migrate_catalog_to_epoch_two_as_operation(
        instance.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?,
        key,
    )?;
    assert_eq!(
        operation.status(),
        positron_governance::DurableOperationStatus::Succeeded
    );
    assert_eq!(operation.progress_percent(), 100);
    assert_eq!(
        operation.irreversible_boundary(),
        positron_governance::DurableOperationBoundary::CatalogGenerationPublished
    );
    assert!(
        !format!("{operation:?}").contains(claim.secret()),
        "durable operation inspection must never retain or expose an API-key secret"
    );
    drop(instance);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    let replay = reopened.migrate_catalog_to_epoch_two_as_operation(
        reopened.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?,
        key,
    )?;
    assert_eq!(replay.operation_id(), operation.operation_id());
    assert_eq!(
        replay.status(),
        positron_governance::DurableOperationStatus::Succeeded
    );
    Ok(())
}

#[test]
fn compatibility_migration_publishes_a_durable_operation_transition() -> Result<(), Box<dyn Error>>
{
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let paths = fixture.paths()?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let key = AdministrativeIdempotencyKey::new([0xca; 16])?;
    instance.migrate_catalog_to_epoch_two(
        instance.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?,
        key,
    )?;
    assert!(
        instance
            .governance_audit_for_test()?
            .iter()
            .any(|entry| entry.action() == "durable-operation.transition"),
        "the compatibility entry point must use the durable-operation authority"
    );
    Ok(())
}

#[test]
fn durable_operation_cancels_before_drain_and_rejects_a_changed_same_key_request()
-> Result<(), Box<dyn Error>> {
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let paths = fixture.paths()?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let actor = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let key = AdministrativeIdempotencyKey::new([0xc5; 16])?;
    let accepted_generation = catalog.pin()?.number();
    let request = DurableOperationRequest::catalog_format_migration(
        actor.principal_id(),
        key,
        instance.instance.to_bytes(),
        accepted_generation,
        17,
    )?;
    let accepted =
        DurableOperationAdministration::accept_catalog_format_migration(&catalog, actor, request)?;
    assert_eq!(
        DurableOperationAdministration::accept_catalog_format_migration(
            &catalog,
            actor,
            DurableOperationRequest::catalog_format_migration(
                actor.principal_id(),
                key,
                instance.instance.to_bytes(),
                accepted_generation.saturating_add(1),
                18,
            )?,
        )
        .expect_err("a changed target generation cannot reuse an accepted key"),
        DurableOperationFailure::IdempotencyConflict
    );
    let cancellation_key = AdministrativeIdempotencyKey::new([0xc4; 16])?;
    let cancelled = DurableOperationAdministration::cancel(
        &catalog,
        actor,
        accepted.operation_id(),
        cancellation_key,
        18,
    )?;
    assert_eq!(
        cancelled.status(),
        positron_governance::DurableOperationStatus::Cancelled
    );
    assert_eq!(
        cancelled.cancellation(),
        positron_governance::DurableOperationCancellation::Cancelled
    );
    assert_eq!(
        DurableOperationAdministration::cancel(
            &catalog,
            actor,
            accepted.operation_id(),
            cancellation_key,
            19,
        )?,
        cancelled,
        "a lost cancellation response retries the original durable outcome"
    );
    Ok(())
}

#[test]
fn durable_operation_persists_terminal_handler_rejection_and_runtime_accessors()
-> Result<(), Box<dyn Error>> {
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let paths = fixture.paths()?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let actor = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let request = DurableOperationRequest::catalog_format_migration(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([0xc7; 16])?,
        instance.instance.to_bytes(),
        catalog.pin()?.number(),
        17,
    )?;
    let accepted =
        DurableOperationAdministration::accept_catalog_format_migration(&catalog, actor, request)?;
    let running =
        DurableOperationAdministration::begin(&catalog, actor, accepted.operation_id(), 18)?;
    let publishing =
        DurableOperationAdministration::mark_drained(&catalog, actor, running.operation_id(), 19)?;
    assert_eq!(
        publishing.phase(),
        positron_governance::DurableOperationPhase::CatalogPublication,
        "after admission is drained, persisted status truthfully names the next handler boundary"
    );
    let failed = DurableOperationAdministration::fail_catalog_format_migration(
        &catalog,
        actor,
        publishing.operation_id(),
        20,
        DurableOperationTerminalError::HandlerRejected,
    )?;
    assert_eq!(failed.status(), DurableOperationStatus::Failed);
    assert_eq!(
        failed.terminal_error(),
        Some(DurableOperationTerminalError::HandlerRejected)
    );
    assert_eq!(
        failed.earliest_lookup_expiry_unix_seconds(),
        Some(2_592_020)
    );
    drop(catalog);

    assert_eq!(
        instance.get_durable_operation(actor, failed.operation_id())?,
        Some(failed),
        "authorized runtime inspection returns the persisted terminal error"
    );
    let audit = instance
        .governance_audit_for_test()?
        .into_iter()
        .find(|entry| {
            entry.action() == "durable-operation.transition" && entry.outcome() == "failed"
        })
        .ok_or("terminal durable-operation audit")?;
    let positron_governance::GovernanceAuditEntry::DurableOperation(audit) = audit else {
        return Err("wrong durable-operation audit type".into());
    };
    assert_eq!(audit.acting_principal(), Some(actor.principal_id()));
    assert_eq!(audit.applicable_tenant(), None);
    assert_eq!(audit.target(), failed.operation_id());
    assert_eq!(audit.request_id(), Some(request.idempotency_key()));
    assert_eq!(
        audit.accepted_generation(),
        Some(request.accepted_generation())
    );
    assert_eq!(
        failed.target_identity(),
        Some(instance.instance.to_bytes()),
        "operation status exposes the authoritative instance target, not its catalog generation"
    );
    assert_eq!(
        audit.progress_percent(),
        Some(publishing.progress_percent())
    );
    assert_eq!(
        instance.wait_for_durable_operation(actor, failed.operation_id())?,
        failed,
        "waiting a terminal operation does not fabricate a retry"
    );
    assert_eq!(
        instance
            .cancel_durable_operation(
                actor,
                failed.operation_id(),
                AdministrativeIdempotencyKey::new([0xc3; 16])?,
            )
            .expect_err("a terminal failure cannot be cancelled")
            .code(),
        crate::BootstrapFailureCode::DurableOperationCancellationUnavailable
    );
    Ok(())
}

#[test]
fn expired_operation_lookup_keeps_its_idempotency_binding_without_reopening_work()
-> Result<(), Box<dyn Error>> {
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let paths = fixture.paths()?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let actor = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let request = DurableOperationRequest::catalog_format_migration(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([0xc8; 16])?,
        instance.instance.to_bytes(),
        catalog.pin()?.number(),
        17,
    )?;
    let accepted =
        DurableOperationAdministration::accept_catalog_format_migration(&catalog, actor, request)?;
    let running =
        DurableOperationAdministration::begin(&catalog, actor, accepted.operation_id(), 18)?;
    DurableOperationAdministration::fail_catalog_format_migration(
        &catalog,
        actor,
        running.operation_id(),
        19,
        DurableOperationTerminalError::HandlerRejected,
    )?;

    let later = DurableOperationRequest::catalog_format_migration(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([0xc9; 16])?,
        instance.instance.to_bytes(),
        catalog.pin()?.number(),
        2_592_019,
    )?;
    DurableOperationAdministration::accept_catalog_format_migration(&catalog, actor, later)?;
    assert_eq!(
        DurableOperationAdministration::accept_catalog_format_migration(&catalog, actor, request)
            .expect_err("expired lookup remains bound to its original request"),
        DurableOperationFailure::CompletedLookupExpired
    );
    let changed = DurableOperationRequest::catalog_format_migration(
        actor.principal_id(),
        request.idempotency_key(),
        instance.instance.to_bytes(),
        request.accepted_generation().saturating_add(1),
        2_592_020,
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_catalog_format_migration(&catalog, actor, changed)
            .expect_err("a changed request cannot reuse an expired operation key"),
        DurableOperationFailure::IdempotencyConflict
    );
    Ok(())
}

#[test]
fn durable_operation_reattaches_a_persisted_running_checkpoint_after_restart()
-> Result<(), Box<dyn Error>> {
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let paths = fixture.paths()?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let actor = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let key = AdministrativeIdempotencyKey::new([0xc6; 16])?;
    let request = DurableOperationRequest::catalog_format_migration(
        actor.principal_id(),
        key,
        instance.instance.to_bytes(),
        catalog.pin()?.number(),
        17,
    )?;
    let accepted =
        DurableOperationAdministration::accept_catalog_format_migration(&catalog, actor, request)?;
    let running =
        DurableOperationAdministration::begin(&catalog, actor, accepted.operation_id(), 18)?;
    assert_eq!(
        running.status(),
        positron_governance::DurableOperationStatus::Running
    );
    drop(catalog);
    drop(instance);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    let completed = reopened.migrate_catalog_to_epoch_two_as_operation(
        reopened.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?,
        key,
    )?;
    assert_eq!(completed.operation_id(), accepted.operation_id());
    assert_eq!(
        completed.status(),
        positron_governance::DurableOperationStatus::Succeeded
    );
    assert_eq!(completed.progress_percent(), 100);
    Ok(())
}

#[test]
fn migration_rechecks_the_current_epoch_and_replays_a_concurrent_successor()
-> Result<(), Box<dyn Error>> {
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let paths = fixture.paths()?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let actor = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let key = AdministrativeIdempotencyKey::new([0xee; 16])?;
    let audit_before = instance.governance_audit_for_test()?.len();
    let (successor_tx, successor_rx) = std::sync::mpsc::channel();
    let successor_instance = Arc::clone(&instance);
    instance.install_catalog_migration_preflight_hook(Arc::new(move || {
        let secret = successor_instance
            .key
            .catalog_secret(successor_instance.instance)
            .expect("catalog secret");
        let catalog = Catalog::open(
            &successor_instance._authority,
            successor_instance.instance,
            secret,
        )
        .expect("catalog");
        let successor = CatalogFormatMigrationAdministration::migrate_to_epoch_two(
            &catalog,
            successor_instance.administrator,
            actor,
            key,
        )
        .expect("concurrent successor migration");
        let _ = successor_tx.send(successor);
    }))?;

    let migration = instance.migrate_catalog_to_epoch_two(actor, key)?;
    assert_eq!(
        migration,
        successor_rx.recv().expect("concurrent successor result"),
        "the second preflight resolves the successor's exact migration"
    );
    assert_eq!(
        instance.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2),
        "the successor remains the sole V2 publication"
    );
    assert_eq!(
        instance.governance_audit_for_test()?.len(),
        audit_before + 1,
        "revalidation does not publish a duplicate migration audit record"
    );
    Ok(())
}

struct LegacyFixtureRoots {
    root: PathBuf,
}

impl LegacyFixtureRoots {
    fn from_f9_fixture() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "positron-migration-drain-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let fixture = Self { root };
        let source = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy-f9-v1"
        ));
        for name in ["data", "secrets"] {
            copy_tree(&source.join(name), &fixture.root.join(name))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                fixture.root.join("secrets"),
                fs::Permissions::from_mode(0o700),
            )?;
            for name in ["bootstrap-claim.v1", "local-root-key.v1"] {
                fs::set_permissions(
                    fixture.root.join("secrets").join(name),
                    fs::Permissions::from_mode(0o600),
                )?;
            }
        }
        Ok(fixture)
    }

    fn paths(&self) -> Result<crate::BootstrapPaths, crate::BootstrapFailure> {
        crate::BootstrapPaths::new(
            &self.root.join("data"),
            &self.root.join("secrets"),
            positron_kernel::MountQualification::LocalHost,
        )
    }
}

fn copy_tree(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), std::io::Error> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &destination_path)?;
        } else if entry.file_type()?.is_file() {
            fs::copy(entry.path(), destination_path)?;
        } else {
            return Err(std::io::Error::other("unsupported legacy fixture entry"));
        }
    }
    Ok(())
}

impl Drop for LegacyFixtureRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
