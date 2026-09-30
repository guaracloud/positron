use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;
use std::sync::Arc;

use positron_domain::identity::{Scope, TenantId, TenantSlug};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, ListenerTransportAuditRequest,
    ListenerTransportRole, PresentedCredential, RequestedIntent, ResourceGeneration,
};
use positron_kernel::{
    CatalogObject, CatalogProposal, CatalogPublicationFault, FormatEpoch, MaintenanceCoordinator,
    MaintenanceFailure, MaintenanceTask, MaintenanceTaskClass, MaintenanceTaskId,
    MaintenanceTaskPhase, TransactionId, with_catalog_publication_fault_after,
    with_catalog_publication_fault_sequence_after,
};

use super::super::ServiceHandle;
use super::schema_maintenance::{Fixture, open_catalog};
use crate::BootstrapFailureCode;

#[test]
fn retention_accepts_distinct_role_receipts_from_one_joint_plaintext_transaction()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    let mut objects = snapshot
        .object_identities()
        .map(|identity| {
            snapshot
                .object(identity)?
                .ok_or_else(|| "catalog object".into())
                .and_then(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let transaction = TransactionId::new([0x77; 16])?;
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8_080);
    let audit_position = snapshot.governance_audit_frontier() + 1;
    for role in [ListenerTransportRole::Api, ListenerTransportRole::OtlpHttp] {
        objects.push(
            positron_governance::plaintext_listener_transport_receipt_object(
                initialized.instance_id(),
                transaction,
                ListenerTransportAuditRequest::configuration_file_listener(role, target),
                audit_position,
            )?,
        );
    }
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)?,
        None,
    )?;
    drop((snapshot, catalog));

    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let update = initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(64).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x78; 16])?,
    )?;
    assert_eq!(update.policy_generation(), ResourceGeneration::new(2)?);
    Ok(())
}

#[test]
fn system_audit_retention_replays_an_immutable_receipt_after_successor_compaction_and_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let first_key = AdministrativeIdempotencyKey::new([0xd1; 16])?;
    let first = initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        first_key,
    )?;
    assert_eq!(first.policy_generation(), ResourceGeneration::new(2)?);
    assert_eq!(first.retained_record_limit().get(), 2);
    let audit = initialized.governance_audit_for_test()?;
    let typed = audit
        .iter()
        .find(|entry| entry.position() == first.audit_position())
        .and_then(positron_governance::GovernanceAuditEntry::as_system_audit_retention_update)
        .ok_or("typed system audit-retention evidence")?;
    assert_eq!(typed.actor_id(), initialized.system_administrator_id());
    assert_eq!(typed.expected_generation(), ResourceGeneration::new(1)?);
    assert_eq!(typed.generation(), first.policy_generation());
    assert_eq!(typed.retained_record_limit(), 2);
    assert!(typed.request_digest().iter().any(|byte| *byte != 0));
    let conflict = initialized
        .update_system_audit_retention(
            actor,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            first_key,
        )
        .expect_err("a changed request under A's key must conflict");
    assert_eq!(
        conflict.code(),
        BootstrapFailureCode::SystemAuditRetentionIdempotencyConflict
    );

    let successor = initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xd2; 16])?,
    )?;
    assert_eq!(successor.policy_generation(), ResourceGeneration::new(3)?);
    assert!(
        ServiceHandle::new(Arc::clone(&initialized))?.wake_maintenance_worker()?,
        "the runtime worker completes the successor's queued audit reclamation"
    );
    assert_eq!(initialized.governance_audit_for_test()?.len(), 1);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let actor = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let generation_before = reopened.catalog_generation();
    assert_eq!(
        reopened.update_system_audit_retention(
            actor,
            NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            first_key,
        )?,
        first,
        "the original durable receipt remains authoritative after a newer policy and compaction"
    );
    assert_eq!(reopened.catalog_generation(), generation_before);
    assert_eq!(reopened.governance_audit_for_test()?.len(), 1);
    Ok(())
}

#[test]
fn retained_governance_audit_history_verifies_after_reopen() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xda; 16])?,
    )?;
    assert!(ServiceHandle::new(Arc::clone(&initialized))?.wake_maintenance_worker()?);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let actor = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    reopened.verify_governance_audit_history(actor, None)?;
    let history = reopened.inspect_governance_audit_history(actor)?;
    assert!(history.retention_anchor_position().is_some());
    assert_eq!(
        history.earliest_visible_position(),
        history
            .records()
            .first()
            .ok_or("retained audit record")?
            .position()
    );
    Ok(())
}

#[test]
fn retained_audit_verifier_accepts_the_prior_trusted_anchor_and_rejects_a_foreign_checkpoint()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let checkpoint = initialized.publish_governance_audit_checkpoint(actor)?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xde; 16])?,
    )?;
    assert!(ServiceHandle::new(Arc::clone(&initialized))?.wake_maintenance_worker()?);
    drop(initialized);
    let reopened = fixture.reopen()?;
    let actor = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    reopened.verify_governance_audit_history(actor, Some(&checkpoint))?;

    let foreign = Fixture::new()?;
    let (foreign_instance, _, _, foreign_secret) = foreign.initialized_with_admin()?;
    let foreign_actor = foreign_instance.attribute(
        PresentedCredential::parse(&foreign_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let foreign_checkpoint = foreign_instance.publish_governance_audit_checkpoint(foreign_actor)?;
    let actor = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let failure = reopened
        .verify_governance_audit_history(actor, Some(&foreign_checkpoint))
        .expect_err("a trusted checkpoint from another instance is rollback evidence");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    Ok(())
}

#[test]
fn system_audit_contexts_are_identity_generation_bound_but_survive_unrelated_catalog_changes()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let stale = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.create_api_key(
        stale,
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe1; 16])?,
    )?;

    let rejected_reader = initialized
        .inspect_governance_audit_history(stale)
        .expect_err("a system context predating an identity successor cannot read audit history");
    assert_eq!(
        rejected_reader.code(),
        BootstrapFailureCode::ApiKeyUnauthorized
    );
    let rejected_retention = initialized
        .update_system_audit_retention(
            stale,
            NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xe2; 16])?,
        )
        .expect_err("a system context predating an identity successor cannot mutate retention");
    assert_eq!(
        rejected_retention.code(),
        BootstrapFailureCode::SystemAuditRetentionUnauthorized
    );

    let current = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        current,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe3; 16])?,
    )?;
    assert!(
        !initialized
            .inspect_governance_audit_history(current)?
            .records()
            .is_empty(),
        "a catalog-only audit-retention successor does not invalidate its identity context"
    );
    Ok(())
}

#[test]
fn tenant_audit_context_is_identity_generation_bound() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant_key = initialized.create_api_key_for_tenant(
        system,
        initialized.default_tenant_id(),
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe4; 16])?,
    )?;
    let tenant_secret = tenant_key.secret().ok_or("tenant administrator secret")?;
    let stale_tenant = initialized.attribute(
        PresentedCredential::parse(tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.create_api_key(
        system,
        Scope::Query,
        None,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xe5; 16])?,
    )?;

    let denied = initialized
        .inspect_governance_audit_history(stale_tenant)
        .expect_err("an active tenant credential still requires a current identity context");
    assert_eq!(denied.code(), BootstrapFailureCode::ApiKeyUnauthorized);
    let current_tenant = initialized.attribute(
        PresentedCredential::parse(tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    assert!(
        initialized
            .inspect_governance_audit_history(current_tenant)?
            .records()
            .iter()
            .all(|entry| entry.tenant_id() == Some(initialized.default_tenant_id()))
    );
    Ok(())
}

#[test]
fn public_audit_history_is_scoped_and_rejects_data_plane_contexts() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest_secret, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let foreign_tenant = TenantId::from_bytes([0xdc; 16])?;
    initialized.create_tenant(
        system,
        foreign_tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("audit-history-foreign")?,
            "Foreign audit tenant",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0xdc; 16])?,
    )?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;

    let tenant_key = initialized.create_api_key_for_tenant(
        system,
        initialized.default_tenant_id(),
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xdb; 16])?,
    )?;
    let tenant_secret = tenant_key.secret().ok_or("tenant administrator secret")?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let all = initialized.inspect_governance_audit_history(system)?;
    assert!(!all.records().is_empty());
    let tenant = initialized.attribute(
        PresentedCredential::parse(tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let scoped = initialized.inspect_governance_audit_history(tenant)?;
    assert!(
        scoped
            .records()
            .iter()
            .all(|entry| { entry.tenant_id() == Some(initialized.default_tenant_id()) })
    );
    assert!(scoped.records().len() <= all.records().len());

    initialized.revoke_api_key(
        system,
        tenant_key.principal_id(),
        initialized
            .list_api_keys(system)?
            .into_iter()
            .find(|key| key.principal_id() == tenant_key.principal_id())
            .map(positron_governance::ApiKeyDescriptor::generation)
            .ok_or("current tenant administrator descriptor")?,
        AdministrativeIdempotencyKey::new([0xdd; 16])?,
    )?;
    let revoked = initialized
        .inspect_governance_audit_history(tenant)
        .expect_err("a revoked administrative context cannot inspect audit history");
    assert_eq!(revoked.code(), BootstrapFailureCode::ApiKeyUnauthorized);

    let ingest = initialized.attribute(
        PresentedCredential::parse(&ingest_secret)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let denied = initialized
        .inspect_governance_audit_history(ingest)
        .expect_err("data-plane contexts cannot inspect governance audit history");
    assert_eq!(denied.code(), BootstrapFailureCode::ApiKeyUnauthorized);
    Ok(())
}

#[test]
fn system_audit_retention_rejects_tenant_data_plane_and_revoked_tenant_contexts()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest_secret, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let ingest = initialized.attribute(
        PresentedCredential::parse(&ingest_secret)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let denied = initialized
        .update_system_audit_retention(
            ingest,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xd3; 16])?,
        )
        .expect_err("data-plane attribution must not update system retention");
    assert_eq!(
        denied.code(),
        BootstrapFailureCode::SystemAuditRetentionUnauthorized
    );
    let system_generation = initialized
        .list_api_keys(system)?
        .into_iter()
        .find(|key| key.principal_id() == initialized.system_administrator_id())
        .map(positron_governance::ApiKeyDescriptor::generation)
        .ok_or("system administrator descriptor")?;

    let tenant_key = initialized.create_api_key(
        system,
        Scope::TenantAdministration,
        None,
        system_generation,
        AdministrativeIdempotencyKey::new([0xd4; 16])?,
    )?;
    let tenant_secret = tenant_key
        .secret()
        .ok_or("tenant administrator secret")?
        .to_owned();
    let tenant = initialized.attribute(
        PresentedCredential::parse(&tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let denied = initialized
        .update_system_audit_retention(
            tenant,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xd5; 16])?,
        )
        .expect_err("tenant administration must not update system retention");
    assert_eq!(
        denied.code(),
        BootstrapFailureCode::SystemAuditRetentionUnauthorized
    );

    initialized.revoke_api_key(
        system,
        tenant_key.principal_id(),
        initialized
            .list_api_keys(system)?
            .into_iter()
            .find(|key| key.principal_id() == tenant_key.principal_id())
            .map(positron_governance::ApiKeyDescriptor::generation)
            .ok_or("current tenant administrator descriptor")?,
        AdministrativeIdempotencyKey::new([0xd6; 16])?,
    )?;
    let denied = initialized
        .update_system_audit_retention(
            tenant,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xd7; 16])?,
        )
        .expect_err("a revoked tenant context must fail closed");
    assert_eq!(
        denied.code(),
        BootstrapFailureCode::SystemAuditRetentionUnauthorized
    );
    Ok(())
}

#[test]
fn committed_system_audit_retention_queues_reclamation_before_physical_mutation()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xd8; 16])?,
    )?;
    let key = AdministrativeIdempotencyKey::new([0xd9; 16])?;
    let retained_record_limit = NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?;
    let expected = ResourceGeneration::new(2)?;
    let audit_before = initialized.governance_audit_for_test()?.len();
    let update =
        with_catalog_publication_fault_after(CatalogPublicationFault::ReclaimAudit, 0, || {
            initialized.update_system_audit_retention(actor, retained_record_limit, expected, key)
        })
        .expect("the policy receipt and bounded maintenance request commit before unlinking");
    assert_eq!(update.policy_generation(), ResourceGeneration::new(3)?);
    assert_eq!(
        initialized.governance_audit_for_test()?.len(),
        audit_before + 1,
        "a policy update only makes physical audit reclamation eligible; its worker has not run"
    );
    Ok(())
}

#[test]
fn runtime_worker_physically_reclaims_a_receipt_bound_system_audit_prefix()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xf0; 16])?,
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xf1; 16])?,
    )?;
    let before = initialized.governance_audit_for_test()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;

    assert!(
        services.wake_maintenance_worker()?,
        "the installed coordinator handler dispatches the queued audit reclaimer"
    );
    let after = initialized.governance_audit_for_test()?;
    assert!(
        after.len() < before.len(),
        "the receipt-bound handler physically reclaims the authorized audit prefix"
    );
    Ok(())
}

#[test]
fn audit_reclaimer_cancellation_before_physical_work_preserves_the_prefix_and_terminalizes()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xf8; 16])?,
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xf9; 16])?,
    )?;
    let audit_before = initialized.governance_audit_for_test()?;
    let catalog = open_catalog(&initialized)?;
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    let execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &initialized._authority,
            1,
            false,
            Some(MaintenanceTaskClass::CatalogReclamation),
        )
        .expect("start receipt-bound audit reclaimer")
        .ok_or("queued receipt-bound audit reclaimer")?;
    let task = execution.task().identity();
    coordinator
        .cancel_and_persist(&catalog, task)
        .expect("durably request cancellation before physical work");

    catalog.complete_running_audit_retention_reclamation(&coordinator, &execution)?;
    assert_eq!(
        coordinator
            .status(task)
            .expect("cancelled audit-reclaimer status")
            .phase(),
        MaintenanceTaskPhase::Cancelled,
        "the exact dispatched descriptor terminalizes instead of remaining Running"
    );
    drop(catalog);
    assert_eq!(
        initialized.governance_audit_for_test()?,
        audit_before,
        "cancellation before the first unlink preserves every audit frame"
    );
    drop(execution);
    drop(coordinator);

    let subsequent_task = MaintenanceTask::new(
        MaintenanceTaskId::new([0xfa; 16]).expect("stable later-work identity"),
        MaintenanceTaskClass::SchemaPromotion,
    );
    let subsequent_catalog = open_catalog(&initialized)?;
    let subsequent_coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    subsequent_coordinator
        .submit_and_persist(&subsequent_catalog, subsequent_task.clone(), 2)
        .expect("submit later coordinator work");
    let subsequent_execution = subsequent_coordinator
        .start_next_with_reservation_and_persist_for_class(
            &subsequent_catalog,
            &initialized._authority,
            2,
            false,
            Some(MaintenanceTaskClass::SchemaPromotion),
        )
        .expect("start later coordinator work")
        .ok_or("later queued coordinator work")?;
    assert_eq!(
        subsequent_execution.task().identity(),
        subsequent_task.identity(),
        "dropping the cancelled execution releases its reservation for later exact work"
    );
    drop(subsequent_execution);
    drop(subsequent_coordinator);
    drop(subsequent_catalog);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let reopened_catalog = open_catalog(&reopened)?;
    let recovered = MaintenanceCoordinator::restore_from_catalog(&reopened_catalog)
        .expect("recover the durable cancellation outcome");
    assert_eq!(
        recovered
            .status(task)
            .expect("durably cancelled audit-reclaimer status")
            .phase(),
        MaintenanceTaskPhase::Cancelled,
        "recovery preserves the exact pre-physical cancellation terminal outcome"
    );
    drop(reopened_catalog);
    assert_eq!(reopened.governance_audit_for_test()?, audit_before);
    Ok(())
}

#[test]
fn audit_reclaimer_recovers_a_prephysical_cancellation_when_its_terminal_write_faults()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xfb; 16])?,
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xfc; 16])?,
    )?;
    let audit_before = initialized.governance_audit_for_test()?;
    let catalog = open_catalog(&initialized)?;
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    let execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &initialized._authority,
            1,
            false,
            Some(MaintenanceTaskClass::CatalogReclamation),
        )
        .expect("start receipt-bound audit reclaimer")
        .ok_or("queued receipt-bound audit reclaimer")?;
    let task = execution.task().identity();
    coordinator
        .cancel_and_persist(&catalog, task)
        .expect("durably request cancellation before physical work");

    let terminal_write =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            catalog.complete_running_audit_retention_reclamation(&coordinator, &execution)
        });
    assert!(
        terminal_write.is_err(),
        "the terminal cancellation write is unavailable or its acknowledgement is lost"
    );
    let recovered_live = coordinator
        .status(task)
        .expect("recovered cancellation status");
    assert_eq!(
        recovered_live.phase(),
        MaintenanceTaskPhase::Cancelled,
        "the same process adopts the exact durable cancellation outcome instead of stranding Running"
    );
    assert!(
        recovered_live.cancellation_requested(),
        "reconciliation preserves the durable cancellation flag rather than making a pre-physical retry eligible"
    );
    drop(catalog);
    assert_eq!(
        initialized.governance_audit_for_test()?,
        audit_before,
        "terminal-write recovery before physical work never reclaims an audit frame"
    );
    drop(execution);
    drop(coordinator);

    let successor = initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(3)?,
        AdministrativeIdempotencyKey::new([0xfd; 16])?,
    )?;
    assert_eq!(successor.policy_generation(), ResourceGeneration::new(4)?);
    assert!(
        ServiceHandle::new(Arc::clone(&initialized))?.wake_maintenance_worker()?,
        "a recovered pre-physical cancellation permits the next authorized audit-reclamation receipt"
    );
    assert!(
        initialized.governance_audit_for_test()?.len() < audit_before.len(),
        "the successor's receipt-bound handler reclaims its authorized prefix"
    );
    drop(initialized);

    let reopened = fixture.reopen()?;
    let reopened_catalog = open_catalog(&reopened)?;
    let recovered = MaintenanceCoordinator::restore_from_catalog(&reopened_catalog)
        .expect("recover the successor outcome");
    assert_eq!(
        recovered
            .status(task)
            .expect_err("the successor removes the recovered cancelled predecessor"),
        MaintenanceFailure::UnknownTask,
        "the successor atomically replaces only the recovered cancelled predecessor record"
    );
    drop(reopened_catalog);
    assert!(reopened.governance_audit_for_test()?.len() < audit_before.len());
    Ok(())
}

#[test]
fn audit_reclaimer_requeues_after_a_post_unlink_fault_and_finishes_on_same_process_retry()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xf2; 16])?,
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xf3; 16])?,
    )?;
    let before = initialized.governance_audit_for_test()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;

    let interrupted =
        with_catalog_publication_fault_after(CatalogPublicationFault::ReclaimAudit, 1, || {
            services.wake_maintenance_worker()
        });
    assert!(
        interrupted.is_err(),
        "the second exact unlink faults after one physical deletion"
    );
    let after_interruption = initialized.governance_audit_for_test()?;
    assert!(
        after_interruption.len() < before.len(),
        "the fault fixture must observe its claimed post-unlink physical mutation"
    );
    assert!(
        services.wake_maintenance_worker()?,
        "the same coordinator retries the exact durable descriptor instead of stranding it Running"
    );
    assert_eq!(initialized.governance_audit_for_test()?.len(), 1);
    Ok(())
}

#[test]
fn audit_reclaimer_recovers_a_directory_sync_fault_after_unlink_across_restart()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xf4; 16])?,
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xf5; 16])?,
    )?;
    let before = initialized.governance_audit_for_test()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let interrupted = with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeReclaimedAuditDirectory,
        0,
        || services.wake_maintenance_worker(),
    );
    assert!(
        interrupted.is_err(),
        "the directory sync faults after exact frame unlinks"
    );
    assert!(
        initialized.governance_audit_for_test()?.len() < before.len(),
        "the fixture observes its post-unlink physical mutation"
    );
    drop((services, initialized));

    let reopened = fixture.reopen()?;
    assert!(
        ServiceHandle::new(Arc::clone(&reopened))?.wake_maintenance_worker()?,
        "restart restores and completes the exact queued receipt-bound descriptor"
    );
    assert_eq!(reopened.governance_audit_for_test()?.len(), 1);
    Ok(())
}

#[test]
fn audit_reclaimer_recovers_same_process_when_terminal_and_requeue_task_records_both_fault_after_unlink()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xf6; 16])?,
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xf7; 16])?,
    )?;
    let task = {
        let records = initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .durable_records()
            .map_err(|_| "durable audit-reclaimer record")?;
        let record = records
            .first()
            .ok_or("queued audit-reclaimer record")?
            .as_bytes();
        let bytes: [u8; 16] = record
            .get(8..24)
            .ok_or("encoded task identity")?
            .try_into()
            .map_err(|_| "task identity length")?;
        MaintenanceTaskId::new(bytes).expect("encoded audit-reclaimer task identity")
    };
    let before = initialized.governance_audit_for_test()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let interrupted = with_catalog_publication_fault_sequence_after(
        &[
            (CatalogPublicationFault::SynchronizeCommit, 1),
            (CatalogPublicationFault::SynchronizeCommit, 0),
            (CatalogPublicationFault::SynchronizeCommit, 0),
        ],
        || services.wake_maintenance_worker(),
    );
    assert!(
        interrupted.is_err(),
        "terminal and durable requeue task-record writes both fault"
    );
    assert!(
        initialized.governance_audit_for_test()?.len() < before.len(),
        "the fixture reaches physical reclamation before terminal-record failure"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .status(task)
            .map_err(|_| "post-failure task status")?
            .phase(),
        MaintenanceTaskPhase::Queued,
        "the ambiguous terminal and requeue writes reconcile the live descriptor before retry"
    );
    assert!(
        services.wake_maintenance_worker()?,
        "the same coordinator reconciles the exact queued descriptor instead of leaving it Running"
    );
    assert_eq!(initialized.governance_audit_for_test()?.len(), 1);
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .status(task)
            .map_err(|_| "same-process terminal task status")?
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    drop((services, initialized));

    let reopened = fixture.reopen()?;
    assert_eq!(reopened.governance_audit_for_test()?.len(), 1);
    Ok(())
}

#[test]
fn system_audit_retention_successor_replaces_the_queued_reclaimer_authority()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xb1; 16])?,
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xb2; 16])?,
    )?;
    let predecessor = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?
        .durable_records()
        .expect("predecessor durable records");
    assert_eq!(
        predecessor.len(),
        1,
        "one initial audit reclaimer is queued"
    );

    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(3)?,
        AdministrativeIdempotencyKey::new([0xb3; 16])?,
    )?;

    let successor = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?
        .durable_records()
        .expect("successor durable records");
    assert_eq!(
        successor.len(),
        1,
        "a newer signed anchor owns exactly one queued Catalog-reclamation authority"
    );
    assert_ne!(
        successor, predecessor,
        "the successor replaces the predecessor PMTC record instead of accumulating it"
    );
    Ok(())
}

#[test]
fn system_audit_retention_refuses_a_successor_while_its_reclaimer_is_running()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xb4; 16])?,
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xb5; 16])?,
    )?;
    let catalog = open_catalog(&initialized)?;
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    let execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &initialized._authority,
            1,
            false,
            Some(MaintenanceTaskClass::CatalogReclamation),
        )
        .expect("start queued system audit reclaimer")
        .ok_or("queued system audit reclaimer starts")?;
    let reclaimer = execution.task().identity();
    let predecessor_records = coordinator
        .durable_records()
        .expect("running predecessor durable record");
    assert_eq!(
        coordinator
            .status(reclaimer)
            .expect("running reclaimer status")
            .phase(),
        MaintenanceTaskPhase::Running
    );
    drop(coordinator);
    drop(catalog);
    let generation_before = initialized.catalog_generation();

    let failure = initialized
        .update_system_audit_retention(
            actor,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(3)?,
            AdministrativeIdempotencyKey::new([0xb6; 16])?,
        )
        .expect_err("a running predecessor must reject a policy successor");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(initialized.catalog_generation(), generation_before);
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    assert_eq!(
        coordinator
            .status(reclaimer)
            .expect("preserved reclaimer status")
            .phase(),
        MaintenanceTaskPhase::Running,
        "the refused successor keeps the sole predecessor and its capability live"
    );
    assert_eq!(
        coordinator
            .durable_records()
            .expect("preserved predecessor durable record"),
        predecessor_records,
        "the unchanged Catalog generation retains the predecessor's exact anchor-bound capability"
    );
    drop(execution);
    Ok(())
}

#[test]
fn lost_system_audit_retention_ack_replays_only_its_exact_queued_reclaimer()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xb7; 16])?,
    )?;
    let running = MaintenanceTask::new(
        MaintenanceTaskId::new([0xb8; 16]).expect("stable running identity"),
        MaintenanceTaskClass::SchemaPromotion,
    );
    let paused = MaintenanceTask::new(
        MaintenanceTaskId::new([0xb9; 16]).expect("stable paused identity"),
        MaintenanceTaskClass::SchemaPromotion,
    );
    let running_id = running.identity();
    let paused_id = paused.identity();
    let catalog = open_catalog(&initialized)?;
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    coordinator
        .submit_and_persist(&catalog, running, 1)
        .expect("submit unrelated running task");
    coordinator
        .submit_and_persist(&catalog, paused, 1)
        .expect("submit unrelated paused task");
    coordinator
        .pause_and_persist(&catalog, paused_id, 1, 100, 1)
        .expect("pause unrelated task");
    let running_execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &initialized._authority,
            1,
            false,
            Some(MaintenanceTaskClass::SchemaPromotion),
        )
        .expect("start unrelated task")
        .ok_or("unrelated task starts")?;
    assert_eq!(running_execution.task().identity(), running_id);
    coordinator
        .cancel_and_persist(&catalog, running_id)
        .expect("request cancellation for the live unrelated task");
    let running_before = coordinator
        .status(running_id)
        .expect("running task status before replay");
    let paused_before = coordinator
        .status(paused_id)
        .expect("paused task status before replay");
    let records_before = coordinator
        .durable_records()
        .expect("durable task records before replay");
    let record_identities_before = records_before
        .iter()
        .map(|record| maintenance_task_record_identity(record.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let running_record_before = records_before
        .iter()
        .find(|record| {
            maintenance_task_record_identity(record.as_bytes())
                .is_ok_and(|identity| identity == running_id)
        })
        .ok_or("durable unrelated running task record")?
        .as_bytes()
        .to_vec();
    let paused_record_before = records_before
        .iter()
        .find(|record| {
            maintenance_task_record_identity(record.as_bytes())
                .is_ok_and(|identity| identity == paused_id)
        })
        .ok_or("durable unrelated paused task record")?
        .as_bytes()
        .to_vec();
    drop(coordinator);
    drop(catalog);

    let key = AdministrativeIdempotencyKey::new([0xba; 16])?;
    let lost_ack = with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        0,
        || {
            initialized.update_system_audit_retention(
                actor,
                NonZeroU64::new(1).expect("nonzero retained audit-record limit"),
                ResourceGeneration::new(2).expect("expected policy generation"),
                key,
            )
        },
    );
    assert!(
        lost_ack.is_err(),
        "the committed publication acknowledgement is lost"
    );
    let catalog = open_catalog(&initialized)?;
    let recovered_coordinator = MaintenanceCoordinator::restore_from_catalog(&catalog)
        .expect("typed recovered maintenance state");
    let recovered = recovered_coordinator
        .durable_records()
        .expect("recovered durable task records");
    let mut committed_reclaimers = Vec::new();
    for record in recovered {
        let identity = maintenance_task_record_identity(record.as_bytes())?;
        let status = recovered_coordinator
            .status(identity)
            .expect("typed recovered maintenance task");
        if !record_identities_before.contains(&identity)
            && status.task().class() == MaintenanceTaskClass::CatalogReclamation
            && status.phase() == MaintenanceTaskPhase::Queued
        {
            committed_reclaimers.push((identity, status));
        }
    }
    assert_eq!(
        committed_reclaimers.len(),
        1,
        "the acknowledged-lost publication contributes one new queued CatalogReclamation descriptor"
    );
    let (reclaimer_id, recovered_reclaimer) = committed_reclaimers
        .pop()
        .ok_or("exact committed reclaimer")?;
    drop(catalog);
    let live_records_before_replay = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?
        .durable_records()
        .expect("live durable records before replay");
    assert!(
        live_records_before_replay.iter().all(|record| {
            maintenance_task_record_identity(record.as_bytes())
                .is_ok_and(|identity| identity != reclaimer_id)
        }),
        "the post-commit acknowledgement loss leaves the exact durable reclaimer absent from memory"
    );

    let replay = initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        key,
    )?;
    assert_eq!(replay.policy_generation(), ResourceGeneration::new(3)?);
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    assert_eq!(
        coordinator
            .status(running_id)
            .expect("running task status after replay"),
        running_before
    );
    assert_eq!(
        coordinator
            .status(paused_id)
            .expect("paused task status after replay"),
        paused_before
    );
    assert_eq!(
        coordinator
            .status(reclaimer_id)
            .expect("replayed CatalogReclamation status"),
        recovered_reclaimer,
        "replay attaches the exact durable queued CatalogReclamation descriptor"
    );
    let records_after_replay = coordinator
        .durable_records()
        .expect("durable records after replay");
    assert_eq!(
        records_after_replay
            .iter()
            .find(|record| {
                maintenance_task_record_identity(record.as_bytes())
                    .is_ok_and(|identity| identity == running_id)
            })
            .ok_or("durable unrelated running task after replay")?
            .as_bytes(),
        running_record_before,
        "replay preserves the unrelated running cancellation record byte-for-byte"
    );
    assert_eq!(
        records_after_replay
            .iter()
            .find(|record| {
                maintenance_task_record_identity(record.as_bytes())
                    .is_ok_and(|identity| identity == paused_id)
            })
            .ok_or("durable unrelated paused task after replay")?
            .as_bytes(),
        paused_record_before,
        "replay preserves the unrelated paused record byte-for-byte"
    );
    drop(running_execution);
    Ok(())
}

#[test]
fn retention_rejects_a_mismatched_legacy_terminal_receipt_without_publishing()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe6; 16])?,
    )?;
    replace_system_retention_receipt_for_test(&initialized, false, [0xe7; 16])?;
    let generation_before = initialized.catalog_generation();
    let audit_before = initialized.governance_audit_for_test()?;

    let failure = initialized
        .update_system_audit_retention(
            actor,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0xe8; 16])?,
        )
        .expect_err("a mismatched retained terminal result cannot authorize audit pruning");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(initialized.catalog_generation(), generation_before);
    assert_eq!(initialized.governance_audit_for_test()?, audit_before);
    Ok(())
}

#[test]
fn retention_rejects_duplicate_terminal_receipts_without_publishing() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe9; 16])?,
    )?;
    replace_system_retention_receipt_for_test(&initialized, true, [0xea; 16])?;
    let generation_before = initialized.catalog_generation();
    let audit_before = initialized.governance_audit_for_test()?;

    let failure = initialized
        .update_system_audit_retention(
            actor,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0xeb; 16])?,
        )
        .expect_err("duplicate retained terminal results cannot authorize audit pruning");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(initialized.catalog_generation(), generation_before);
    assert_eq!(initialized.governance_audit_for_test()?, audit_before);
    Ok(())
}

#[test]
fn retention_capacity_refusal_does_not_publish_a_partial_successor() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    fill_catalog_to_object_limit_for_test(&initialized, [0xec; 16])?;
    let generation_before = initialized.catalog_generation();
    let audit_before = initialized.governance_audit_for_test()?;

    let failure = initialized
        .update_system_audit_retention(
            actor,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xed; 16])?,
        )
        .expect_err("a full catalog must refuse the entire retention successor before migration");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(initialized.catalog_generation(), generation_before);
    assert_eq!(initialized.governance_audit_for_test()?, audit_before);
    Ok(())
}

fn maintenance_task_record_identity(record: &[u8]) -> Result<MaintenanceTaskId, Box<dyn Error>> {
    let bytes: [u8; 16] = record
        .get(8..24)
        .ok_or("encoded maintenance task identity")?
        .try_into()
        .map_err(|_| "maintenance task identity length")?;
    Ok(MaintenanceTaskId::new(bytes).expect("encoded maintenance task identity"))
}

fn replace_system_retention_receipt_for_test(
    initialized: &crate::InitializedInstance,
    retain_original: bool,
    transaction: [u8; 16],
) -> Result<(), Box<dyn Error>> {
    let catalog = open_catalog(initialized)?;
    let basis = catalog.pin()?;
    let receipt = basis
        .object_identities()
        .find_map(|identity| {
            basis
                .object(identity)
                .ok()
                .flatten()
                .filter(|bytes| bytes.starts_with(b"POSARR01"))
                .map(|bytes| (identity, bytes.to_vec()))
        })
        .ok_or("system audit-retention receipt")?;
    let mut altered = receipt.1;
    let last = altered.last_mut().ok_or("nonempty terminal receipt")?;
    *last ^= 0x01;
    let mut objects = basis
        .object_identities()
        .filter(|identity| retain_original || *identity != receipt.0)
        .map(|identity| {
            basis
                .object(identity)?
                .ok_or_else(|| "catalog object".into())
                .and_then(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    objects.push(CatalogObject::new(altered)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}

fn fill_catalog_to_object_limit_for_test(
    initialized: &crate::InitializedInstance,
    transaction: [u8; 16],
) -> Result<(), Box<dyn Error>> {
    const CATALOG_OBJECT_LIMIT: usize = 1_024;

    let catalog = open_catalog(initialized)?;
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .map(|identity| {
            basis
                .object(identity)?
                .ok_or_else(|| "catalog object".into())
                .and_then(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    objects.try_reserve_exact(CATALOG_OBJECT_LIMIT.saturating_sub(objects.len()))?;
    while objects.len() < CATALOG_OBJECT_LIMIT {
        let mut bytes = b"retention-capacity-fixture\0".to_vec();
        bytes.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        objects.push(CatalogObject::new(bytes)?);
    }
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}
