use positron_domain::identity::{Scope, TenantId};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, GovernanceAuditEntry, Identity,
    IngestPolicyAdministration, PolicyAdministrationFailureCode, PresentedCredential,
    RequestedIntent, ResourceGeneration,
};
use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule};
use positron_kernel::{
    AuditIntent, Catalog, CatalogObject, CatalogProposal, CatalogPublicationFault, FormatEpoch,
    ResourceAmounts, ResourceDimension, TransactionId, WorkClaim, WorkKind,
    with_catalog_publication_fault_after,
};

use super::super::{InitializationPlan, InitializedInstance, InstanceBootstrap};
use super::support::Roots;
use crate::BootstrapFailureCode;

mod concurrency;
mod corruption;
mod live;

#[test]
fn tenant_administrator_can_activate_its_prospective_ingest_policy()
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
    let tenant_administrator = initialized.create_api_key(
        system,
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x71; 16])?,
    )?;
    let tenant_secret = tenant_administrator
        .secret()
        .ok_or("tenant-administration secret")?
        .to_owned();
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let identity = Identity::open(&catalog.pin()?)?;
    let actor = identity.attribute(
        &initialized.key,
        PresentedCredential::parse(&tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let administration = IngestPolicyAdministration::open(&catalog, initialized.tenant)?;
    let activation = administration.activate(
        &catalog,
        &identity,
        actor,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x72; 16])?,
        IngestPolicy::compile(
            2,
            vec![PolicyRule::new(
                "tenant-policy",
                Vec::new(),
                PolicyAction::Accept,
            )?],
        )?,
    )?;
    assert_eq!(activation.resource_generation().get(), 2);
    assert_eq!(
        administration.serving().pin()?.generation(),
        2,
        "activation affects only subsequently pinned policy snapshots"
    );
    Ok(())
}

#[test]
fn reopened_instance_applies_the_current_durable_quota_before_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let snapshot = catalog.pin()?;
    let (_, governance) = snapshot.governance_object()?;
    let mut objects = Vec::new();
    for object in snapshot.object_identities() {
        let bytes = snapshot.object(object)?.ok_or("catalog object")?;
        if !bytes.starts_with(b"POSGOV") {
            objects.push(CatalogObject::new(bytes.to_vec())?);
        }
    }
    objects.push(CatalogObject::new(governance.with_quota(2, 1, [1; 11])?)?);
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0x73; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    drop(catalog);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    let failure = reopened
        ._authority
        .governor()
        .reserve(WorkClaim::tenant(
            reopened.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)
        .expect_err("the persisted quota must limit admission after reopen");
    assert_eq!(
        failure.code(),
        positron_kernel::AdmissionFailureCode::TenantQuotaExceeded
    );
    Ok(())
}

#[test]
fn tenant_administrator_publishes_a_quota_that_immediately_limits_new_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x74; 16])?;
    let update = initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x75; 16])?,
        1,
        [1; 11],
    )?;
    assert_eq!(update.resource_generation().get(), 2);
    let replay = initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x75; 16])?,
        1,
        [1; 11],
    )?;
    assert_eq!(replay, update);
    let failure = initialized
        ._authority
        .governor()
        .reserve(WorkClaim::tenant(
            initialized.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)
        .expect_err("the committed quota must limit new admission");
    assert_eq!(
        failure.code(),
        positron_kernel::AdmissionFailureCode::TenantQuotaExceeded
    );
    let audit = initialized
        .governance_audit_for_test()?
        .into_iter()
        .find(|audit| audit.position() == update.audit_position())
        .ok_or("quota audit")?;
    assert_eq!(audit.action(), "tenant-quota.update");
    assert_eq!(audit.outcome(), "succeeded");
    let quota = audit.as_tenant_quota_update().ok_or("quota audit type")?;
    assert_eq!(quota.principal_id(), actor.principal_id());
    assert_eq!(quota.tenant_id(), initialized.tenant);
    assert_eq!(quota.expected_generation().get(), 1);
    assert_eq!(quota.generation().get(), 2);
    assert_eq!(quota.weight(), 1);
    assert_eq!(quota.resources(), [1; 11]);
    assert_eq!(quota.idempotency_key().to_bytes(), [0x75; 16]);
    assert_ne!(quota.request_digest(), [0; 32]);
    Ok(())
}

#[test]
fn quota_replay_returns_its_original_result_without_restoring_an_obsolete_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x76; 16])?;
    let first = initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x77; 16])?,
        1,
        [1; 11],
    )?;
    initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x78; 16])?,
        1,
        [3; 11],
    )?;
    let replay = initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x77; 16])?,
        1,
        [1; 11],
    )?;
    assert_eq!(replay, first);
    let reservation = initialized
        ._authority
        .governor()
        .reserve(WorkClaim::tenant(
            initialized.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)?;
    drop(reservation);
    Ok(())
}

#[test]
fn changed_quota_request_reusing_an_idempotency_key_is_a_typed_conflict()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x79; 16])?;
    let key = AdministrativeIdempotencyKey::new([0x7a; 16])?;
    initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        key,
        1,
        [2; 11],
    )?;
    let failure = initialized
        .update_tenant_quota(
            actor,
            initialized.tenant,
            ResourceGeneration::new(1)?,
            key,
            1,
            [3; 11],
        )
        .expect_err("changed request must not reuse an idempotency result");
    assert_eq!(
        failure.code(),
        BootstrapFailureCode::TenantQuotaIdempotencyConflict
    );
    Ok(())
}

#[test]
fn stale_quota_generation_returns_the_current_generation_without_quota_contents()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x7b; 16])?;
    initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x7c; 16])?,
        1,
        [2; 11],
    )?;
    let failure = initialized
        .update_tenant_quota(
            actor,
            initialized.tenant,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x7d; 16])?,
            1,
            [3; 11],
        )
        .expect_err("new requests must carry the current quota generation");
    assert_eq!(
        failure.code(),
        BootstrapFailureCode::TenantQuotaStaleGeneration
    );
    assert_eq!(
        failure
            .quota_generation_conflict()
            .map(ResourceGeneration::get),
        Some(2)
    );
    Ok(())
}

#[test]
fn quota_update_is_durable_across_restart_and_rejects_invalid_prepublication_input()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x7e; 16])?;
    let invalid = initialized
        .update_tenant_quota(
            actor,
            initialized.tenant,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x7f; 16])?,
            0,
            [1; 11],
        )
        .expect_err("invalid quota must not publish");
    assert_eq!(invalid.code(), BootstrapFailureCode::CatalogUnavailable);
    initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x80; 16])?,
        1,
        [1; 11],
    )?;
    drop(initialized);
    let reopened = InstanceBootstrap::reopen(&paths)?;
    let failure = reopened
        ._authority
        .governor()
        .reserve(WorkClaim::tenant(
            reopened.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)
        .expect_err("restart must reconstruct the published quota");
    assert_eq!(
        failure.code(),
        positron_kernel::AdmissionFailureCode::TenantQuotaExceeded
    );
    Ok(())
}

#[test]
fn quota_update_rejects_wrong_scope_and_tenant_without_publishing()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let ingest = initialized.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest key")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let wrong_scope = initialized
        .update_tenant_quota(
            ingest,
            initialized.tenant,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x81; 16])?,
            1,
            [1; 11],
        )
        .expect_err("ingest scope cannot administer a quota");
    assert_eq!(
        wrong_scope.code(),
        BootstrapFailureCode::TenantQuotaUnauthorized
    );
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let wrong_tenant = initialized
        .update_tenant_quota(
            system,
            TenantId::from_bytes([0x82; 16])?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x83; 16])?,
            1,
            [1; 11],
        )
        .expect_err("a system principal must still name an existing tenant");
    assert_eq!(
        wrong_tenant.code(),
        BootstrapFailureCode::TenantQuotaUnauthorized
    );
    Ok(())
}

#[test]
fn failed_quota_catalog_publication_preserves_the_durable_and_live_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x84; 16])?;
    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            initialized.update_tenant_quota(
                actor,
                initialized.tenant,
                ResourceGeneration::new(1).expect("known valid generation"),
                AdministrativeIdempotencyKey::new([0x85; 16]).expect("known valid key"),
                1,
                [1; 11],
            )
        })
        .expect_err("commit synchronization fault must reject quota publication");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let (_, governance) = catalog.pin()?.governance_object()?;
    assert_eq!(governance.quota_generation(), 1);
    let reservation = initialized
        ._authority
        .governor()
        .reserve(WorkClaim::tenant(
            initialized.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)?;
    drop(reservation);
    Ok(())
}

fn tenant_administrator(
    initialized: &InitializedInstance,
    secret: &str,
    key: [u8; 16],
) -> Result<positron_governance::AuthorizedContext, Box<dyn std::error::Error>> {
    let system = initialized.attribute(
        PresentedCredential::parse(secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant_key = initialized.create_api_key(
        system,
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new(key)?,
    )?;
    Ok(initialized.attribute(
        PresentedCredential::parse(tenant_key.secret().ok_or("tenant key")?)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?)
}

#[test]
fn catalog_activation_is_loaded_unchanged_after_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let invalid_generation = ResourceGeneration::new(0).expect_err("zero generation");
    assert_eq!(
        invalid_generation.code(),
        PolicyAdministrationFailureCode::InvalidInput
    );
    assert_eq!(
        invalid_generation.to_string(),
        "ingest policy administration failed"
    );
    assert_eq!(
        AdministrativeIdempotencyKey::new([0; 16])
            .expect_err("zero idempotency key")
            .code(),
        PolicyAdministrationFailureCode::InvalidInput,
    );
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let administrator = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let ingest = initialized.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let policy = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "catalog-accept",
            Vec::new(),
            PolicyAction::Accept,
        )?],
    )?;
    let first_digest = policy.digest();
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let administration = IngestPolicyAdministration::open(&catalog, initialized.tenant)?;
    assert_eq!(administration.serving().pin()?.generation(), 1,);
    assert_eq!(
        administration
            .activate(
                &catalog,
                &initialized.identity,
                ingest,
                ResourceGeneration::new(1)?,
                AdministrativeIdempotencyKey::new([0x91; 16])?,
                policy.clone(),
            )
            .expect_err("ingest principal cannot administer policy")
            .code(),
        PolicyAdministrationFailureCode::Unauthorized,
    );
    assert_eq!(
        administration
            .activate(
                &catalog,
                &initialized.identity,
                administrator,
                ResourceGeneration::new(1)?,
                AdministrativeIdempotencyKey::new([0x90; 16])?,
                IngestPolicy::preserving(3)?,
            )
            .expect_err("generation must advance exactly once")
            .code(),
        PolicyAdministrationFailureCode::InvalidResourceGeneration,
    );
    let outcome = administration.activate(
        &catalog,
        &initialized.identity,
        administrator,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x92; 16])?,
        policy.clone(),
    )?;
    assert_eq!(outcome.resource_generation().get(), 2);
    assert_eq!(outcome.digest(), first_digest);
    let retry = administration.activate(
        &catalog,
        &initialized.identity,
        administrator,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x92; 16])?,
        policy.clone(),
    )?;
    assert_eq!(retry, outcome);
    let conflicting = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "catalog-reject",
            Vec::new(),
            PolicyAction::Reject,
        )?],
    )?;
    assert_eq!(
        administration
            .activate(
                &catalog,
                &initialized.identity,
                administrator,
                ResourceGeneration::new(1)?,
                AdministrativeIdempotencyKey::new([0x92; 16])?,
                conflicting,
            )
            .expect_err("changed retry must conflict")
            .code(),
        PolicyAdministrationFailureCode::IdempotencyConflict,
    );
    let stale = administration
        .activate(
            &catalog,
            &initialized.identity,
            administrator,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x93; 16])?,
            policy.clone(),
        )
        .expect_err("a new key cannot bypass the resource generation");
    assert_eq!(
        stale.code(),
        PolicyAdministrationFailureCode::StaleResourceGeneration
    );
    assert_eq!(
        stale.current_generation().map(ResourceGeneration::get),
        Some(2)
    );
    let activated = administration.serving().pin()?;
    assert_eq!(activated.digest(), first_digest);
    let audits = catalog.governance_audit_records()?;
    let record = audits
        .iter()
        .find(|record| record.position() == outcome.audit_position())
        .ok_or("activation audit disappeared")?;
    let audit = GovernanceAuditEntry::decode(record)?;
    assert_eq!(audit.position(), outcome.audit_position());
    assert_eq!(audit.action(), "ingest-policy.activate");
    assert_eq!(audit.outcome(), "succeeded");
    let activation = match audit {
        GovernanceAuditEntry::IngestPolicyActivation(entry) => entry,
        _ => return Err("wrong audit action".into()),
    };
    assert_eq!(activation.position(), outcome.audit_position());
    assert_eq!(activation.principal_id(), administrator.principal_id());
    assert_eq!(activation.tenant_id(), initialized.tenant);
    assert_eq!(activation.expected_generation().get(), 1);
    assert_eq!(activation.generation().get(), 2);
    assert_eq!(activation.idempotency_key().to_bytes(), [0x92; 16]);
    assert_eq!(activation.digest(), first_digest);
    assert_ne!(activation.request_digest(), [0; 32]);
    let activation_audit_intent = record.intent().to_vec();
    let successor = IngestPolicy::compile(
        3,
        vec![PolicyRule::new(
            "catalog-successor",
            Vec::new(),
            PolicyAction::Accept,
        )?],
    )?;
    let successor_digest = successor.digest();
    let successor_outcome = administration.activate(
        &catalog,
        &initialized.identity,
        administrator,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x94; 16])?,
        successor,
    )?;
    assert_eq!(successor_outcome.resource_generation().get(), 3);
    assert_eq!(administration.serving().pin()?.digest(), successor_digest,);
    drop(audits);
    drop(claim);
    drop(catalog);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)
        .map_err(|failure| format!("bootstrap reopen: {:?}", failure.code()))?;
    let reopened_policy = reopened.ingest_policy.serving().pin()?;
    assert_eq!(reopened_policy.generation(), 3);
    assert_eq!(reopened_policy.digest(), successor_digest);

    let catalog = Catalog::open(
        &reopened._authority,
        reopened.instance,
        reopened.key.catalog_secret(reopened.instance)?,
    )?;
    let current = catalog.pin()?;
    let mut objects = Vec::new();
    for identity in current.object_identities() {
        let bytes = current
            .object(identity)?
            .ok_or("catalog object disappeared")?;
        objects.push(CatalogObject::new(bytes.to_vec())?);
    }
    let mismatched = catalog.commit(
        current.identity(),
        CatalogProposal::new(
            TransactionId::new([0x95; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        Some(AuditIntent::new(activation_audit_intent)?),
    )?;
    assert!(
        GovernanceAuditEntry::decode(
            mismatched
                .governance_audit_record()
                .ok_or("mismatched audit disappeared")?
        )
        .is_err()
    );
    Ok(())
}
