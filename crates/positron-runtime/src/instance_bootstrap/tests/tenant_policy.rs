use positron_domain::identity::Scope;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, GovernanceAuditEntry, Identity,
    IngestPolicyAdministration, PolicyAdministrationFailureCode, PresentedCredential,
    RequestedIntent, ResourceGeneration,
};
use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule};
use positron_kernel::{
    AuditIntent, Catalog, CatalogObject, CatalogProposal, CatalogPublicationFault, FormatEpoch,
    TransactionId, with_catalog_publication_fault_after,
};
use std::num::NonZeroU64;

use super::super::{InitializationPlan, InitializedInstance, InstanceBootstrap};
use super::support::Roots;

#[path = "policy_activation/concurrency.rs"]
mod concurrency;
#[path = "policy_activation/corruption.rs"]
mod corruption;
#[path = "policy_activation/live.rs"]
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
fn policy_activation_replays_after_audit_reclamation_and_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant_key = initialized.create_api_key(
        system,
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe4; 16])?,
    )?;
    let tenant_secret = tenant_key
        .secret()
        .ok_or("tenant administration secret")?
        .to_owned();
    let actor = initialized.attribute(
        PresentedCredential::parse(&tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let identity = Identity::open(&catalog.pin()?)?;
    let administration = IngestPolicyAdministration::open(&catalog, initialized.tenant)?;
    let key = AdministrativeIdempotencyKey::new([0xe5; 16])?;
    let policy = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "retained-policy-replay",
            Vec::new(),
            PolicyAction::Accept,
        )?],
    )?;
    let activation = administration.activate(
        &catalog,
        &identity,
        actor,
        ResourceGeneration::new(1)?,
        key,
        policy.clone(),
    )?;
    drop(catalog);
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        system,
        NonZeroU64::new(1).ok_or("nonzero audit retention")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe6; 16])?,
    )?;
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    let catalog = Catalog::open(
        &reopened._authority,
        reopened.instance,
        reopened.key.catalog_secret(reopened.instance)?,
    )?;
    let identity = Identity::open(&catalog.pin()?)?;
    let actor = identity.attribute(
        &reopened.key,
        PresentedCredential::parse(&tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let administration = IngestPolicyAdministration::open(&catalog, reopened.tenant)?;
    assert_eq!(
        administration.activate(
            &catalog,
            &identity,
            actor,
            ResourceGeneration::new(1)?,
            key,
            policy,
        )?,
        activation,
        "the terminal policy receipt retains the original activation after pruning"
    );
    Ok(())
}

#[test]
fn failed_policy_catalog_publication_preserves_the_durable_and_live_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let administrator = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let administration = IngestPolicyAdministration::open(&catalog, initialized.tenant)?;
    let candidate = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "reject-after-failed-publication",
            Vec::new(),
            PolicyAction::Reject,
        )?],
    )?;
    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            administration.activate(
                &catalog,
                &initialized.identity,
                administrator,
                ResourceGeneration::new(1).expect("known valid generation"),
                AdministrativeIdempotencyKey::new([0xa6; 16]).expect("known valid key"),
                candidate.clone(),
            )
        })
        .expect_err("a failed audited catalog commit must reject policy activation");
    assert_eq!(
        failure.code(),
        PolicyAdministrationFailureCode::PersistenceUnavailable
    );
    assert_eq!(
        administration.serving().pin()?.generation(),
        1,
        "a failed commit must not advance the in-memory serving snapshot"
    );
    let reopened_administration = IngestPolicyAdministration::open(&catalog, initialized.tenant)?;
    assert_eq!(
        reopened_administration.serving().pin()?.generation(),
        1,
        "a failed commit must not publish a durable policy generation"
    );
    assert!(
        catalog
            .governance_audit_records()?
            .iter()
            .all(|record| GovernanceAuditEntry::decode(record)
                .map(|entry| entry.action() != "ingest-policy.activate")
                .unwrap_or(false)),
        "a rejected commit must not emit a successful policy activation audit entry"
    );
    Ok(())
}

pub(super) fn tenant_administrator(
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
    let catalog = Catalog::open(
        &reopened._authority,
        reopened.instance,
        reopened.key.catalog_secret(reopened.instance)?,
    )?;
    let reopened_policy = IngestPolicyAdministration::open(&catalog, reopened.tenant)?
        .serving()
        .pin()?;
    assert_eq!(reopened_policy.generation(), 3);
    assert_eq!(reopened_policy.digest(), successor_digest);
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
