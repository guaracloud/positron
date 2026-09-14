use std::error::Error;
use std::fs;

use crate::{BootstrapFailureCode, InitializationPlan, InstanceBootstrap};
use positron_domain::identity::{Scope, TenantId, TenantSlug};
use positron_governance::{AdministrativeIdempotencyKey, ResourceGeneration};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{
    Catalog, CatalogPublicationFault, ResourceAmounts, ResourceDimension, WorkClaim, WorkKind,
    with_catalog_publication_fault_after,
};

use super::initialization::Roots;

#[test]
fn pre_marker_tenant_creation_is_invisible_then_resumes_its_prepared_envelope()
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
    let tenant = TenantId::from_bytes([0x61; 16])?;
    let idempotency = AdministrativeIdempotencyKey::new([0x62; 16])?;
    let predecessor = instance.catalog_generation();
    let audit_before = instance.governance_audit_for_test()?;
    let failed =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            instance.create_tenant(
                administrator().expect("administrator"),
                tenant,
                positron_governance::TenantCreateConfiguration::new(
                    TenantSlug::parse_canonical("prepared-tenant").expect("tenant slug"),
                    "Prepared tenant",
                    2_592_000,
                    1,
                    [1; 11],
                ),
                idempotency,
            )
        })
        .expect_err("pre-marker tenant creation must not acknowledge a tenant");
    assert_eq!(failed.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(instance.catalog_generation(), predecessor);
    assert_eq!(instance.governance_audit_for_test()?, audit_before);
    assert!(
        instance
            ._authority
            .governor()
            .reserve(WorkClaim::tenant(
                tenant,
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
            )?)
            .is_err(),
        "a failed creation must not leave live tenant admission"
    );
    let prepared_manifest = roots
        .data
        .join("catalog/staging/62626262626262626262626262626262/prepared.manifest");
    let staged_envelope_commit = fs::read(&prepared_manifest)?;
    assert!(
        !staged_envelope_commit.is_empty(),
        "the failed creation retains encrypted transaction-owned evidence"
    );
    drop(instance);

    let recovered = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        recovered.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let changed = recovered
        .create_tenant(
            administrator()?,
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("prepared-tenant")?,
                "Changed tenant",
                2_592_000,
                1,
                [1; 11],
            ),
            idempotency,
        )
        .expect_err("a changed request must not claim the prepared tenant transaction");
    assert_eq!(
        changed.code(),
        BootstrapFailureCode::ApiKeyIdempotencyConflict
    );
    assert_eq!(recovered.catalog_generation(), predecessor);
    assert_eq!(recovered.governance_audit_for_test()?, audit_before);

    let resumed = recovered.create_tenant(
        administrator()?,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("prepared-tenant")?,
            "Prepared tenant",
            2_592_000,
            1,
            [1; 11],
        ),
        idempotency,
    )?;
    assert_eq!(resumed.tenant_id(), tenant);
    assert_ne!(resumed.audit_position(), 0);
    assert_eq!(
        fs::read(&prepared_manifest)?,
        staged_envelope_commit,
        "the retry must publish the exact staged envelope proposal without replacement entropy"
    );
    let catalog = Catalog::open(
        &recovered._authority,
        recovered.instance,
        recovered.key.catalog_secret(recovered.instance)?,
    )?;
    let snapshot = catalog.pin()?;
    assert!(snapshot.number() > predecessor);
    assert!(
        snapshot.object_identities().into_iter().any(|identity| {
            snapshot
                .object(identity)
                .ok()
                .flatten()
                .is_some_and(|object| {
                    object.starts_with(b"POSTNR03")
                        && object.windows(8).any(|window| window == b"POSTKE01")
                })
        }),
        "the resumed catalog generation contains the tenant's staged KEK envelope"
    );
    let admission = recovered._authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    drop(admission);
    Ok(())
}

#[test]
fn tenant_scoped_actor_cannot_claim_a_prepared_tenant_creation_idempotency_key()
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
    let query_key = instance.create_api_key(
        administrator()?,
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x63; 16])?,
    )?;
    let query_secret = query_key.secret().ok_or("one-time query key")?.to_owned();
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let idempotency = AdministrativeIdempotencyKey::new([0x65; 16])?;
    with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
        instance.create_tenant(
            administrator().expect("administrator"),
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("actor-bound-tenant").expect("tenant slug"),
                "Actor-bound tenant",
                2_592_000,
                1,
                [1; 11],
            ),
            idempotency,
        )
    })
    .expect_err("pre-marker tenant creation must leave a prepared transaction");
    drop(instance);

    let recovered = InstanceBootstrap::reopen(&paths)?;
    let query_actor = recovered.attribute(
        PresentedCredential::parse(&query_secret)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let before = recovered.catalog_generation();
    let audit_before = recovered.governance_audit_for_test()?;
    let rejected = recovered
        .create_tenant(
            query_actor,
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("actor-bound-tenant")?,
                "Actor-bound tenant",
                2_592_000,
                1,
                [1; 11],
            ),
            idempotency,
        )
        .expect_err("a changed actor must not resolve another administrator's transaction");
    assert_eq!(rejected.code(), BootstrapFailureCode::ApiKeyUnauthorized);
    assert_eq!(recovered.catalog_generation(), before);
    assert_eq!(recovered.governance_audit_for_test()?, audit_before);

    let administrator = recovered.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let resumed = recovered.create_tenant(
        administrator,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("actor-bound-tenant")?,
            "Actor-bound tenant",
            2_592_000,
            1,
            [1; 11],
        ),
        idempotency,
    )?;
    assert_eq!(resumed.tenant_id(), tenant);
    Ok(())
}

#[test]
fn advanced_catalog_refuses_prepared_tenant_creation_without_live_admission()
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
    let tenant = TenantId::from_bytes([0x66; 16])?;
    let idempotency = AdministrativeIdempotencyKey::new([0x67; 16])?;
    with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
        instance.create_tenant(
            administrator().expect("administrator"),
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("advanced-tenant").expect("tenant slug"),
                "Advanced tenant",
                2_592_000,
                1,
                [1; 11],
            ),
            idempotency,
        )
    })
    .expect_err("pre-marker tenant creation must leave a prepared transaction");
    drop(instance);

    let recovered = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        recovered.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    recovered.create_api_key(
        administrator()?,
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x68; 16])?,
    )?;
    let audit_before_retry = recovered.governance_audit_for_test()?;
    let rejected = recovered
        .create_tenant(
            administrator()?,
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("advanced-tenant")?,
                "Advanced tenant",
                2_592_000,
                1,
                [1; 11],
            ),
            idempotency,
        )
        .expect_err("an advanced predecessor must not publish a stale tenant proposal");
    assert_eq!(rejected.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(recovered.governance_audit_for_test()?, audit_before_retry);
    assert!(
        recovered
            ._authority
            .governor()
            .reserve(WorkClaim::tenant(
                tenant,
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
            )?)
            .is_err(),
        "an unavailable prepared retry must not activate tenant admission"
    );
    Ok(())
}

#[test]
fn pre_marker_api_key_create_retry_resumes_the_prepared_credential_without_a_secret()
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
    let idempotency = AdministrativeIdempotencyKey::new([51; 16])?;
    let prepared_predecessor = instance.catalog_generation();
    let before = instance.list_api_keys(administrator()?)?;
    let failed =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            instance.create_api_key(
                administrator().expect("administrator"),
                Scope::Query,
                None,
                ResourceGeneration::new(1).expect("generation"),
                idempotency,
            )
        })
        .expect_err("pre-marker failure must not acknowledge the credential");
    assert_eq!(failed.code(), BootstrapFailureCode::CatalogUnavailable);
    drop(instance);

    let recovered = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        recovered.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    assert_eq!(recovered.catalog_generation(), prepared_predecessor);
    assert_eq!(recovered.list_api_keys(administrator()?)?, before);
    let changed = recovered
        .create_api_key(
            administrator()?,
            Scope::Ingest,
            None,
            ResourceGeneration::new(1)?,
            idempotency,
        )
        .expect_err("a changed request cannot claim the prepared idempotency key");
    assert_eq!(
        changed.code(),
        BootstrapFailureCode::ApiKeyIdempotencyConflict
    );
    assert_eq!(recovered.list_api_keys(administrator()?)?, before);
    let resumed = recovered.create_api_key(
        administrator()?,
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        idempotency,
    )?;
    assert!(
        resumed.secret().is_none(),
        "a restart retry may publish the original salted verifier but never recover its secret"
    );
    let descriptors = recovered.list_api_keys(administrator()?)?;
    assert_eq!(descriptors.len(), before.len() + 1);
    assert!(descriptors.iter().any(|descriptor| {
        descriptor.principal_id() == resumed.principal_id() && descriptor.scope() == Scope::Query
    }));
    drop(recovered);
    let normally_reopened = InstanceBootstrap::reopen(&paths)?;
    assert!(
        normally_reopened.catalog_generation() > prepared_predecessor + 1,
        "a published prepared record no longer defers normal ledger startup"
    );
    let administrator = normally_reopened.attribute(
        PresentedCredential::parse(claim.secret()).expect("claim syntax"),
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(normally_reopened.list_api_keys(administrator)?, descriptors);
    Ok(())
}

#[test]
fn pre_marker_api_key_rotation_retry_resumes_the_prepared_successor_without_a_secret()
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
    let predecessor = instance.create_api_key(
        administrator()?,
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([54; 16])?,
    )?;
    let idempotency = AdministrativeIdempotencyKey::new([55; 16])?;
    let failed =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            instance.rotate_api_key(
                administrator().expect("administrator"),
                predecessor.principal_id(),
                ResourceGeneration::new(2).expect("generation"),
                idempotency,
            )
        })
        .expect_err("pre-marker rotation must not acknowledge a successor");
    assert_eq!(failed.code(), BootstrapFailureCode::CatalogUnavailable);
    drop(instance);

    let recovered = InstanceBootstrap::reopen(&paths)?;
    let administrator = recovered.attribute(
        PresentedCredential::parse(claim.secret()).expect("claim syntax"),
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let resumed = recovered.rotate_api_key(
        administrator,
        predecessor.principal_id(),
        ResourceGeneration::new(2)?,
        idempotency,
    )?;
    assert!(resumed.secret().is_none());
    let administrator = recovered.attribute(
        PresentedCredential::parse(claim.secret()).expect("claim syntax"),
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let descriptors = recovered.list_api_keys(administrator)?;
    assert!(descriptors.iter().any(|descriptor| {
        descriptor.principal_id() == resumed.principal_id() && descriptor.is_active()
    }));
    Ok(())
}

#[test]
fn incomplete_prepared_api_key_record_fails_closed_without_mutation() -> Result<(), Box<dyn Error>>
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
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let idempotency = AdministrativeIdempotencyKey::new([55; 16])?;
    let before = instance.list_api_keys(administrator()?)?;
    with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
        instance.create_api_key(
            administrator().expect("administrator"),
            Scope::Query,
            None,
            ResourceGeneration::new(1).expect("generation"),
            idempotency,
        )
    })
    .expect_err("pre-marker failure must leave a prepared transaction");
    drop(instance);

    fs::remove_file(
        roots
            .data
            .join("catalog/staging/37373737373737373737373737373737/transaction.digest"),
    )?;
    let recovered = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        recovered.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let rejected = recovered
        .create_api_key(
            administrator()?,
            Scope::Query,
            None,
            ResourceGeneration::new(1)?,
            idempotency,
        )
        .expect_err("a prepared record without its immutable digest cannot publish");
    assert_eq!(rejected.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(recovered.list_api_keys(administrator()?)?, before);
    Ok(())
}

#[test]
fn tampered_prepared_api_key_record_fails_closed_without_exposing_a_secret()
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
    let idempotency = AdministrativeIdempotencyKey::new([54; 16])?;
    let before = instance.list_api_keys(administrator()?)?;
    with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
        instance.create_api_key(
            administrator().expect("administrator"),
            Scope::Query,
            None,
            ResourceGeneration::new(1).expect("generation"),
            idempotency,
        )
    })
    .expect_err("pre-marker failure must leave a prepared transaction");
    drop(instance);

    let manifest = roots
        .data
        .join("catalog/staging/36363636363636363636363636363636/prepared.manifest");
    let mut protected = fs::read(&manifest)?;
    assert!(
        !protected.starts_with(b"PPRE0001"),
        "the prepared record is encrypted rather than a plaintext credential proposal"
    );
    let last = protected
        .last_mut()
        .ok_or("prepared manifest must have authenticated bytes")?;
    *last ^= 1;
    fs::write(&manifest, protected)?;

    let recovered = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        recovered.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let rejected = recovered
        .create_api_key(
            administrator()?,
            Scope::Query,
            None,
            ResourceGeneration::new(1)?,
            idempotency,
        )
        .expect_err("an unauthenticated prepared record cannot become an API-key outcome");
    assert_eq!(rejected.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(recovered.list_api_keys(administrator()?)?, before);
    Ok(())
}

#[test]
fn advanced_catalog_refuses_prepared_api_key_recovery_without_mutation()
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
    let original = AdministrativeIdempotencyKey::new([52; 16])?;
    with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
        instance.create_api_key(
            administrator().expect("administrator"),
            Scope::Query,
            None,
            ResourceGeneration::new(1).expect("generation"),
            original,
        )
    })
    .expect_err("pre-marker failure must leave a prepared transaction");
    drop(instance);

    let recovered = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        recovered.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let successor = recovered.create_api_key(
        administrator()?,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([53; 16])?,
    )?;
    assert!(successor.secret().is_some());
    let before_retry = recovered.list_api_keys(administrator()?)?;
    let rejected = recovered
        .create_api_key(
            administrator()?,
            Scope::Query,
            None,
            ResourceGeneration::new(1)?,
            original,
        )
        .expect_err("an advanced Catalog predecessor cannot publish a stale prepared proposal");
    assert_eq!(rejected.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(recovered.list_api_keys(administrator()?)?, before_retry);
    drop(recovered);
    let normally_reopened = InstanceBootstrap::reopen(&paths)?;
    assert!(
        normally_reopened.catalog_generation() > 1,
        "an advanced prepared record does not suppress later normal startup"
    );
    Ok(())
}
