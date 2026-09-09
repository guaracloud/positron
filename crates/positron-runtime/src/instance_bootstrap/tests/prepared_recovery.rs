use std::error::Error;
use std::fs;

use crate::{BootstrapFailureCode, InitializationPlan, InstanceBootstrap};
use positron_domain::identity::Scope;
use positron_governance::{AdministrativeIdempotencyKey, ResourceGeneration};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_after};

use super::initialization::Roots;

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
    Ok(())
}
