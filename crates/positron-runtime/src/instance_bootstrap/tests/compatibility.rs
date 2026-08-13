use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{
    BootstrapArtifact, BootstrapObjectPurpose, Catalog, CatalogObject, CatalogProposal,
    FormatEpoch, TransactionId,
};

use super::super::codec::{BootstrapRecord, decode_claim, encode_legacy_claim};
use super::super::storage::{BootstrapFileEvent, with_fault};
use super::support::Roots;
use crate::{InitializationPlan, InstanceBootstrap};

#[test]
fn legacy_initialized_instance_reopens_and_preserves_its_one_time_admin_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let expected_instance = initialized.instance_id();
    let expected_tenant = initialized.default_tenant_id();
    let expected_administrator = initialized.system_administrator_id();

    publish_legacy_governance(&initialized)?;
    rewrite_bootstrap_and_claim_as_v1(&paths, &initialized)?;
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(reopened.instance_id(), expected_instance);
    assert_eq!(reopened.default_tenant_id(), expected_tenant);
    assert_eq!(reopened.system_administrator_id(), expected_administrator);
    assert!(reopened.claim_available());
    drop(reopened);

    let claim = InstanceBootstrap::claim(&paths)?;
    assert_eq!(claim.principal_id(), expected_administrator);
    assert_eq!(claim.ingest_principal_id(), None);
    assert_eq!(claim.ingest_secret(), None);
    assert_eq!(claim.query_principal_id(), None);
    assert_eq!(claim.query_secret(), None);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    let administrator = reopened.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(
        reopened
            .inspect_governance(administrator)?
            .audit_records()
            .len(),
        1,
    );
    assert!(
        reopened
            .attribute(
                PresentedCredential::parse(claim.secret())?,
                RequestedIntent::Ingest,
                CompatibilityHints::none(),
            )
            .is_err()
    );
    assert!(
        reopened
            .attribute(
                PresentedCredential::parse(claim.secret())?,
                RequestedIntent::Query,
                CompatibilityHints::none(),
            )
            .is_err()
    );
    assert!(!reopened.claim_available());
    Ok(())
}

#[test]
fn legacy_pending_before_catalog_commit_migrates_to_v3_and_claims_fresh_data_authorities()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    with_fault(BootstrapFileEvent::ReplacePendingAfterSync, || {
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
    })
    .expect_err("fault leaves a protected pre-catalog pending record");

    rewrite_pending_replacement_as_v1(&paths)?;
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    assert!(initialized.claim_available());
    drop(initialized);

    let claim = InstanceBootstrap::claim(&paths)?;
    let ingest_secret = claim
        .ingest_secret()
        .ok_or("migrated ingest secret missing")?;
    let ingest_principal = claim
        .ingest_principal_id()
        .ok_or("migrated ingest principal missing")?;
    let query_secret = claim
        .query_secret()
        .ok_or("migrated query secret missing")?;
    let query_principal = claim
        .query_principal_id()
        .ok_or("migrated query principal missing")?;
    let reopened = InstanceBootstrap::reopen(&paths)?;
    let context = reopened.attribute(
        PresentedCredential::parse(ingest_secret)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    assert_eq!(context.principal_id(), ingest_principal);
    assert_eq!(
        context.tenant_attribution().map(|value| value.tenant_id()),
        Some(reopened.default_tenant_id())
    );
    let query = reopened.attribute(
        PresentedCredential::parse(query_secret)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    assert_eq!(query.principal_id(), query_principal);
    Ok(())
}

fn publish_legacy_governance(
    initialized: &super::super::InitializedInstance,
) -> Result<(), Box<dyn std::error::Error>> {
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let current = catalog.pin()?;
    let mut replaced = false;
    let mut objects = Vec::new();
    for identity in current.object_identities() {
        let object = current.object(identity)?.ok_or("missing catalog object")?;
        let plaintext = if object.starts_with(b"POSGOV03") {
            replaced = true;
            legacy_governance(object)?
        } else {
            object.to_vec()
        };
        objects.push(CatalogObject::new(plaintext)?);
    }
    if !replaced {
        return Err("current governance object missing".into());
    }
    catalog.commit(
        current.identity(),
        CatalogProposal::new(
            TransactionId::new([0x71; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}

fn rewrite_bootstrap_and_claim_as_v1(
    paths: &super::super::BootstrapPaths,
    initialized: &super::super::InitializedInstance,
) -> Result<(), Box<dyn std::error::Error>> {
    let access = paths.storage.inspect().map_err(storage_error)?;
    let initialized_bytes = access
        .read(BootstrapArtifact::Initialized)
        .map_err(storage_error)?;
    let plaintext = initialized.key.open_object(
        initialized.instance,
        BootstrapObjectPurpose::Initialized,
        &initialized_bytes,
    )?;
    let mut record = BootstrapRecord::decode(&plaintext)?;
    record.ingest = None;
    record.query = None;
    let protected = initialized.key.protect(
        initialized.instance,
        BootstrapObjectPurpose::Initialized,
        &record.encode(),
    )?;

    let claim_bytes = access
        .read(BootstrapArtifact::Claim)
        .map_err(storage_error)?;
    let claim = initialized.key.open_object(
        initialized.instance,
        BootstrapObjectPurpose::Claim,
        &claim_bytes,
    )?;
    let claim = decode_claim(initialized.instance, &claim)?;
    let legacy_claim = encode_legacy_claim(initialized.instance, claim.principal, &claim.secret);
    let protected_claim = initialized.key.protect(
        initialized.instance,
        BootstrapObjectPurpose::Claim,
        &legacy_claim,
    )?;

    access
        .remove(BootstrapArtifact::Initialized)
        .map_err(storage_error)?;
    access
        .write_new(BootstrapArtifact::Initialized, &protected)
        .map_err(storage_error)?;
    access
        .remove(BootstrapArtifact::Claim)
        .map_err(storage_error)?;
    access
        .write_new(BootstrapArtifact::Claim, &protected_claim)
        .map_err(storage_error)?;
    Ok(())
}

fn rewrite_pending_replacement_as_v1(
    paths: &super::super::BootstrapPaths,
) -> Result<(), Box<dyn std::error::Error>> {
    let access = paths.storage.inspect().map_err(storage_error)?;
    let key = access.open_key()?;
    let encrypted = access
        .read(BootstrapArtifact::PendingReplacement)
        .map_err(storage_error)?;
    let instance = positron_kernel::BootstrapKeyCustody::routed_instance(
        BootstrapObjectPurpose::Pending,
        &encrypted,
    )?;
    let plaintext = key.open_object(instance, BootstrapObjectPurpose::Pending, &encrypted)?;
    let mut record = BootstrapRecord::decode(&plaintext)?;
    record.ingest = None;
    record.query = None;
    let legacy = key.protect(instance, BootstrapObjectPurpose::Pending, &record.encode())?;
    access
        .remove(BootstrapArtifact::PendingReplacement)
        .map_err(storage_error)?;
    access
        .write_new(BootstrapArtifact::PendingReplacement, &legacy)
        .map_err(storage_error)?;
    Ok(())
}

fn legacy_governance(current: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if current.len() < 303 {
        return Err("truncated current governance object".into());
    }
    let mut legacy = current.to_vec();
    legacy[..8].copy_from_slice(b"POSGOV01");
    legacy.drain(143..303);
    Ok(legacy)
}

fn storage_error(failure: positron_kernel::BootstrapStorageFailure) -> String {
    format!("{failure:?}")
}
