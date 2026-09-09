use positron_domain::identity::Scope;
use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::{
    BootstrapArtifact, BootstrapObjectPurpose, Catalog, CatalogGovernanceObject, CatalogObject,
    CatalogProposal, FormatEpoch, TransactionId,
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
            .inspect_governance_for_fixture(administrator)?
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
    let listed = reopened.list_api_keys(administrator)?;
    assert_eq!(
        listed.len(),
        1,
        "legacy system administrator remains managed"
    );
    assert_eq!(listed[0].scope(), Scope::SystemAdministration);
    let second_administrator = reopened
        .attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
        .map_err(|_| "second legacy administrator attribution")?;
    let created = reopened.create_api_key(
        second_administrator,
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x72; 16])?,
    )?;
    assert!(created.secret().is_some());
    let rotated = reopened.rotate_api_key(
        second_administrator,
        created.principal_id(),
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x73; 16])?,
    )?;
    assert!(rotated.secret().is_some());
    reopened.revoke_api_key(
        second_administrator,
        created.principal_id(),
        ResourceGeneration::new(3)?,
        AdministrativeIdempotencyKey::new([0x74; 16])?,
    )?;
    let post_create_administrator = reopened
        .attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
        .map_err(|_| "post-create administrator attribution")?;
    let descriptors = reopened.list_api_keys(post_create_administrator)?;
    assert_eq!(descriptors.len(), 3);
    assert!(descriptors.iter().any(|descriptor| {
        descriptor.principal_id() == created.principal_id() && !descriptor.is_active()
    }));
    assert!(descriptors.iter().any(|descriptor| {
        descriptor.principal_id() == rotated.principal_id()
            && descriptor.scope() == Scope::Query
            && descriptor.is_active()
    }));
    drop(reopened);
    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(
        reopened
            .list_api_keys(
                reopened
                    .attribute(
                        PresentedCredential::parse(claim.secret())?,
                        RequestedIntent::SystemAdministration,
                        CompatibilityHints::none(),
                    )
                    .map_err(|_| "post-reopen administrator attribution")?
            )?
            .len(),
        3,
    );
    Ok(())
}

#[test]
fn v6_lifecycle_governance_rewrites_to_a_released_reader_and_reopens()
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
    initialized.transition_tenant_lifecycle(
        administrator,
        initialized.default_tenant_id(),
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x7c; 16])?,
    )?;
    publish_legacy_governance(&initialized)?;
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(reopened.default_tenant_slug().as_str(), "default");
    assert!(
        reopened
            .attribute(
                PresentedCredential::parse(claim.ingest_secret().ok_or("ingest secret")?)?,
                RequestedIntent::Ingest,
                CompatibilityHints::none(),
            )
            .is_err()
    );
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
        let plaintext = if object.starts_with(b"POSGOV03")
            || object.starts_with(b"POSGOV04")
            || object.starts_with(b"POSGOV05")
            || object.starts_with(b"POSGOV06")
        {
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
    let mut legacy = current.to_vec();
    if legacy.starts_with(b"POSGOV06") {
        let credential_extension = CatalogGovernanceObject::decode(&legacy)?
            .credentials()
            .len()
            .checked_mul(90)
            .and_then(|bytes| bytes.checked_add(10))
            .ok_or("credential extension overflow")?;
        let generation_start = legacy
            .len()
            .checked_sub(credential_extension)
            .and_then(|start| start.checked_sub(8))
            .ok_or("truncated V6 lifecycle generation")?;
        let suffix = legacy.split_off(
            generation_start
                .checked_add(8)
                .ok_or("lifecycle generation overflow")?,
        );
        legacy.truncate(generation_start);
        legacy.extend_from_slice(&suffix);
        legacy[..8].copy_from_slice(b"POSGOV05");
    }
    if legacy.starts_with(b"POSGOV05") {
        let extension = CatalogGovernanceObject::decode(current)?
            .credentials()
            .len()
            .checked_mul(90)
            .and_then(|bytes| bytes.checked_add(10))
            .ok_or("credential extension overflow")?;
        let v4_length = legacy
            .len()
            .checked_sub(extension)
            .ok_or("truncated V5 credential extension")?;
        legacy.truncate(v4_length);
        legacy[..8].copy_from_slice(b"POSGOV04");
    }
    if legacy.starts_with(b"POSGOV04") {
        let slug_length = usize::from(*current.get(40).ok_or("truncated slug length")?);
        let alias_start = 41usize
            .checked_add(slug_length)
            .ok_or("slug offset overflow")?;
        let alias_presence = *current.get(alias_start).ok_or("truncated alias presence")?;
        let alias_length = usize::from(
            *current
                .get(alias_start.checked_add(1).ok_or("alias offset overflow")?)
                .ok_or("truncated alias length")?,
        );
        if alias_presence != 1 {
            return Err("current alias is not bound".into());
        }
        let alias_end = alias_start
            .checked_add(2)
            .and_then(|offset| offset.checked_add(alias_length))
            .ok_or("alias end overflow")?;
        if alias_end > legacy.len() {
            return Err("truncated current alias".into());
        }
        legacy.drain(alias_start..alias_end);
    }
    if legacy.len() < 303 {
        return Err("truncated current governance object".into());
    }
    legacy[..8].copy_from_slice(b"POSGOV01");
    legacy.drain(143..303);
    Ok(legacy)
}

fn storage_error(failure: positron_kernel::BootstrapStorageFailure) -> String {
    format!("{failure:?}")
}
