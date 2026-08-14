use positron_domain::identity::{PrincipalId, TenantId};
use positron_governance::Identity;
use positron_governance::{InitialAuditContext, InitialGovernanceIntent, InitialTenantIntent};
use positron_kernel::{
    AuditIntent, BootstrapArtifact, BootstrapArtifactAccess, BootstrapKeyCustody,
    BootstrapObjectPurpose, Catalog, CatalogObject, CatalogProposal, FormatEpoch, InstanceId,
    OwnedPrimaryDataVolume, TransactionId,
};
use zeroize::Zeroizing;

use super::codec::{
    BootstrapIngestIdentity, BootstrapQueryIdentity, BootstrapRecord, decode_claim,
};
use super::storage::{self, INTENT};
use super::{
    BootstrapClaim, BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState,
    InitializationPlan, InitializedInstance, resources,
};

mod classification;
mod compatibility;
mod completion;
mod policy;
pub(super) mod support;
pub(super) use classification::classify;
pub(super) use completion::governance_audit_records;
use completion::{ensure_claim, open_initial_ledgers, outcome};
pub(super) use policy::activated_policy;
pub(super) use support::decode_record;
use support::{
    acquire, catalog_failure, entropy_failure, format_secret, inconsistent, key_failure,
    recover_pending_replacement, require_key_identity,
};

pub(super) fn initialize(
    paths: &BootstrapPaths,
    plan: InitializationPlan,
) -> Result<InitializedInstance, BootstrapFailure> {
    match storage::classify(paths)? {
        BootstrapState::Empty => {
            let (volume, access) = acquire(paths)?;
            storage::write_new(&access, BootstrapArtifact::Pending, INTENT)?;
            return resume(paths, plan, volume, access);
        },
        BootstrapState::Incomplete => {},
        BootstrapState::Initialized => return reopen(paths),
        BootstrapState::Inconsistent => return Err(inconsistent()),
    }
    let (volume, access) = acquire(paths)?;
    resume(paths, plan, volume, access)
}

fn resume(
    paths: &BootstrapPaths,
    plan: InitializationPlan,
    volume: OwnedPrimaryDataVolume,
    access: BootstrapArtifactAccess,
) -> Result<InitializedInstance, BootstrapFailure> {
    if storage::exists(&access, BootstrapArtifact::InitializedStaging)?
        && !storage::exists(&access, BootstrapArtifact::Pending)?
    {
        storage::publish_initialized(&access)?;
        drop(volume);
        return reopen(paths);
    }
    let key = if access
        .layout()
        .map_err(storage::storage_failure)?
        .contains(positron_kernel::BootstrapEntry::LocalKey)
    {
        access.open_key().map_err(key_failure)?
    } else {
        access.initialize_key().map_err(key_failure)?
    };
    recover_pending_replacement(&access, &key)?;
    let pending_bytes = storage::read(&access, BootstrapArtifact::Pending)?;
    let mut record = if pending_bytes == INTENT {
        let generated = generate_record(&key)?;
        let protected = key
            .protect(
                generated.instance,
                BootstrapObjectPurpose::Pending,
                &generated.encode(),
            )
            .map_err(key_failure)?;
        storage::replace_pending(&access, &protected)?;
        generated
    } else {
        decode_record(&key, BootstrapObjectPurpose::Pending, &pending_bytes)?
    };
    require_key_identity(&record, key.identity())?;
    let authority = resources::establish(volume, record.tenant)?;
    let catalog = Catalog::open(
        &authority,
        record.instance,
        key.catalog_secret(record.instance).map_err(key_failure)?,
    )
    .map_err(catalog_failure)?;
    compatibility::migrate_pending_v1(&access, &key, &catalog, &mut record)?;
    let api_secret = record
        .api_key_secret
        .as_ref()
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let integrity_secret = record
        .integrity_key_secret
        .as_ref()
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let integrity_identity = key
        .integrity_identity(integrity_secret)
        .map_err(key_failure)?;
    if integrity_identity.fingerprint() != record.integrity_fingerprint {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::IdentityMismatch,
        ));
    }
    let protected_integrity = key
        .protect_instance_integrity_key(record.instance, integrity_secret)
        .map_err(key_failure)?;
    let tenant_key_envelope = key
        .tenant_key_envelope(record.instance, record.tenant)
        .map_err(key_failure)?;
    let before = catalog.pin().map_err(catalog_failure)?;
    let initial = if before.number() == 0 {
        let ingest = compatibility::require_new_ingest(&record)?;
        let query = compatibility::require_new_query(&record)?;
        let tenant_intent = InitialTenantIntent::new(
            record.instance.to_bytes(),
            record.tenant,
            BootstrapRecord::tenant_slug()?,
            "Default tenant",
            record.administrator,
            record.api_key_salt,
            record.api_key_hash,
            ingest.principal,
            ingest.api_key_salt,
            ingest.api_key_hash,
            query.principal,
            query.api_key_salt,
            query.api_key_hash,
            integrity_identity.public_key(),
            record.integrity_fingerprint,
            protected_integrity,
            tenant_key_envelope,
            2_592_000,
            1,
            1,
            resources::initial_tenant_quota(),
            InitialAuditContext::new(
                key.identity().created_at_unix_seconds(),
                record.transaction.to_bytes(),
                plan.creates_claim(),
            )
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let governance = InitialGovernanceIntent::create_tenant(tenant_intent)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let (governance_object, audit_intent) = governance.into_parts();
        Some(
            catalog
                .commit(
                    before.identity(),
                    CatalogProposal::new(
                        record.transaction,
                        FormatEpoch::CATALOG_V1,
                        vec![CatalogObject::new(governance_object).map_err(catalog_failure)?],
                    )
                    .map_err(catalog_failure)?,
                    Some(AuditIntent::new(audit_intent).map_err(catalog_failure)?),
                )
                .map_err(catalog_failure)?,
        )
    } else {
        None
    };
    open_initial_ledgers(&authority, &catalog, &key, &record)?;
    let current = catalog.pin().map_err(catalog_failure)?;
    if plan.creates_claim() {
        ensure_claim(&access, &key, &record, api_secret)?;
    }
    let initialized_record = record.initialized();
    let initialized = key
        .protect(
            record.instance,
            BootstrapObjectPurpose::Initialized,
            &initialized_record.encode(),
        )
        .map_err(key_failure)?;
    if !storage::exists(&access, BootstrapArtifact::InitializedStaging)? {
        storage::write_new(&access, BootstrapArtifact::InitializedStaging, &initialized)?;
    }
    storage::remove(&access, BootstrapArtifact::Pending)?;
    storage::publish_initialized(&access)?;
    let generation = current.number();
    let audit = initial
        .as_ref()
        .and_then(|commit| commit.governance_audit_record())
        .map_or(current.governance_audit_frontier(), |audit| {
            audit.position()
        });
    let claim_available = storage::exists(&access, BootstrapArtifact::Claim)?;
    let identity = Identity::open(&current)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let audit_records = governance_audit_records(&catalog)?;
    let ingest_policy = activated_policy(&current, record.tenant)?;
    drop(catalog);
    outcome(
        &record,
        key,
        identity,
        audit_records,
        authority,
        generation,
        audit,
        claim_available,
        ingest_policy,
    )
}

pub(super) fn reopen(paths: &BootstrapPaths) -> Result<InitializedInstance, BootstrapFailure> {
    let (volume, access) = acquire(paths)?;
    if storage::classify_with(&access)? != BootstrapState::Initialized {
        return Err(inconsistent());
    }
    let key = access.open_key().map_err(key_failure)?;
    let encoded = storage::read(&access, BootstrapArtifact::Initialized)?;
    let record = decode_record(&key, BootstrapObjectPurpose::Initialized, &encoded)?;
    require_key_identity(&record, key.identity())?;
    let authority = resources::establish(volume, record.tenant)?;
    let catalog = Catalog::open(
        &authority,
        record.instance,
        key.catalog_secret(record.instance).map_err(key_failure)?,
    )
    .map_err(catalog_failure)?;
    if catalog.pin().map_err(catalog_failure)?.number() == 0 {
        return Err(BootstrapFailure::new(BootstrapFailureCode::CorruptState));
    }
    open_initial_ledgers(&authority, &catalog, &key, &record)?;
    let current = catalog.pin().map_err(catalog_failure)?;
    let generation = current.number();
    let audit = current.governance_audit_frontier();
    let claim_available = storage::exists(&access, BootstrapArtifact::Claim)?;
    let identity = Identity::open(&current)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let audit_records = governance_audit_records(&catalog)?;
    let ingest_policy = activated_policy(&current, record.tenant)?;
    drop(catalog);
    outcome(
        &record,
        key,
        identity,
        audit_records,
        authority,
        generation,
        audit,
        claim_available,
        ingest_policy,
    )
}

pub(super) fn claim(paths: &BootstrapPaths) -> Result<BootstrapClaim, BootstrapFailure> {
    let (_volume, access) = acquire(paths)?;
    if storage::classify_with(&access)? != BootstrapState::Initialized
        || !storage::exists(&access, BootstrapArtifact::Claim)?
    {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::ClaimUnavailable,
        ));
    }
    let key = access.open_key().map_err(key_failure)?;
    let initialized = storage::read(&access, BootstrapArtifact::Initialized)?;
    let record = decode_record(&key, BootstrapObjectPurpose::Initialized, &initialized)?;
    let encrypted_claim = storage::read(&access, BootstrapArtifact::Claim)?;
    let plaintext = key
        .open_object(
            record.instance,
            BootstrapObjectPurpose::Claim,
            &encrypted_claim,
        )
        .map_err(key_failure)?;
    let decoded = decode_claim(record.instance, &plaintext)?;
    let expected_ingest = record.ingest.as_ref().map(|ingest| ingest.principal);
    let expected_query = record.query.as_ref().map(|query| query.principal);
    if decoded.principal != record.administrator
        || decoded.ingest.as_ref().map(|(principal, _)| *principal) != expected_ingest
        || decoded.query.as_ref().map(|(principal, _)| *principal) != expected_query
    {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::IdentityMismatch,
        ));
    }
    let secret = Zeroizing::new(format_secret(&decoded.secret));
    let principal = decoded.principal;
    let ingest = decoded
        .ingest
        .map(|(principal, secret)| (principal, Zeroizing::new(format_secret(&secret))));
    let query = decoded
        .query
        .map(|(principal, secret)| (principal, Zeroizing::new(format_secret(&secret))));
    storage::remove(&access, BootstrapArtifact::Claim)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ClaimDestructionFailed))?;
    Ok(BootstrapClaim {
        principal,
        secret,
        ingest,
        query,
    })
}

fn generate_record(key: &BootstrapKeyCustody) -> Result<BootstrapRecord, BootstrapFailure> {
    let instance = InstanceId::new(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let tenant = TenantId::from_bytes(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let administrator = PrincipalId::from_bytes(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let transaction = TransactionId::new(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let api_key_salt = key.random_secret().map_err(key_failure)?;
    let api_key_secret = key.random_secret().map_err(key_failure)?;
    let api_key_hash = key
        .salted_secret_hash(api_key_salt.as_ref(), api_key_secret.as_ref())
        .map_err(key_failure)?;
    let ingest_principal = PrincipalId::from_bytes(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let ingest_api_key_salt = key.random_secret().map_err(key_failure)?;
    let ingest_api_key_secret = key.random_secret().map_err(key_failure)?;
    let ingest_api_key_hash = key
        .salted_secret_hash(ingest_api_key_salt.as_ref(), ingest_api_key_secret.as_ref())
        .map_err(key_failure)?;
    let query_principal = PrincipalId::from_bytes(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let query_api_key_salt = key.random_secret().map_err(key_failure)?;
    let query_api_key_secret = key.random_secret().map_err(key_failure)?;
    let query_api_key_hash = key
        .salted_secret_hash(query_api_key_salt.as_ref(), query_api_key_secret.as_ref())
        .map_err(key_failure)?;
    let integrity_secret = key.random_secret().map_err(key_failure)?;
    let integrity_fingerprint = key
        .integrity_identity(integrity_secret.as_ref())
        .map_err(key_failure)?
        .fingerprint();
    Ok(BootstrapRecord {
        instance,
        key: key.identity(),
        tenant,
        administrator,
        transaction,
        api_key_salt: *api_key_salt,
        api_key_hash,
        ingest: Some(BootstrapIngestIdentity {
            principal: ingest_principal,
            api_key_salt: *ingest_api_key_salt,
            api_key_hash: ingest_api_key_hash,
            api_key_secret: Some(Zeroizing::new(*ingest_api_key_secret)),
        }),
        query: Some(BootstrapQueryIdentity {
            principal: query_principal,
            api_key_salt: *query_api_key_salt,
            api_key_hash: query_api_key_hash,
            api_key_secret: Some(Zeroizing::new(*query_api_key_secret)),
        }),
        integrity_fingerprint,
        api_key_secret: Some(Zeroizing::new(*api_key_secret)),
        integrity_key_secret: Some(Zeroizing::new(*integrity_secret)),
    })
}
