use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_governance::{InitialGovernanceIntent, InitialTenantIntent};
use positron_kernel::{
    ActiveSegmentLedger, AuditIntent, BootstrapArtifact, BootstrapArtifactAccess,
    BootstrapKeyCustody, BootstrapObjectPurpose, Catalog, CatalogObject, CatalogProposal,
    FormatEpoch, InstanceId, OwnedPrimaryDataVolume, SegmentScope, StorageKernelResourceAuthority,
    TransactionId,
};
use zeroize::Zeroizing;

use super::codec::{BootstrapRecord, decode_claim, encode_claim};
use super::storage::{self, INTENT};
use super::{
    BootstrapClaim, BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState,
    InitializationPlan, InitializedInstance, resources,
};

pub(super) mod support;
use support::{
    acquire, catalog_failure, entropy_failure, format_secret, inconsistent, key_failure,
    require_key_identity,
};

pub(super) fn classify(paths: &BootstrapPaths) -> Result<BootstrapState, BootstrapFailure> {
    let access = paths.storage.inspect().map_err(storage::storage_failure)?;
    let state = storage::classify_with(&access)?;
    if state != BootstrapState::Initialized {
        return Ok(state);
    }
    match validate_initialized(&access) {
        Ok(()) => Ok(BootstrapState::Initialized),
        Err(failure)
            if matches!(
                failure.code(),
                BootstrapFailureCode::CorruptState | BootstrapFailureCode::IdentityMismatch
            ) =>
        {
            Ok(BootstrapState::Inconsistent)
        },
        Err(failure) => Err(failure),
    }
}

fn validate_initialized(access: &BootstrapArtifactAccess) -> Result<(), BootstrapFailure> {
    if storage::classify_with(access)? != BootstrapState::Initialized {
        return Err(inconsistent());
    }
    let key = access.open_key().map_err(key_failure)?;
    let encoded = storage::read(access, BootstrapArtifact::Initialized)?;
    let record = decode_record(&key, BootstrapObjectPurpose::Initialized, &encoded)?;
    require_key_identity(&record, key.identity())?;
    let generation = access
        .inspect_catalog(
            record.instance,
            key.catalog_secret(record.instance).map_err(key_failure)?,
        )
        .map_err(storage::storage_failure)?;
    if generation == 0 {
        return Err(BootstrapFailure::new(BootstrapFailureCode::CorruptState));
    }
    Ok(())
}

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
    let pending_bytes = storage::read(&access, BootstrapArtifact::Pending)?;
    let record = if pending_bytes == INTENT {
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
    let tenant_intent = InitialTenantIntent::new(
        record.instance.to_bytes(),
        record.tenant,
        BootstrapRecord::tenant_slug()?,
        "Default tenant",
        record.administrator,
        record.api_key_salt,
        record.api_key_hash,
        integrity_identity.public_key(),
        record.integrity_fingerprint,
        protected_integrity,
        tenant_key_envelope,
        2_592_000,
        1,
        1,
        resources::initial_tenant_quota(),
    )
    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let governance = InitialGovernanceIntent::create_tenant(tenant_intent)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let (governance_object, audit_intent) = governance.into_parts();
    let initial = catalog
        .commit(
            catalog.pin().map_err(catalog_failure)?.identity(),
            CatalogProposal::new(
                record.transaction,
                FormatEpoch::CATALOG_V1,
                vec![CatalogObject::new(governance_object).map_err(catalog_failure)?],
            )
            .map_err(catalog_failure)?,
            Some(AuditIntent::new(audit_intent).map_err(catalog_failure)?),
        )
        .map_err(catalog_failure)?;
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
        .governance_audit_record()
        .map_or(current.governance_audit_frontier(), |audit| {
            audit.position()
        });
    let claim_available = storage::exists(&access, BootstrapArtifact::Claim)?;
    drop(catalog);
    outcome(&record, key, authority, generation, audit, claim_available)
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
    drop(catalog);
    outcome(&record, key, authority, generation, audit, claim_available)
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
    let (principal, secret) = decode_claim(record.instance, &plaintext)?;
    if principal != record.administrator {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::IdentityMismatch,
        ));
    }
    let secret = Zeroizing::new(format_secret(&secret));
    storage::remove(&access, BootstrapArtifact::Claim)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ClaimDestructionFailed))?;
    Ok(BootstrapClaim { principal, secret })
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
        integrity_fingerprint,
        api_key_secret: Some(Zeroizing::new(*api_key_secret)),
        integrity_key_secret: Some(Zeroizing::new(*integrity_secret)),
    })
}

pub(super) fn decode_record(
    key: &BootstrapKeyCustody,
    purpose: BootstrapObjectPurpose,
    encoded: &[u8],
) -> Result<BootstrapRecord, BootstrapFailure> {
    let instance = BootstrapKeyCustody::routed_instance(purpose, encoded).map_err(key_failure)?;
    let plaintext = key
        .open_object(instance, purpose, encoded)
        .map_err(key_failure)?;
    let record = BootstrapRecord::decode(&plaintext)?;
    if record.instance != instance {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::IdentityMismatch,
        ));
    }
    Ok(record)
}

fn open_initial_ledgers(
    authority: &positron_kernel::StorageKernelResourceAuthority,
    catalog: &Catalog<'_>,
    key: &BootstrapKeyCustody,
    record: &BootstrapRecord,
) -> Result<(), BootstrapFailure> {
    let shard = VirtualShardId::new(1)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    for signal in [SignalKind::Logs, SignalKind::Traces] {
        let scope = SegmentScope::new(record.tenant, signal, shard);
        let protection = key
            .segment_key(record.instance, scope)
            .map_err(key_failure)?;
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, protection)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::LedgerUnavailable))?;
        drop(ledger);
    }
    Ok(())
}

fn ensure_claim(
    access: &BootstrapArtifactAccess,
    key: &BootstrapKeyCustody,
    record: &BootstrapRecord,
    secret: &[u8; 32],
) -> Result<(), BootstrapFailure> {
    let plaintext = encode_claim(record.instance, record.administrator, secret);
    let encrypted = key
        .protect(record.instance, BootstrapObjectPurpose::Claim, &plaintext)
        .map_err(key_failure)?;
    if storage::exists(access, BootstrapArtifact::Claim)? {
        let existing = storage::read(access, BootstrapArtifact::Claim)?;
        let opened = key
            .open_object(record.instance, BootstrapObjectPurpose::Claim, &existing)
            .map_err(key_failure)?;
        if opened != plaintext {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        Ok(())
    } else {
        storage::write_new(access, BootstrapArtifact::Claim, &encrypted)
    }
}

fn outcome(
    record: &BootstrapRecord,
    key: BootstrapKeyCustody,
    authority: StorageKernelResourceAuthority,
    generation: u64,
    audit: u64,
    claim_available: bool,
) -> Result<InitializedInstance, BootstrapFailure> {
    Ok(InitializedInstance {
        _key: key,
        _authority: authority,
        instance: record.instance,
        tenant: record.tenant,
        tenant_slug: BootstrapRecord::tenant_slug()?,
        administrator: record.administrator,
        integrity_key_fingerprint: record.integrity_fingerprint,
        catalog_generation: generation,
        governance_audit_frontier: audit,
        claim_available,
    })
}
