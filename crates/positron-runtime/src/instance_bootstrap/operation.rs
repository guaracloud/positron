use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_governance::InitialGovernanceIntent;
use positron_kernel::{
    ActiveSegmentLedger, AuditIntent, BootstrapKeyCustody, BootstrapKeyIdentity,
    BootstrapObjectPurpose, Catalog, CatalogObject, CatalogProposal, FormatEpoch, InstanceId,
    MountQualification, PrimaryDataVolume, SegmentScope, TransactionId,
};
use zeroize::Zeroizing;

use super::codec::{BootstrapRecord, decode_claim, encode_claim};
use super::storage::{self, CLAIM, INITIALIZED, INITIALIZED_TEMP, INTENT, LOCAL_KEY, PENDING};
use super::{
    BootstrapClaim, BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState,
    InitializationPlan, InitializedInstance, resources,
};

pub(super) fn initialize(
    paths: &BootstrapPaths,
    plan: InitializationPlan,
) -> Result<InitializedInstance, BootstrapFailure> {
    match storage::classify(paths)? {
        BootstrapState::Empty => storage::write_new(&paths.data, PENDING, INTENT)?,
        BootstrapState::Incomplete => {},
        BootstrapState::Initialized => return reopen(paths),
        BootstrapState::Inconsistent => return Err(inconsistent()),
    }
    resume(paths, plan)
}

fn resume(
    paths: &BootstrapPaths,
    plan: InitializationPlan,
) -> Result<InitializedInstance, BootstrapFailure> {
    if storage::exists(&paths.data, INITIALIZED_TEMP) && !storage::exists(&paths.data, PENDING) {
        storage::publish_initialized(&paths.data)?;
        return reopen(paths);
    }
    let volume = PrimaryDataVolume::acquire(&paths.data, MountQualification::LocalHost)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::StorageUnavailable))?;
    let key = if storage::exists(&paths.secrets, LOCAL_KEY) {
        BootstrapKeyCustody::open(&paths.secrets).map_err(key_failure)?
    } else {
        BootstrapKeyCustody::initialize(&paths.secrets).map_err(key_failure)?
    };
    let pending_bytes = storage::read(&paths.data, PENDING)?;
    let record = if pending_bytes == INTENT {
        let generated = generate_record(&key)?;
        let protected = key
            .protect(
                generated.instance,
                BootstrapObjectPurpose::Pending,
                &generated.encode(),
            )
            .map_err(key_failure)?;
        storage::replace(&paths.data, PENDING, &protected)?;
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
    let governance = InitialGovernanceIntent::new(
        record.instance.to_bytes(),
        record.tenant,
        &BootstrapRecord::tenant_slug()?,
        record.administrator,
        record.api_key_salt,
        record.api_key_hash,
        integrity_identity.public_key(),
        record.integrity_fingerprint,
        &protected_integrity,
    )
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
        ensure_claim(paths, &key, &record, api_secret)?;
    }
    let initialized_record = record.initialized();
    let initialized = key
        .protect(
            record.instance,
            BootstrapObjectPurpose::Initialized,
            &initialized_record.encode(),
        )
        .map_err(key_failure)?;
    if !storage::exists(&paths.data, INITIALIZED_TEMP) {
        storage::write_new(&paths.data, INITIALIZED_TEMP, &initialized)?;
    }
    storage::remove(&paths.data, PENDING)?;
    storage::publish_initialized(&paths.data)?;
    outcome(
        &record,
        current.number(),
        initial
            .governance_audit_record()
            .map_or(current.governance_audit_frontier(), |audit| {
                audit.position()
            }),
        storage::exists(&paths.secrets, CLAIM),
    )
}

pub(super) fn reopen(paths: &BootstrapPaths) -> Result<InitializedInstance, BootstrapFailure> {
    if storage::classify(paths)? != BootstrapState::Initialized {
        return Err(inconsistent());
    }
    let key = BootstrapKeyCustody::open(&paths.secrets).map_err(key_failure)?;
    let encoded = storage::read(&paths.data, INITIALIZED)?;
    let record = decode_record(&key, BootstrapObjectPurpose::Initialized, &encoded)?;
    require_key_identity(&record, key.identity())?;
    let volume = PrimaryDataVolume::acquire(&paths.data, MountQualification::LocalHost)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::StorageUnavailable))?;
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
    outcome(
        &record,
        current.number(),
        current.governance_audit_frontier(),
        storage::exists(&paths.secrets, CLAIM),
    )
}

pub(super) fn claim(paths: &BootstrapPaths) -> Result<BootstrapClaim, BootstrapFailure> {
    if storage::classify(paths)? != BootstrapState::Initialized
        || !storage::exists(&paths.secrets, CLAIM)
    {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::ClaimUnavailable,
        ));
    }
    let key = BootstrapKeyCustody::open(&paths.secrets).map_err(key_failure)?;
    let initialized = storage::read(&paths.data, INITIALIZED)?;
    let record = decode_record(&key, BootstrapObjectPurpose::Initialized, &initialized)?;
    let encrypted_claim = storage::read(&paths.secrets, CLAIM)?;
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
    let secret = Zeroizing::new(format_secret(secret.as_ref()));
    storage::remove(&paths.secrets, CLAIM)
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

fn decode_record(
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
    paths: &BootstrapPaths,
    key: &BootstrapKeyCustody,
    record: &BootstrapRecord,
    secret: &[u8; 32],
) -> Result<(), BootstrapFailure> {
    let plaintext = encode_claim(record.instance, record.administrator, secret);
    let encrypted = key
        .protect(record.instance, BootstrapObjectPurpose::Claim, &plaintext)
        .map_err(key_failure)?;
    if storage::exists(&paths.secrets, CLAIM) {
        let existing = storage::read(&paths.secrets, CLAIM)?;
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
        storage::write_new(&paths.secrets, CLAIM, &encrypted)
    }
}

fn outcome(
    record: &BootstrapRecord,
    generation: u64,
    audit: u64,
    claim_available: bool,
) -> Result<InitializedInstance, BootstrapFailure> {
    Ok(InitializedInstance {
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

fn require_key_identity(
    record: &BootstrapRecord,
    actual: BootstrapKeyIdentity,
) -> Result<(), BootstrapFailure> {
    if record.key == actual {
        Ok(())
    } else {
        Err(BootstrapFailure::new(
            BootstrapFailureCode::IdentityMismatch,
        ))
    }
}

fn format_secret(secret: &[u8; 32]) -> String {
    let mut result = String::with_capacity(68);
    result.push_str("pos_");
    for byte in secret {
        result.push(hex_digit(byte >> 4));
        result.push(hex_digit(byte & 0x0f));
    }
    result
}

const fn hex_digit(value: u8) -> char {
    match value {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        15 => 'f',
        _ => '?',
    }
}

fn inconsistent() -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::InconsistentRoots)
}

fn entropy_failure() -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::EntropyUnavailable)
}

fn key_failure(failure: positron_kernel::BootstrapKeyFailure) -> BootstrapFailure {
    let code = match failure {
        positron_kernel::BootstrapKeyFailure::Custody => {
            BootstrapFailureCode::KeyCustodyUnavailable
        },
        positron_kernel::BootstrapKeyFailure::Entropy => BootstrapFailureCode::EntropyUnavailable,
        positron_kernel::BootstrapKeyFailure::Authentication
        | positron_kernel::BootstrapKeyFailure::InvalidInput
        | positron_kernel::BootstrapKeyFailure::LimitExceeded => BootstrapFailureCode::CorruptState,
    };
    BootstrapFailure::new(code)
}

fn catalog_failure(_failure: positron_kernel::CatalogFailure) -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable)
}
