//! Administration-owned intent and durable replay for system audit retention.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::num::NonZeroU64;

use positron_domain::identity::PrincipalId;
use positron_kernel::{
    AuditCheckpointSigner, AuditIntent, Catalog, CatalogFailureCode, CatalogObject,
    CatalogSnapshot, SystemAuditRetentionPolicy, TransactionId,
};
use sha2::{Digest, Sha256};

use crate::audit::SystemAuditRetentionAuditIntent;
use crate::{
    AdministrativeIdempotencyKey, AuthorizedContext, GovernanceAuditEntry, Identity,
    ResourceGeneration,
};

const RECEIPT_MAGIC: [u8; 8] = *b"POSARR01";
const RECEIPT_BYTES: usize = 105;
const REQUEST_DOMAIN: &[u8] = b"positron.system-audit-retention.request.v1\0";

#[derive(Clone, Copy)]
pub struct SystemAuditRetentionRequest {
    actor: AuthorizedContext,
    retained_record_limit: NonZeroU64,
    expected_generation: ResourceGeneration,
    idempotency_key: AdministrativeIdempotencyKey,
    audit_ingest_time_unix_seconds: u64,
}

impl SystemAuditRetentionRequest {
    pub fn new(
        actor: AuthorizedContext,
        retained_record_limit: NonZeroU64,
        expected_generation: ResourceGeneration,
        idempotency_key: AdministrativeIdempotencyKey,
        audit_ingest_time_unix_seconds: u64,
    ) -> Result<Self, SystemAuditRetentionAdministrationFailure> {
        if audit_ingest_time_unix_seconds == 0 {
            return Err(SystemAuditRetentionAdministrationFailure::InvalidInput);
        }
        Ok(Self {
            actor,
            retained_record_limit,
            expected_generation,
            idempotency_key,
            audit_ingest_time_unix_seconds,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemAuditRetentionUpdate {
    policy_generation: ResourceGeneration,
    retained_record_limit: NonZeroU64,
    audit_position: u64,
}

impl SystemAuditRetentionUpdate {
    #[must_use]
    pub const fn policy_generation(self) -> ResourceGeneration {
        self.policy_generation
    }
    #[must_use]
    pub const fn retained_record_limit(self) -> NonZeroU64 {
        self.retained_record_limit
    }
    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemAuditRetentionAdministrationFailure {
    InvalidInput,
    Unauthorized,
    StaleGeneration,
    IdempotencyConflict,
    CapacityExceeded,
    PersistenceUnavailable,
}

impl Display for SystemAuditRetentionAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("system audit retention administration failed")
    }
}

impl Error for SystemAuditRetentionAdministrationFailure {}

pub enum SystemAuditRetentionAdministration {}

impl SystemAuditRetentionAdministration {
    pub fn update(
        catalog: &Catalog<'_>,
        instance: positron_kernel::InstanceId,
        identity: &Identity,
        signer: &AuditCheckpointSigner,
        request: SystemAuditRetentionRequest,
    ) -> Result<SystemAuditRetentionUpdate, SystemAuditRetentionAdministrationFailure> {
        let actor = identity
            .authorize_system_audit_retention(request.actor)
            .map_err(|_| SystemAuditRetentionAdministrationFailure::Unauthorized)?;
        let digest = request_digest(actor, request);
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if let Some(receipt) = find_receipt(&snapshot, request.idempotency_key)? {
            if receipt.actor != actor
                || receipt.expected_generation != request.expected_generation
                || receipt.retained_record_limit != request.retained_record_limit
                || receipt.request_digest != digest
            {
                return Err(SystemAuditRetentionAdministrationFailure::IdempotencyConflict);
            }
            if receipt.reclamation_required {
                catalog
                    .complete_audit_retention_reclamation()
                    .map_err(map_catalog)?;
            }
            return Ok(receipt.update());
        }
        let current_generation = catalog
            .system_audit_retention_policy()
            .map_err(map_catalog)?
            .map_or(1, SystemAuditRetentionPolicy::generation);
        if current_generation != request.expected_generation.get() {
            return Err(SystemAuditRetentionAdministrationFailure::StaleGeneration);
        }
        let generation = request
            .expected_generation
            .get()
            .checked_add(1)
            .ok_or(SystemAuditRetentionAdministrationFailure::CapacityExceeded)
            .and_then(|value| {
                ResourceGeneration::new(value)
                    .map_err(|_| SystemAuditRetentionAdministrationFailure::CapacityExceeded)
            })?;
        let records = catalog.governance_audit_records().map_err(map_catalog)?;
        let limit = usize::try_from(request.retained_record_limit.get())
            .map_err(|_| SystemAuditRetentionAdministrationFailure::CapacityExceeded)?;
        let excess = records.len().saturating_add(1).saturating_sub(limit);
        let last_removed = excess.checked_sub(1).and_then(|index| records.get(index));
        let supplemental_capacity = snapshot
            .system_audit_retention_receipt_capacity(last_removed.is_some())
            .map_err(map_catalog)?;
        let migration_capacity = supplemental_capacity
            .checked_sub(1)
            .ok_or(SystemAuditRetentionAdministrationFailure::CapacityExceeded)?;
        let receipt_index = terminal_receipt_index(&snapshot)?;
        let migrated_receipts = migrate_pruned_receipts(
            &snapshot,
            &records[..excess],
            &receipt_index,
            migration_capacity,
        )?;
        let audit_position = snapshot
            .governance_audit_frontier()
            .checked_add(1)
            .ok_or(SystemAuditRetentionAdministrationFailure::CapacityExceeded)?;
        let receipt = Receipt {
            actor,
            expected_generation: request.expected_generation,
            retained_record_limit: request.retained_record_limit,
            generation,
            audit_position,
            reclamation_required: last_removed.is_some(),
            request_digest: digest,
        };
        let audit = SystemAuditRetentionAuditIntent {
            ingest_time_unix_seconds: request.audit_ingest_time_unix_seconds,
            idempotency_key: request.idempotency_key,
            actor,
            expected_generation: request.expected_generation,
            generation,
            retained_record_limit: request.retained_record_limit.get(),
            request_digest: digest,
        }
        .encode();
        catalog
            .publish_system_audit_retention_policy_with_receipt(
                TransactionId::new(request.idempotency_key.to_bytes()).map_err(map_catalog)?,
                signer,
                SystemAuditRetentionPolicy::new(
                    instance,
                    generation.get(),
                    request.retained_record_limit.get(),
                )
                .map_err(map_catalog)?,
                last_removed,
                AuditIntent::new(audit).map_err(map_catalog)?,
                {
                    let mut receipts = migrated_receipts;
                    receipts.push(receipt.object(request.idempotency_key)?);
                    receipts
                },
            )
            .map_err(map_catalog)?;
        Ok(receipt.update())
    }
}

fn migrate_pruned_receipts(
    snapshot: &CatalogSnapshot,
    records: &[positron_kernel::GovernanceAuditRecord],
    index: &TerminalReceiptIndex,
    capacity: usize,
) -> Result<Vec<CatalogObject>, SystemAuditRetentionAdministrationFailure> {
    let mut migrated = Vec::new();
    migrated
        .try_reserve_exact(records.len().min(capacity))
        .map_err(|_| SystemAuditRetentionAdministrationFailure::CapacityExceeded)?;
    for record in records {
        let entry = GovernanceAuditEntry::decode(record)
            .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?;
        if let GovernanceAuditEntry::SystemAuditRetentionUpdate(entry) = &entry {
            if has_system_retention_receipt(snapshot, entry, index)? {
                continue;
            }
            return Err(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable);
        }
        let Some(receipt) = receipt_for_pruned_entry(&entry, record.transaction())? else {
            continue;
        };
        if index.has_exact(&receipt)? {
            continue;
        }
        if migrated.len() == capacity {
            return Err(SystemAuditRetentionAdministrationFailure::CapacityExceeded);
        }
        migrated.push(receipt.object);
    }
    Ok(migrated)
}

fn has_system_retention_receipt(
    snapshot: &CatalogSnapshot,
    entry: &crate::audit::SystemAuditRetentionUpdateAuditEntry,
    index: &TerminalReceiptIndex,
) -> Result<bool, SystemAuditRetentionAdministrationFailure> {
    let Some(identity) = index.get(
        TerminalReceiptKind::SystemAuditRetention,
        entry.idempotency_key().to_bytes(),
    ) else {
        return Ok(false);
    };
    let bytes = snapshot
        .object(identity)
        .map_err(map_catalog)?
        .ok_or(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?;
    let (_, receipt) = decode_receipt(bytes)?;
    if receipt.actor != entry.actor_id()
        || receipt.expected_generation != entry.expected_generation()
        || receipt.generation != entry.generation()
        || receipt.retained_record_limit.get() != entry.retained_record_limit()
        || receipt.audit_position != entry.position()
        || receipt.request_digest != entry.request_digest()
    {
        return Err(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable);
    }
    Ok(true)
}

struct MigratedReceipt {
    object: CatalogObject,
    kind: TerminalReceiptKind,
    key: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum TerminalReceiptKind {
    SystemAuditRetention,
    TenantCreation,
    TenantDisplayName,
    CatalogFormatMigration,
    IngestPolicyActivation,
    TenantQuota,
    TenantAlias,
    TenantRetention,
    ListenerTransport,
    ApiKeyLifecycle,
    TenantLifecycle,
}

impl TerminalReceiptKind {
    const ALL: [Self; 11] = [
        Self::SystemAuditRetention,
        Self::TenantCreation,
        Self::TenantDisplayName,
        Self::CatalogFormatMigration,
        Self::IngestPolicyActivation,
        Self::TenantQuota,
        Self::TenantAlias,
        Self::TenantRetention,
        Self::ListenerTransport,
        Self::ApiKeyLifecycle,
        Self::TenantLifecycle,
    ];

    fn key(
        self,
        bytes: &[u8],
    ) -> Result<Option<[u8; 16]>, SystemAuditRetentionAdministrationFailure> {
        let key = match self {
            Self::SystemAuditRetention => {
                crate::audit::terminal_receipt_key(bytes, &[(RECEIPT_MAGIC, RECEIPT_BYTES, 8)])
            },
            Self::TenantCreation => crate::tenant_administration::retention_terminal_key(bytes),
            Self::TenantDisplayName => {
                crate::tenant_profile_administration::retention_terminal_key(bytes)
            },
            Self::CatalogFormatMigration => {
                crate::format_migration_administration::retention_terminal_key(bytes)
            },
            Self::IngestPolicyActivation => {
                crate::policy_administration::retention_terminal_key(bytes)
            },
            Self::TenantQuota => crate::quota_administration::retention_terminal_key(bytes),
            Self::TenantAlias => crate::tenant_alias_administration::retention_terminal_key(bytes),
            Self::TenantRetention => {
                crate::tenant_retention_administration::retention_terminal_key(bytes)
            },
            Self::ListenerTransport => {
                crate::listener_transport_administration::retention_terminal_key(bytes)
            },
            Self::ApiKeyLifecycle => crate::api_key_administration::retention_terminal_key(bytes),
            Self::TenantLifecycle => {
                crate::tenant_lifecycle_administration::retention_terminal_key(bytes)
            },
        };
        key.map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)
    }
}

struct TerminalReceiptIndex {
    entries: HashMap<(TerminalReceiptKind, [u8; 16]), positron_kernel::CatalogObjectId>,
}

impl TerminalReceiptIndex {
    fn get(
        &self,
        kind: TerminalReceiptKind,
        key: [u8; 16],
    ) -> Option<positron_kernel::CatalogObjectId> {
        self.entries.get(&(kind, key)).copied()
    }

    fn has_exact(
        &self,
        expected: &MigratedReceipt,
    ) -> Result<bool, SystemAuditRetentionAdministrationFailure> {
        match self.get(expected.kind, expected.key) {
            None => Ok(false),
            Some(identity) if identity == expected.object.identity() => Ok(true),
            Some(_) => Err(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable),
        }
    }
}

fn terminal_receipt_index(
    snapshot: &CatalogSnapshot,
) -> Result<TerminalReceiptIndex, SystemAuditRetentionAdministrationFailure> {
    let mut entries = HashMap::new();
    entries
        .try_reserve(snapshot.object_count())
        .map_err(|_| SystemAuditRetentionAdministrationFailure::CapacityExceeded)?;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?;
        for kind in TerminalReceiptKind::ALL {
            let Some(key) = kind.key(bytes)? else {
                continue;
            };
            if entries.insert((kind, key), identity).is_some() {
                return Err(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable);
            }
        }
    }
    Ok(TerminalReceiptIndex { entries })
}

fn receipt_for_pruned_entry(
    entry: &GovernanceAuditEntry,
    transaction: TransactionId,
) -> Result<Option<MigratedReceipt>, SystemAuditRetentionAdministrationFailure> {
    let (object, kind, key) = match entry {
        GovernanceAuditEntry::Initialization(_)
        | GovernanceAuditEntry::CatalogRootRotation(_)
        | GovernanceAuditEntry::SchemaCheckpoint(_)
        | GovernanceAuditEntry::DurableOperation(_)
        | GovernanceAuditEntry::Configuration(_)
        | GovernanceAuditEntry::TlsMaterialReload(_) => return Ok(None),
        GovernanceAuditEntry::TenantCreation(entry) => (
            crate::tenant_administration::legacy_receipt_object(entry)
                .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?,
            TerminalReceiptKind::TenantCreation,
            entry.idempotency_key().to_bytes(),
        ),
        GovernanceAuditEntry::TenantDisplayNameUpdate(entry) => (
            crate::tenant_profile_administration::legacy_receipt_object(entry)
                .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?,
            TerminalReceiptKind::TenantDisplayName,
            entry.idempotency_key().to_bytes(),
        ),
        GovernanceAuditEntry::CatalogFormatMigration(entry) => (
            crate::format_migration_administration::legacy_receipt_object(entry)
                .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?,
            TerminalReceiptKind::CatalogFormatMigration,
            entry.idempotency_key().to_bytes(),
        ),
        GovernanceAuditEntry::IngestPolicyActivation(entry) => (
            crate::policy_administration::legacy_receipt_object(entry)
                .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?,
            TerminalReceiptKind::IngestPolicyActivation,
            entry.idempotency_key().to_bytes(),
        ),
        GovernanceAuditEntry::TenantQuotaUpdate(entry) => (
            crate::quota_administration::legacy_receipt_object(entry)
                .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?,
            TerminalReceiptKind::TenantQuota,
            entry.idempotency_key().to_bytes(),
        ),
        GovernanceAuditEntry::TenantAliasBinding(entry) => (
            crate::tenant_alias_administration::legacy_receipt_object(entry)
                .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?,
            TerminalReceiptKind::TenantAlias,
            entry.idempotency_key().to_bytes(),
        ),
        GovernanceAuditEntry::TenantRetentionUpdate(entry) => (
            crate::tenant_retention_administration::legacy_receipt_object(entry)
                .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?,
            TerminalReceiptKind::TenantRetention,
            entry.idempotency_key().to_bytes(),
        ),
        GovernanceAuditEntry::ListenerTransport(entry) => {
            let key = entry
                .request_id()
                .ok_or(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?;
            if transaction.to_bytes() != key {
                return Err(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable);
            }
            (
                crate::listener_transport_administration::legacy_receipt_object(entry).map_err(
                    |_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable,
                )?,
                TerminalReceiptKind::ListenerTransport,
                key,
            )
        },
        GovernanceAuditEntry::ApiKeyLifecycle(entry) => (
            crate::api_key_administration::legacy_receipt_object(entry)
                .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?,
            TerminalReceiptKind::ApiKeyLifecycle,
            entry.idempotency_key().to_bytes(),
        ),
        GovernanceAuditEntry::TenantLifecycle(entry) => (
            crate::tenant_lifecycle_administration::legacy_receipt_object(entry)
                .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?,
            TerminalReceiptKind::TenantLifecycle,
            entry.idempotency_key().to_bytes(),
        ),
        // A system-retention record is handled above: its existing compact
        // receipt is required and validated against the typed audit entry.
        GovernanceAuditEntry::SystemAuditRetentionUpdate(_) => {
            return Err(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable);
        },
    };
    Ok(Some(MigratedReceipt { object, kind, key }))
}

#[derive(Clone, Copy)]
struct Receipt {
    actor: PrincipalId,
    expected_generation: ResourceGeneration,
    retained_record_limit: NonZeroU64,
    generation: ResourceGeneration,
    audit_position: u64,
    reclamation_required: bool,
    request_digest: [u8; 32],
}

impl Receipt {
    fn update(self) -> SystemAuditRetentionUpdate {
        SystemAuditRetentionUpdate {
            policy_generation: self.generation,
            retained_record_limit: self.retained_record_limit,
            audit_position: self.audit_position,
        }
    }

    fn object(
        self,
        idempotency_key: AdministrativeIdempotencyKey,
    ) -> Result<CatalogObject, SystemAuditRetentionAdministrationFailure> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(RECEIPT_BYTES)
            .map_err(|_| SystemAuditRetentionAdministrationFailure::CapacityExceeded)?;
        bytes.extend_from_slice(&RECEIPT_MAGIC);
        bytes.extend_from_slice(&idempotency_key.to_bytes());
        bytes.extend_from_slice(&self.actor.to_bytes());
        bytes.extend_from_slice(&self.expected_generation.get().to_be_bytes());
        bytes.extend_from_slice(&self.generation.get().to_be_bytes());
        bytes.extend_from_slice(&self.retained_record_limit.get().to_be_bytes());
        bytes.extend_from_slice(&self.audit_position.to_be_bytes());
        bytes.push(u8::from(self.reclamation_required));
        bytes.extend_from_slice(&self.request_digest);
        CatalogObject::new(bytes).map_err(map_catalog)
    }
}

fn find_receipt(
    snapshot: &CatalogSnapshot,
    key: AdministrativeIdempotencyKey,
) -> Result<Option<Receipt>, SystemAuditRetentionAdministrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(&RECEIPT_MAGIC) {
            continue;
        }
        let (stored_key, receipt) = decode_receipt(bytes)?;
        if stored_key == key && found.replace(receipt).is_some() {
            return Err(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable);
        }
    }
    Ok(found)
}

fn decode_receipt(
    bytes: &[u8],
) -> Result<(AdministrativeIdempotencyKey, Receipt), SystemAuditRetentionAdministrationFailure> {
    if bytes.len() != RECEIPT_BYTES || bytes.get(..8) != Some(RECEIPT_MAGIC.as_slice()) {
        return Err(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable);
    }
    let array16 = |start| {
        bytes
            .get(start..start + 16)
            .and_then(|value| value.try_into().ok())
            .ok_or(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)
    };
    let long = |start| {
        bytes
            .get(start..start + 8)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)
    };
    let key = AdministrativeIdempotencyKey::new(array16(8)?)
        .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?;
    let actor = PrincipalId::from_bytes(array16(24)?)
        .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?;
    let expected_generation = ResourceGeneration::new(long(40)?)
        .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?;
    let generation = ResourceGeneration::new(long(48)?)
        .map_err(|_| SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?;
    let retained_record_limit = NonZeroU64::new(long(56)?)
        .ok_or(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?;
    let audit_position = long(64)?;
    let reclamation_required = match bytes.get(72).copied() {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable),
    };
    let request_digest = bytes
        .get(73..105)
        .and_then(|value| value.try_into().ok())
        .filter(|digest: &[u8; 32]| digest.iter().any(|byte| *byte != 0))
        .ok_or(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable)?;
    if expected_generation.get().checked_add(1) != Some(generation.get()) || audit_position == 0 {
        return Err(SystemAuditRetentionAdministrationFailure::PersistenceUnavailable);
    }
    Ok((
        key,
        Receipt {
            actor,
            expected_generation,
            retained_record_limit,
            generation,
            audit_position,
            reclamation_required,
            request_digest,
        },
    ))
}

fn request_digest(actor: PrincipalId, request: SystemAuditRetentionRequest) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(REQUEST_DOMAIN);
    hash.update(request.idempotency_key.to_bytes());
    hash.update(actor.to_bytes());
    hash.update(request.expected_generation.get().to_be_bytes());
    hash.update(request.retained_record_limit.get().to_be_bytes());
    hash.finalize().into()
}

fn map_catalog(
    failure: positron_kernel::CatalogFailure,
) -> SystemAuditRetentionAdministrationFailure {
    match failure.code() {
        CatalogFailureCode::IdempotencyConflict => {
            SystemAuditRetentionAdministrationFailure::IdempotencyConflict
        },
        CatalogFailureCode::LimitExceeded | CatalogFailureCode::ResourceAdmissionRefused => {
            SystemAuditRetentionAdministrationFailure::CapacityExceeded
        },
        _ => SystemAuditRetentionAdministrationFailure::PersistenceUnavailable,
    }
}
