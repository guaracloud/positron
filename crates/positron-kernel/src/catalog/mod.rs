//! Immutable encrypted Catalog Generations and their single publication authority.

mod audit_checkpoint;
mod budget;
mod codec;
#[cfg(feature = "test-support")]
mod fixture;
mod governance_object;
mod inspection;
mod preparation;
mod recovery;
mod rotation;
mod storage;
mod types;

#[cfg(test)]
pub(crate) mod tests;

use std::collections::BTreeMap;
use std::fs::File;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use budget::{
    audit_checkpoint_resource_claim, commit_resource_claim, recovery_resource_claim,
    reserve_history, retained_artifact_bytes,
};
use codec::{
    CommitRecord, encode_commit, generation_identity, object_set_digest, prepare_audit,
    snapshot_from_record, transaction_digest,
};
use preparation::PreparedCommit;
use recovery::load_snapshot;
use recovery::recover;
use storage::{CatalogStorage, PreparedLookup};

use crate::data_protection::ControlTokenProtector;
use crate::resource_governor::CatalogWriterLease;
use crate::{
    GovernanceAuditCheckpointBinding, MaintenanceCoordinator, MaintenanceExecution,
    MaintenanceObjectId, MaintenancePreconditions, MaintenanceScope, MaintenanceTask,
    MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTrigger, RecoveryWorkClaim,
    RecoveryWorkKind, ResourceAmounts, ResourceDimension, StorageKernelResourceAuthority,
    WorkClaim, WorkKind,
};

pub use audit_checkpoint::{
    AuditCheckpointSigner, AuditRetentionAnchor, AuditRetentionTrust, GovernanceAuditCheckpoint,
    SystemAuditRetentionPolicy,
};
#[cfg(feature = "test-support")]
pub use fixture::GovernanceFixtureTarget;
pub use governance_object::{
    CatalogCredential, CatalogGovernanceObject, CatalogGovernanceVersion, CatalogLogRetentionPolicy,
};
#[cfg(feature = "test-support")]
pub use storage::{
    CatalogPublicationFault, with_catalog_generation_ambiguity_hook_after,
    with_catalog_publication_ambiguity_hook_after, with_catalog_publication_fault_after,
    with_catalog_publication_fault_sequence_after, with_catalog_publication_hook_after,
};
use types::AuditFrontier;
#[cfg(feature = "test-support")]
pub use types::GovernanceFixtureObject;
pub use types::{
    AuditIntent, CatalogCommit, CatalogFailure, CatalogFailureCode, CatalogGenerationId,
    CatalogObject, CatalogObjectId, CatalogProposal, CatalogRotation, CatalogSecret,
    CatalogSnapshot, CatalogWrappingKey, FormatEpoch, GovernanceAuditRecord, InstanceId,
    TransactionId,
};
pub(crate) use types::{MAX_CATALOG_OBJECTS, MAX_CATALOG_TOTAL_BYTES};

#[cfg(any(test, fuzzing))]
pub(crate) use storage::with_catalog_fault;

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_compaction_publication_fault<T>(enabled: bool, action: impl FnOnce() -> T) -> T {
    if enabled {
        storage::with_catalog_fault(storage::fault::CatalogFileEvent::SynchronizeCommit, action)
    } else {
        action()
    }
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
pub(crate) use storage::before_lease_marker_basis;
#[cfg(test)]
pub(crate) use storage::fault::with_catalog_fault_hook_after;

#[cfg(any(test, fuzzing))]
pub(crate) use storage::fault::CatalogFileEvent;

const MAX_RECOVERED_AUDIT_BYTES: usize = 16_777_216;
#[cfg(test)]
const MAX_GENERATIONS: usize = storage::MAX_GENERATIONS;
const MAX_RETAINED_HISTORY_BYTES: usize = 16_777_216;
const MAX_RECOVERY_MEMORY_BYTES: u64 = 70_000_000;
const MAX_RECOVERY_ITEMS: u64 = 65_540;

impl CatalogSnapshot {
    /// Returns the exact number of supplemental terminal receipts that can be
    /// included in the next system audit-retention publication. The policy,
    /// retention anchor, and reclamation receipt are replaced atomically, so
    /// they do not consume capacity from the successor proposal.
    pub fn system_audit_retention_receipt_capacity(
        &self,
        will_reclaim_audit: bool,
    ) -> Result<usize, CatalogFailure> {
        let existing_anchor = audit_checkpoint::retention_anchor(self)?.is_some();
        let removed = self
            .plaintext_objects()
            .filter(|object| {
                AuditRetentionAnchor::is_encoded(object)
                    || SystemAuditRetentionPolicy::is_encoded(object)
                    || audit_checkpoint::AuditRetentionReclamationReceipt::is_encoded(object)
            })
            .count();
        let retained = self
            .plaintext_object_count()
            .checked_sub(removed)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        let replacement = 1_usize
            .checked_add(usize::from(existing_anchor || will_reclaim_audit).saturating_mul(2))
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        MAX_CATALOG_OBJECTS
            .checked_sub(retained)
            .and_then(|capacity| capacity.checked_sub(replacement))
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))
    }
}

/// The only Release 1 authority that publishes Catalog Generations.
pub struct Catalog<'authority> {
    authority: &'authority StorageKernelResourceAuthority,
    _writer: CatalogWriterLease<'authority>,
    instance: InstanceId,
    secret: Mutex<CatalogSecret>,
    storage: CatalogStorage,
    operation: Mutex<()>,
    pub(crate) export_output_operation: Mutex<()>,
    state: Mutex<CatalogState>,
}

/// The caller-owned inputs that must reach one joint system audit-retention
/// Catalog publication, including its coordinator-owned reclamation draft.
pub struct SystemAuditRetentionPublication<'a> {
    pub policy: SystemAuditRetentionPolicy,
    pub last_removed: Option<&'a GovernanceAuditRecord>,
    pub audit: AuditIntent,
    pub receipts: Vec<CatalogObject>,
    pub coordinator: &'a MaintenanceCoordinator,
    pub submitted_at: u64,
}

struct CatalogState {
    current: CatalogSnapshot,
    audit: Vec<GovernanceAuditRecord>,
    audit_checkpoint: Option<GovernanceAuditCheckpoint>,
    transactions: BTreeMap<TransactionId, TransactionOutcome>,
    retained_history_bytes: usize,
}

/// One immutable, authenticated Catalog generation with its visible audit chain.
///
/// This read-only view never acquires the Catalog writer lease. Callers that
/// intend to publish must still open [`Catalog`] after completing admission
/// barriers and revalidate against that writer-owned generation.
#[derive(Clone)]
pub struct CatalogReadView {
    snapshot: CatalogSnapshot,
    audit: Vec<GovernanceAuditRecord>,
    audit_checkpoint: Option<GovernanceAuditCheckpoint>,
    audit_retention_anchor: Option<AuditRetentionAnchor>,
    audit_retention_trust: Option<AuditRetentionTrust>,
}

impl CatalogReadView {
    #[must_use]
    pub const fn snapshot(&self) -> &CatalogSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub fn governance_audit_records(&self) -> &[GovernanceAuditRecord] {
        &self.audit
    }

    /// Returns the most recent durable signed audit-chain anchor, when one has
    /// been published by the system maintenance path.
    pub fn latest_audit_checkpoint(
        &self,
    ) -> Result<Option<GovernanceAuditCheckpoint>, CatalogFailure> {
        Ok(self.audit_checkpoint.clone())
    }

    /// Returns the authenticated Catalog-reachable retention boundary, if the
    /// system policy has published one.
    #[must_use]
    pub fn audit_retention_anchor(&self) -> Option<&AuditRetentionAnchor> {
        self.audit_retention_anchor.as_ref()
    }

    /// Verifies a future physically retained suffix against this view's
    /// Catalog-reachable boundary and trusted system policy.
    pub fn verify_retained_audit_suffix(
        &self,
        records: &[GovernanceAuditRecord],
    ) -> Result<(), CatalogFailure> {
        let trust = self
            .audit_retention_trust
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        let frontier = self.snapshot.governance_audit_frontier();
        let anchor = self
            .audit_retention_anchor
            .as_ref()
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        if records.last().map(GovernanceAuditRecord::position) != Some(frontier)
            && !(records.is_empty() && anchor.position() == frontier)
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        AuditRetentionAnchor::verify_retained_suffix(records, Some(anchor), trust)
    }

    /// Verifies the complete visible audit chain and an optional trusted
    /// signed checkpoint without granting any mutation capability.
    pub fn verify_audit_chain(
        &self,
        trusted_public_key: [u8; 32],
        checkpoint: Option<&GovernanceAuditCheckpoint>,
    ) -> Result<(), CatalogFailure> {
        audit_checkpoint::verify_chain(&self.audit, trusted_public_key, checkpoint)
    }
}

#[derive(Clone)]
struct TransactionOutcome {
    digest: [u8; 32],
    record: CommitRecord,
    audit: Option<GovernanceAuditRecord>,
}

/// Resolution of a transaction-owned, unpublished administrative proposal.
pub enum PreparedTransactionResolution {
    Absent,
    Resumed(CatalogCommit),
    Unavailable,
}

/// Verified read-only view of one transaction-owned administrative proposal.
///
/// This is intentionally limited to the immutable successor snapshot. Callers
/// use it to stage external admission before asking [`Catalog`] to publish the
/// same exact prepared transaction; it exposes neither prepared bytes nor any
/// secret material.
#[derive(Debug)]
pub enum PreparedTransactionInspection {
    Absent,
    Inspected(CatalogSnapshot),
    Unavailable,
}

impl std::fmt::Debug for Catalog<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Catalog { <storage-and-key-redacted> }")
    }
}

impl<'authority> Catalog<'authority> {
    /// Builds the sole durable coordinator task contract for a checkpoint of
    /// one already-visible Governance Audit frontier.
    pub fn governance_audit_checkpoint_task(
        frontier: &GovernanceAuditRecord,
        integrity_key_fingerprint: [u8; 32],
    ) -> Result<(MaintenanceTask, GovernanceAuditCheckpointBinding), CatalogFailure> {
        let binding = GovernanceAuditCheckpointBinding::new(
            frontier.position(),
            frontier.record_hash(),
            integrity_key_fingerprint,
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        let mut digest = Sha256::new();
        digest.update(b"positron-governance-audit-checkpoint-task-v1\\0");
        digest.update(frontier.position().to_be_bytes());
        digest.update(frontier.record_hash());
        digest.update(integrity_key_fingerprint);
        let digest = digest.finalize();
        let identity = MaintenanceTaskId::new(
            digest
                .get(..16)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        let task = MaintenanceTask::with_contract(
            identity,
            MaintenanceTaskClass::GovernanceAuditCheckpoint,
            MaintenanceScope::System,
            MaintenanceTrigger::Event,
            // The signed record is the complete durable frontier contract.
            // An incidental Catalog generation change must not turn a retry of
            // that same frontier into a conflicting task.
            MaintenancePreconditions::new(frontier.position(), 1)
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::InvalidInput))?,
            vec![
                MaintenanceObjectId::new(frontier.record_hash())
                    .map_err(|_| CatalogFailure::new(CatalogFailureCode::InvalidInput))?,
            ],
            vec![
                MaintenanceObjectId::new(integrity_key_fingerprint)
                    .map_err(|_| CatalogFailure::new(CatalogFailureCode::InvalidInput))?,
            ],
            audit_checkpoint_resource_claim(),
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        Ok((task, binding))
    }

    pub(crate) const fn control_tokens(&self) -> ControlTokenProtector<'_> {
        ControlTokenProtector::new(&self.secret)
    }
    pub(crate) const fn instance(&self) -> InstanceId {
        self.instance
    }

    /// Opens and recovers the Catalog under the sole Storage Kernel resource authority.
    pub fn open(
        authority: &'authority StorageKernelResourceAuthority,
        instance: InstanceId,
        secret: CatalogSecret,
    ) -> Result<Self, CatalogFailure> {
        let writer = authority
            .acquire_catalog_writer()
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let recovery_claim =
            RecoveryWorkClaim::system(RecoveryWorkKind::Repair, recovery_resource_claim())
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let _reservation = authority
            .recovery()
            .reserve(recovery_claim)
            .map_err(CatalogFailure::admission)?;
        let volume = authority
            .primary_data_volume()
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::ResourceAdmissionRefused))?;
        let storage = CatalogStorage::open(volume)?;
        let state = recover(&storage, &secret, instance)?;
        Ok(Self {
            authority,
            _writer: writer,
            instance,
            secret: Mutex::new(secret),
            storage,
            operation: Mutex::new(()),
            export_output_operation: Mutex::new(()),
            state: Mutex::new(state),
        })
    }

    /// Reads the highest complete authenticated generation without acquiring
    /// the Catalog Writer lease.
    pub fn read_current_snapshot(
        authority: &'authority StorageKernelResourceAuthority,
        instance: InstanceId,
        secret: CatalogSecret,
    ) -> Result<CatalogSnapshot, CatalogFailure> {
        Ok(Self::read_current_view(authority, instance, secret)?.snapshot)
    }

    /// Reads the highest complete authenticated generation and its visible
    /// audit records without acquiring the Catalog writer lease.
    pub fn read_current_view(
        authority: &'authority StorageKernelResourceAuthority,
        instance: InstanceId,
        secret: CatalogSecret,
    ) -> Result<CatalogReadView, CatalogFailure> {
        let recovery_claim =
            RecoveryWorkClaim::system(RecoveryWorkKind::Repair, recovery_resource_claim())
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let _reservation = authority
            .recovery()
            .reserve(recovery_claim)
            .map_err(CatalogFailure::admission)?;
        let volume = authority
            .primary_data_volume()
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::ResourceAdmissionRefused))?;
        let root = volume
            ._root
            .try_clone()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        let storage = CatalogStorage::inspect(&root)?;
        let recovered = recover(&storage, &secret, instance)?;
        let audit_retention_anchor = audit_checkpoint::retention_anchor(&recovered.current)?;
        let audit_retention_trust = audit_retention_anchor
            .as_ref()
            .map(|anchor| {
                let trust =
                    audit_checkpoint::retention_trust(&recovered.current, anchor.instance())?;
                anchor.verify(trust)?;
                Ok(trust)
            })
            .transpose()?;
        Ok(CatalogReadView {
            snapshot: recovered.current,
            audit: recovered.audit,
            audit_checkpoint: recovered.audit_checkpoint,
            audit_retention_anchor,
            audit_retention_trust,
        })
    }

    /// Reports whether an unpublished prepared administrative transaction defers
    /// startup publications until its owner resolves it or it fails closed.
    pub fn has_prepared_transaction(&self) -> Result<bool, CatalogFailure> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        self.storage
            .has_prepared_transaction(&secret, self.instance, state.current.identity())
    }

    /// Pins the complete currently published immutable generation.
    pub fn pin(&self) -> Result<CatalogSnapshot, CatalogFailure> {
        self.state
            .lock()
            .map(|state| state.current.clone())
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))
    }

    pub(crate) fn export_output_root(&self) -> Result<File, CatalogFailure> {
        self.authority
            .primary_data_volume()
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::ResourceAdmissionRefused))?
            ._root
            .try_clone()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))
    }

    pub(crate) fn protect_export_output(
        &self,
        content_identity: [u8; 32],
        format_epoch: FormatEpoch,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CatalogFailure> {
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        storage::artifact::protect_export_output(
            &secret,
            self.instance,
            content_identity,
            format_epoch,
            plaintext,
        )
    }

    pub(crate) fn open_export_output(
        &self,
        content_identity: [u8; 32],
        format_epoch: FormatEpoch,
        encoded: &[u8],
    ) -> Result<Vec<u8>, CatalogFailure> {
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        storage::artifact::open_export_output(
            &secret,
            self.instance,
            content_identity,
            format_epoch,
            encoded,
        )
    }

    pub(crate) fn reserve_export_output(
        &self,
        tenant: positron_domain::identity::TenantId,
        payload_bytes: usize,
        durable_bytes: usize,
    ) -> Result<crate::ResourceReservation<'_>, CatalogFailure> {
        let payload = u64::try_from(payload_bytes)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let durable = u64::try_from(durable_bytes)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let amounts = ResourceAmounts::new([payload, 0, 1, payload, 1, 0, 0, 1, 0, 1, durable]);
        let claim = WorkClaim::tenant(tenant, WorkKind::InteractiveQueryTail, amounts)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        self.authority
            .governor()
            .reserve(claim)
            .map_err(CatalogFailure::admission)
    }

    /// Publishes one complete Catalog Proposal and optional Administration-owned audit intent.
    pub fn commit(
        &self,
        expected: CatalogGenerationId,
        proposal: CatalogProposal,
        audit: Option<AuditIntent>,
    ) -> Result<CatalogCommit, CatalogFailure> {
        if !proposal.format_epoch.is_catalog_writable() {
            return Err(CatalogFailure::new(CatalogFailureCode::UnsupportedFormat));
        }
        let durability_claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            commit_resource_claim(&proposal, audit.as_ref())?,
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let _reservation = self
            .authority
            .recovery()
            .reserve(durability_claim)
            .map_err(CatalogFailure::admission)?;
        let result = {
            let _operation = self
                .operation
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            self.commit_unreserved(expected, proposal, audit, None)
        };
        drop(_reservation);
        #[cfg(any(test, feature = "test-support"))]
        if result
            .as_ref()
            .is_err_and(|failure| failure.code() == CatalogFailureCode::StorageUnavailable)
        {
            storage::after_ambiguous_publication(self);
        }
        result
    }

    pub(crate) fn commit_admitted_maintenance_task_state(
        &self,
        expected: CatalogGenerationId,
        proposal: CatalogProposal,
        execution: &MaintenanceExecution<'_>,
    ) -> Result<CatalogCommit, CatalogFailure> {
        let required = commit_resource_claim(&proposal, None)?;
        if ResourceDimension::ALL.iter().any(|dimension| {
            execution.reservation().granted().get(*dimension) < required.get(*dimension)
        }) {
            return Err(CatalogFailure::new(
                CatalogFailureCode::ResourceAdmissionRefused,
            ));
        }
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        self.commit_unreserved(expected, proposal, None, None)
    }

    /// Publishes an administrative proposal whose retry identity is fixed before
    /// entropy-derived proposal contents are generated.
    pub fn commit_prepared(
        &self,
        expected: CatalogGenerationId,
        proposal: CatalogProposal,
        audit: AuditIntent,
        request_digest: [u8; 32],
    ) -> Result<CatalogCommit, CatalogFailure> {
        let durability_claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            commit_resource_claim(&proposal, Some(&audit))?,
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let _reservation = self
            .authority
            .recovery()
            .reserve(durability_claim)
            .map_err(CatalogFailure::admission)?;
        let result = {
            let _operation = self
                .operation
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            self.commit_unreserved(expected, proposal, Some(audit), Some(request_digest))
        };
        drop(_reservation);
        result
    }

    /// Resolves an unpublished administrative transaction without accepting a
    /// replacement proposal for its transaction identity.
    pub fn resume_prepared(
        &self,
        transaction: TransactionId,
        request_digest: [u8; 32],
    ) -> Result<PreparedTransactionResolution, CatalogFailure> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let recovered = recover(&self.storage, &secret, self.instance)?;
        if recovered.current.number() > state.current.number() {
            *state = recovered;
        }
        match self
            .storage
            .prepared_transaction(&secret, self.instance, transaction)?
        {
            PreparedLookup::Absent => Ok(PreparedTransactionResolution::Absent),
            PreparedLookup::Unavailable => Ok(PreparedTransactionResolution::Unavailable),
            PreparedLookup::Found {
                transaction,
                prepared,
            } => {
                if prepared.request_digest != request_digest {
                    return Err(CatalogFailure::new(CatalogFailureCode::IdempotencyConflict));
                }
                let Some(snapshot) = self.prepared_snapshot(&state, &secret, &prepared)? else {
                    return Ok(PreparedTransactionResolution::Unavailable);
                };
                let additional_history_bytes =
                    retained_artifact_bytes(prepared.encoded_commit.len())?
                        .checked_add(storage::MARKER_BYTES)
                        .and_then(|bytes| {
                            bytes.checked_add(
                                retained_artifact_bytes(prepared.encoded_audit.len()).ok()?,
                            )
                        })
                        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
                reserve_history(
                    state.retained_history_bytes,
                    additional_history_bytes,
                    prepared.record.number,
                )?;
                self.storage.publish_commit(
                    &transaction,
                    &secret,
                    self.instance,
                    prepared.record.generation,
                    &prepared.encoded_commit,
                )?;
                self.storage.publish_marker(
                    &transaction,
                    &secret,
                    prepared.record.number,
                    prepared.record.generation,
                )?;
                state.audit.push(prepared.audit.clone());
                state.transactions.insert(
                    prepared.record.transaction,
                    TransactionOutcome {
                        digest: prepared.record.transaction_digest,
                        record: prepared.record.clone(),
                        audit: Some(prepared.audit.clone()),
                    },
                );
                state.current = snapshot.clone();
                state.retained_history_bytes = state
                    .retained_history_bytes
                    .checked_add(additional_history_bytes)
                    .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
                Ok(PreparedTransactionResolution::Resumed(CatalogCommit {
                    snapshot,
                    audit: Some(prepared.audit),
                }))
            },
        }
    }

    /// Resolves a transaction already visible in the authenticated Catalog.
    /// This is intentionally read-only with respect to proposal generation and
    /// lets an administrative caller recover an acknowledgement-lost commit.
    pub fn committed_transaction(
        &self,
        transaction: TransactionId,
    ) -> Result<Option<CatalogCommit>, CatalogFailure> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let recovered = recover(&self.storage, &secret, self.instance)?;
        if recovered.current.number() > state.current.number() {
            *state = recovered;
        }
        let Some(outcome) = state.transactions.get(&transaction) else {
            return Ok(None);
        };
        let snapshot = load_snapshot(&self.storage, &secret, self.instance, &outcome.record)?;
        Ok(Some(CatalogCommit {
            snapshot,
            audit: outcome.audit.clone(),
        }))
    }

    /// Inspects one exact unpublished proposal without making it visible.
    ///
    /// The request digest, predecessor, audit frontier, every staged object,
    /// and the staged audit entry must verify exactly as they do for
    /// [`Self::resume_prepared`]. A changed or advanced proposal is never
    /// surfaced as a candidate for external admission.
    pub fn inspect_prepared(
        &self,
        transaction: TransactionId,
        request_digest: [u8; 32],
    ) -> Result<PreparedTransactionInspection, CatalogFailure> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let recovered = recover(&self.storage, &secret, self.instance)?;
        if recovered.current.number() > state.current.number() {
            *state = recovered;
        }
        match self
            .storage
            .prepared_transaction(&secret, self.instance, transaction)?
        {
            PreparedLookup::Absent => Ok(PreparedTransactionInspection::Absent),
            PreparedLookup::Unavailable => Ok(PreparedTransactionInspection::Unavailable),
            PreparedLookup::Found { prepared, .. } => {
                if prepared.request_digest != request_digest {
                    return Err(CatalogFailure::new(CatalogFailureCode::IdempotencyConflict));
                }
                Ok(match self.prepared_snapshot(&state, &secret, &prepared)? {
                    Some(snapshot) => PreparedTransactionInspection::Inspected(snapshot),
                    None => PreparedTransactionInspection::Unavailable,
                })
            },
        }
    }

    fn prepared_snapshot(
        &self,
        state: &CatalogState,
        secret: &CatalogSecret,
        prepared: &PreparedCommit,
    ) -> Result<Option<CatalogSnapshot>, CatalogFailure> {
        let audit_frontier = state.current.0.audit_frontier;
        if prepared.record.predecessor != state.current.identity()
            || prepared.record.number
                != state
                    .current
                    .number()
                    .checked_add(1)
                    .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?
            || prepared.audit.position
                != audit_frontier
                    .position
                    .checked_add(1)
                    .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?
            || prepared.audit.predecessor_hash != audit_frontier.hash
        {
            return Ok(None);
        }
        for object in &prepared.record.objects {
            self.storage.read_object(
                secret,
                self.instance,
                *object,
                prepared.record.format_epoch,
            )?;
        }
        if self.storage.read_audit(
            secret,
            self.instance,
            prepared.audit.position,
            prepared.audit.hash,
        )? != prepared.encoded_audit
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        load_snapshot(&self.storage, secret, self.instance, &prepared.record).map(Some)
    }

    fn commit_unreserved(
        &self,
        expected: CatalogGenerationId,
        proposal: CatalogProposal,
        audit: Option<AuditIntent>,
        prepared_request: Option<[u8; 32]>,
    ) -> Result<CatalogCommit, CatalogFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let mut object_ids = Vec::new();
        object_ids
            .try_reserve_exact(proposal.objects.len())
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ResourceAdmissionRefused))?;
        for object in &proposal.objects {
            object_ids.push(object.identity());
        }
        let audit_intent = audit.as_ref().map(|intent| intent.0.as_slice());
        let digest = transaction_digest(proposal.format_epoch, &object_ids, audit_intent)?;
        // Resolve an earlier acknowledgement-ambiguous marker publication before
        // evaluating idempotency or the expected-generation precondition.
        let recovered = recover(&self.storage, &secret, self.instance)?;
        if recovered.current.number() > state.current.number() {
            *state = recovered;
        }

        if let Some(outcome) = state.transactions.get(&proposal.transaction) {
            if outcome.digest != digest {
                return Err(CatalogFailure::new(CatalogFailureCode::IdempotencyConflict));
            }
            self.storage.confirm_publication(
                &secret,
                self.instance,
                &outcome.record,
                outcome.audit.as_ref(),
            )?;
            return Ok(CatalogCommit {
                snapshot: load_snapshot(&self.storage, &secret, self.instance, &outcome.record)?,
                audit: outcome.audit.clone(),
            });
        }
        if expected != state.current.identity() {
            return Err(CatalogFailure::stale(state.current.identity()));
        }

        let number = state
            .current
            .number()
            .checked_add(1)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let prepared_audit = match audit.as_ref() {
            Some(intent) => Some(prepare_audit(
                state.current.0.audit_frontier,
                proposal.transaction,
                &intent.0,
            )?),
            None => None,
        };
        let audit_frontier =
            prepared_audit
                .as_ref()
                .map_or(state.current.0.audit_frontier, |(record, _)| {
                    AuditFrontier {
                        position: record.position,
                        hash: record.hash,
                    }
                });
        let mut record = CommitRecord {
            generation: CatalogGenerationId::ORIGIN,
            number,
            predecessor: state.current.identity(),
            instance: self.instance,
            format_epoch: proposal.format_epoch,
            transaction: proposal.transaction,
            transaction_digest: digest,
            object_set_digest: object_set_digest(&object_ids)?,
            audit_frontier,
            objects: object_ids,
        };
        let encoded_commit = encode_commit(&record);
        record.generation = generation_identity(&encoded_commit)?;
        let additional_history_bytes = retained_artifact_bytes(encoded_commit.len())?
            .checked_add(storage::MARKER_BYTES)
            .and_then(|bytes| {
                prepared_audit
                    .as_ref()
                    .and_then(|(_, encoded)| {
                        bytes.checked_add(retained_artifact_bytes(encoded.len()).ok()?)
                    })
                    .or_else(|| prepared_audit.is_none().then_some(bytes))
            })
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        reserve_history(
            state.retained_history_bytes,
            additional_history_bytes,
            number,
        )?;
        let transaction = match prepared_request {
            Some(request_digest) => {
                let (audit, encoded_audit) = prepared_audit
                    .as_ref()
                    .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
                let prepared = PreparedCommit::new(
                    request_digest,
                    record.clone(),
                    encoded_commit.clone(),
                    audit.clone(),
                    encoded_audit.clone(),
                )?;
                self.storage
                    .prepare_transaction(&secret, self.instance, &prepared)?
            },
            None => self
                .storage
                .open_transaction(proposal.transaction, digest)?,
        };

        let mut objects = BTreeMap::new();
        for object in proposal.objects {
            self.storage.publish_object(
                &transaction,
                &secret,
                self.instance,
                object.identity,
                proposal.format_epoch,
                &object.plaintext,
            )?;
            objects.insert(object.identity, Arc::from(object.plaintext));
        }
        if let Some((record, encoded)) = &prepared_audit {
            self.storage
                .publish_audit(&transaction, &secret, self.instance, record, encoded)?;
        }

        self.storage.publish_commit(
            &transaction,
            &secret,
            self.instance,
            record.generation,
            &encoded_commit,
        )?;
        self.storage
            .publish_marker(&transaction, &secret, number, record.generation)?;

        let snapshot = snapshot_from_record(&record, objects);
        let visible_audit = prepared_audit.map(|(record, _)| record);
        if let Some(record) = &visible_audit {
            state.audit.push(record.clone());
        }
        state.transactions.insert(
            proposal.transaction,
            TransactionOutcome {
                digest,
                record,
                audit: visible_audit.clone(),
            },
        );
        state.current = snapshot.clone();
        state.retained_history_bytes = state
            .retained_history_bytes
            .checked_add(additional_history_bytes)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        Ok(CatalogCommit {
            snapshot,
            audit: visible_audit,
        })
    }

    /// Returns the complete visible Governance Audit Record chain.
    pub fn governance_audit_records(&self) -> Result<Vec<GovernanceAuditRecord>, CatalogFailure> {
        self.state
            .lock()
            .map(|state| state.audit.clone())
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))
    }

    /// Returns the most recent durable signed audit-chain anchor published by
    /// the system maintenance path.
    pub fn latest_audit_checkpoint(
        &self,
    ) -> Result<Option<GovernanceAuditCheckpoint>, CatalogFailure> {
        self.state
            .lock()
            .map(|state| state.audit_checkpoint.clone())
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))
    }

    /// Returns the current Administration-owned system audit-retention policy.
    pub fn system_audit_retention_policy(
        &self,
    ) -> Result<Option<SystemAuditRetentionPolicy>, CatalogFailure> {
        audit_checkpoint::retention_policy(&self.pin()?)
    }

    /// Persists the exact signed Governance Audit frontier admitted by the
    /// sole Maintenance Coordinator. The execution's reservation is the only
    /// capacity authority for this write; this Catalog path never self-admits.
    pub fn publish_admitted_audit_checkpoint(
        &self,
        execution: &MaintenanceExecution<'_>,
        signer: &AuditCheckpointSigner,
        integrity_key_fingerprint: [u8; 32],
    ) -> Result<GovernanceAuditCheckpoint, CatalogFailure> {
        if execution.task().class() != MaintenanceTaskClass::GovernanceAuditCheckpoint {
            return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
        }
        let binding =
            GovernanceAuditCheckpointBinding::from_checkpoint(execution.task_checkpoint())
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        if execution.task().inputs().len() != 1
            || execution.task().inputs()[0].to_bytes() != binding.record_hash()
            || execution.task().outputs().len() != 1
            || execution.task().outputs()[0].to_bytes() != binding.integrity_key_fingerprint()
        {
            return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
        }
        let snapshot = self.pin()?;
        let (_, governance) = snapshot.governance_object()?;
        if binding.integrity_key_fingerprint() != integrity_key_fingerprint
            || binding.integrity_key_fingerprint() != governance.integrity_key_fingerprint()
            || signer.public_key() != governance.integrity_public_key()
        {
            return Err(CatalogFailure::new(
                CatalogFailureCode::AuthenticationFailed,
            ));
        }
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let frontier = state
            .audit
            .iter()
            .find(|record| {
                record.position() == binding.position()
                    && record.record_hash() == binding.record_hash()
            })
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        if let Some(existing) = state.audit_checkpoint.as_ref()
            && existing.position() == frontier.position()
            && existing.record_hash() == frontier.record_hash()
        {
            existing.verify(signer.public_key())?;
            return Ok(existing.clone());
        }
        let checkpoint = GovernanceAuditCheckpoint::create(signer, self.instance, frontier)?;
        self.storage
            .publish_audit_checkpoint(&secret, self.instance, &checkpoint)?;
        if state
            .audit_checkpoint
            .as_ref()
            .is_none_or(|current| checkpoint.position() > current.position())
        {
            state.audit_checkpoint = Some(checkpoint.clone());
        }
        Ok(checkpoint)
    }

    #[cfg(test)]
    pub(crate) fn publish_audit_checkpoint_for_test(
        &self,
        signer: &AuditCheckpointSigner,
    ) -> Result<GovernanceAuditCheckpoint, CatalogFailure> {
        let claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            audit_checkpoint_resource_claim(),
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let _reservation = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(CatalogFailure::admission)?;
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let frontier = state
            .audit
            .last()
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        if let Some(existing) = state.audit_checkpoint.as_ref()
            && existing.position() == frontier.position()
            && existing.record_hash() == frontier.record_hash()
        {
            existing.verify(signer.public_key())?;
            return Ok(existing.clone());
        }
        let checkpoint = GovernanceAuditCheckpoint::create(signer, self.instance, frontier)?;
        self.storage
            .publish_audit_checkpoint(&secret, self.instance, &checkpoint)?;
        state.audit_checkpoint = Some(checkpoint.clone());
        Ok(checkpoint)
    }

    /// Publishes one signed, Catalog-reachable predecessor boundary for a
    /// later audit-retention reclamation. This publication keeps every audit
    /// record and Catalog generation reachable; physical pruning remains a
    /// separate receipt-aware lifecycle operation.
    pub fn publish_audit_retention_anchor(
        &self,
        transaction: TransactionId,
        signer: &AuditCheckpointSigner,
        last_removed: &GovernanceAuditRecord,
    ) -> Result<AuditRetentionAnchor, CatalogFailure> {
        let basis = self.pin()?;
        let trust = audit_checkpoint::retention_trust(&basis, self.instance)?;
        let records = self.governance_audit_records()?;
        if !records.iter().any(|record| {
            record.position == last_removed.position && record.hash == last_removed.hash
        }) {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        let anchor = AuditRetentionAnchor::create(signer, trust, last_removed)?;
        if let Some(existing) = audit_checkpoint::retention_anchor(&basis)? {
            if existing == anchor {
                return Ok(existing);
            }
            if existing.position() > anchor.position() {
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            }
        }
        let capacity = basis
            .plaintext_object_count()
            .checked_add(1)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(capacity)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        for identity in basis.object_identities() {
            let object = basis
                .object(identity)?
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
            if AuditRetentionAnchor::is_encoded(object) {
                AuditRetentionAnchor::decode(object)?;
                continue;
            }
            objects.push(CatalogObject::new(object.to_vec())?);
        }
        objects.push(CatalogObject::new(anchor.encode())?);
        let format_epoch = basis
            .format_epoch()
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::UnsupportedFormat))?;
        let proposal = CatalogProposal::new(transaction, format_epoch, objects)?;
        let durability_claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            commit_resource_claim(&proposal, None)?,
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let reservation = self
            .authority
            .recovery()
            .reserve(durability_claim)
            .map_err(CatalogFailure::admission)?;
        let result = {
            let _operation = self
                .operation
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            self.commit_unreserved(basis.identity(), proposal, None, None)
        };
        drop(reservation);
        #[cfg(any(test, feature = "test-support"))]
        if result
            .as_ref()
            .is_err_and(|failure| failure.code() == CatalogFailureCode::StorageUnavailable)
        {
            storage::after_ambiguous_publication(self);
        }
        result?;
        Ok(anchor)
    }

    /// Atomically publishes an Administration-owned system audit-retention
    /// policy successor and its rebound signed anchor in one joint-audited
    /// Catalog generation. This is the only supported policy-generation
    /// transition: replacing a policy object without its matching anchor
    /// deliberately fences recovery.
    pub fn publish_system_audit_retention_policy(
        &self,
        transaction: TransactionId,
        signer: &AuditCheckpointSigner,
        policy: SystemAuditRetentionPolicy,
        last_removed: &GovernanceAuditRecord,
        audit: AuditIntent,
    ) -> Result<AuditRetentionAnchor, CatalogFailure> {
        let coordinator = MaintenanceCoordinator::new();
        self.publish_system_audit_retention_policy_with_receipt(
            transaction,
            signer,
            SystemAuditRetentionPublication {
                policy,
                last_removed: Some(last_removed),
                audit,
                receipts: Vec::new(),
                coordinator: &coordinator,
                submitted_at: 0,
            },
        )?
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
    }

    /// Publishes a system retention successor together with an Administration
    /// receipts. The receipts are opaque immutable objects retained across later
    /// policy replacements; they never grant Catalog mutation authority. The
    /// administration layer may also atomically migrate compact terminal replay
    /// receipts for records about to be reclaimed.
    pub fn publish_system_audit_retention_policy_with_receipt(
        &self,
        transaction: TransactionId,
        signer: &AuditCheckpointSigner,
        publication: SystemAuditRetentionPublication<'_>,
    ) -> Result<Option<AuditRetentionAnchor>, CatalogFailure> {
        let basis = self.pin()?;
        let trust = audit_checkpoint::retention_trust_for_policy(
            &basis,
            self.instance,
            publication.policy,
        )?;
        let records = self.governance_audit_records()?;
        let anchor = match publication.last_removed {
            Some(record) => {
                if !records.iter().any(|candidate| {
                    candidate.position == record.position && candidate.hash == record.hash
                }) {
                    return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
                }
                Some(AuditRetentionAnchor::create(signer, trust, record)?)
            },
            None => audit_checkpoint::retention_anchor(&basis)?
                .as_ref()
                .map(|previous| previous.rebind(signer, trust))
                .transpose()?,
        };
        let queued_reclamation = anchor
            .as_ref()
            .map(|anchor| {
                Self::audit_retention_reclamation_task(anchor).and_then(|task| {
                    publication
                        .coordinator
                        .prepare_catalog_reclamation(task, publication.submitted_at)
                        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))
                })
            })
            .transpose()?;
        let capacity = basis
            .plaintext_object_count()
            .checked_add(4)
            .and_then(|value| value.checked_add(publication.receipts.len()))
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(capacity)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        for identity in basis.object_identities() {
            let object = basis
                .object(identity)?
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
            if AuditRetentionAnchor::is_encoded(object)
                || SystemAuditRetentionPolicy::is_encoded(object)
                || audit_checkpoint::AuditRetentionReclamationReceipt::is_encoded(object)
            {
                continue;
            }
            objects.push(CatalogObject::new(object.to_vec())?);
        }
        objects.push(publication.policy.into_catalog_object()?);
        if let Some(anchor) = &anchor {
            objects.push(CatalogObject::new(anchor.encode())?);
            objects.push(CatalogObject::new(
                audit_checkpoint::AuditRetentionReclamationReceipt::new(anchor).encode(),
            )?);
        }
        if let Some(queued) = &queued_reclamation {
            objects.push(
                queued
                    .catalog_object()
                    .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
            );
        }
        for receipt in publication.receipts {
            objects.push(receipt);
        }
        let format_epoch = basis
            .format_epoch()
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::UnsupportedFormat))?;
        let proposal = CatalogProposal::new(transaction, format_epoch, objects)?;
        let durability_claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            commit_resource_claim(&proposal, Some(&publication.audit))?,
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let reservation = self
            .authority
            .recovery()
            .reserve(durability_claim)
            .map_err(CatalogFailure::admission)?;
        let result = {
            let _operation = self
                .operation
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            self.commit_unreserved(basis.identity(), proposal, Some(publication.audit), None)
        };
        drop(reservation);
        #[cfg(any(test, feature = "test-support"))]
        if result
            .as_ref()
            .is_err_and(|failure| failure.code() == CatalogFailureCode::StorageUnavailable)
        {
            storage::after_ambiguous_publication(self);
        }
        if let Err(failure) = result {
            if let Some(queued) = queued_reclamation {
                queued.discard(publication.coordinator);
            }
            return Err(failure);
        }
        if let Some(queued) = queued_reclamation {
            queued
                .install(publication.coordinator)
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        }
        Ok(anchor)
    }

    fn audit_retention_reclamation_task(
        anchor: &AuditRetentionAnchor,
    ) -> Result<MaintenanceTask, CatalogFailure> {
        let anchor_object = CatalogObject::new(anchor.encode())?;
        let receipt_object = CatalogObject::new(
            audit_checkpoint::AuditRetentionReclamationReceipt::new(anchor).encode(),
        )?;
        let mut digest = Sha256::new();
        digest.update(b"positron.audit-retention-reclamation-task.v1\0");
        digest.update(anchor_object.identity().to_bytes());
        digest.update(receipt_object.identity().to_bytes());
        let bytes: [u8; 16] = digest
            .finalize()
            .get(..16)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        MaintenanceTask::with_contract(
            MaintenanceTaskId::new(bytes)
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
            MaintenanceTaskClass::CatalogReclamation,
            MaintenanceScope::System,
            MaintenanceTrigger::Event,
            MaintenancePreconditions::new(anchor.system_policy_generation(), 1)
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
            vec![
                MaintenanceObjectId::new(anchor_object.identity().to_bytes())
                    .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
            ],
            vec![
                MaintenanceObjectId::new(receipt_object.identity().to_bytes())
                    .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
            ],
            ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))
    }

    /// Completes an already-published, receipt-bound Governance Audit
    /// reclamation. This is safe to retry after interruption: the receipt and
    /// signed anchor are durable before any exact frame is unlinked.
    pub fn complete_audit_retention_reclamation(&self) -> Result<(), CatalogFailure> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let anchor = audit_checkpoint::retention_anchor(&state.current)?
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        let trust = audit_checkpoint::retention_trust(&state.current, self.instance)?;
        anchor.verify(trust)?;
        if audit_checkpoint::retention_reclamation_receipt(&state.current, &anchor)?.is_none() {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        for record in state
            .audit
            .iter()
            .filter(|record| record.position() <= anchor.position())
        {
            if self
                .storage
                .audit_exists(record.position(), record.record_hash())?
            {
                let encoded = self.storage.read_audit(
                    &secret,
                    self.instance,
                    record.position(),
                    record.record_hash(),
                )?;
                if codec::decode_audit(&encoded)? != *record {
                    return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
                }
                self.storage
                    .reclaim_audit(record.position(), record.record_hash())?;
            }
        }
        self.storage.synchronize_reclaimed_audit()?;
        state
            .audit
            .retain(|record| record.position() > anchor.position());
        Ok(())
    }

    pub(crate) fn refresh_state(&self) -> Result<(), CatalogFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let recovered = recover(&self.storage, &secret, self.instance)?;
        if recovered.current.number() > state.current.number() {
            *state = recovered;
        }
        Ok(())
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn refresh_after_ambiguous_publication_for_test(&self) -> Result<(), CatalogFailure> {
        self.refresh_state()
    }
}

pub(crate) use inspection::inspect_read_only;

#[cfg(fuzzing)]
pub fn fuzz_catalog_stateful(data: &[u8]) {
    fuzzing::fuzz_catalog_stateful(data);
}

#[cfg(fuzzing)]
mod fuzzing;

#[cfg(fuzzing)]
pub(crate) use fuzzing::fuzz_authority;
