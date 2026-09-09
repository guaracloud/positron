//! Immutable encrypted Catalog Generations and their single publication authority.

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
mod tests;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use budget::{
    commit_resource_claim, recovery_resource_claim, reserve_history, retained_artifact_bytes,
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
use crate::{RecoveryWorkClaim, RecoveryWorkKind, StorageKernelResourceAuthority};

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

/// The only Release 1 authority that publishes Catalog Generations.
pub struct Catalog<'authority> {
    authority: &'authority StorageKernelResourceAuthority,
    _writer: CatalogWriterLease<'authority>,
    instance: InstanceId,
    secret: Mutex<CatalogSecret>,
    storage: CatalogStorage,
    operation: Mutex<()>,
    state: Mutex<CatalogState>,
}

struct CatalogState {
    current: CatalogSnapshot,
    audit: Vec<GovernanceAuditRecord>,
    transactions: BTreeMap<TransactionId, TransactionOutcome>,
    retained_history_bytes: usize,
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

impl std::fmt::Debug for Catalog<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Catalog { <storage-and-key-redacted> }")
    }
}

impl<'authority> Catalog<'authority> {
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
        Ok(recover(&storage, &secret, instance)?.current)
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
                    return Ok(PreparedTransactionResolution::Unavailable);
                }
                for object in &prepared.record.objects {
                    self.storage.read_object(
                        &secret,
                        self.instance,
                        *object,
                        prepared.record.format_epoch,
                    )?;
                }
                if self.storage.read_audit(
                    &secret,
                    self.instance,
                    prepared.audit.position,
                    prepared.audit.hash,
                )? != prepared.encoded_audit
                {
                    return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
                }
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
                let snapshot =
                    load_snapshot(&self.storage, &secret, self.instance, &prepared.record)?;
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
