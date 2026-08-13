//! Immutable encrypted Catalog Generations and their single publication authority.

mod codec;
mod inspection;
mod storage;
mod types;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use codec::{
    CommitRecord, decode_audit, decode_commit, encode_commit, generation_identity,
    object_set_digest, prepare_audit, snapshot_from_record, transaction_digest,
};
use storage::{CatalogStorage, FRAME_OVERHEAD_BYTES, MAX_GENERATIONS};

use crate::data_protection::DataProtection;
use crate::resource_governor::CatalogWriterLease;
use crate::{RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts, StorageKernelResourceAuthority};

use types::AuditFrontier;
pub use types::{
    AuditIntent, CatalogCommit, CatalogFailure, CatalogFailureCode, CatalogGenerationId,
    CatalogObject, CatalogObjectId, CatalogProposal, CatalogRotation, CatalogSecret,
    CatalogSnapshot, CatalogWrappingKey, FormatEpoch, GovernanceAuditRecord, InstanceId,
    TransactionId,
};

#[cfg(any(test, fuzzing))]
pub(crate) use storage::with_catalog_fault;

#[cfg(any(test, fuzzing))]
pub(crate) use storage::fault::CatalogFileEvent;

const MAX_RECOVERED_AUDIT_BYTES: usize = 16_777_216;
const MAX_RETAINED_HISTORY_BYTES: usize = 16_777_216;
const MAX_RECOVERY_MEMORY_BYTES: u64 = 70_000_000;
const MAX_RECOVERY_ITEMS: u64 = 65_540;
const ROTATION_AUDIT_DOMAIN: &[u8] = b"catalog-root-rotation-v1\0";
const ROTATION_TRANSACTION_DOMAIN: &[u8] = b"positron-catalog-root-rotation-transaction-v1";

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

impl std::fmt::Debug for Catalog<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Catalog { <storage-and-key-redacted> }")
    }
}

impl<'authority> Catalog<'authority> {
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
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        self.commit_unreserved(expected, proposal, audit)
    }

    fn commit_unreserved(
        &self,
        expected: CatalogGenerationId,
        proposal: CatalogProposal,
        audit: Option<AuditIntent>,
    ) -> Result<CatalogCommit, CatalogFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let object_ids: Vec<_> = proposal
            .objects
            .iter()
            .map(CatalogObject::identity)
            .collect();
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
        let transaction = self
            .storage
            .open_transaction(proposal.transaction, digest)?;

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

    /// Rewraps every reachable encrypted artifact under a successor root key.
    ///
    /// Marker authentication is a separate stable authority and is never changed. An
    /// interrupted pass can be reopened with [`CatalogSecret::with_predecessor`] and retried.
    /// Started, successor-verified, and completed states are deterministic audited Catalog
    /// transactions. The predecessor route remains installed until completion is published.
    pub fn rewrap(
        &self,
        transaction: TransactionId,
        replacement: CatalogWrappingKey,
        intent: AuditIntent,
    ) -> Result<CatalogRotation, CatalogFailure> {
        let transactions = rotation_transactions(transaction)?;
        let audits = rotation_audits(&replacement, &intent)?;
        let replacement_route = (replacement.provider_key_reference, replacement.key_epoch);
        let claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            rewrap_resource_claim(),
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

        self.refresh_state()?;
        let started_exists = self.has_transaction(transactions[0])?;
        {
            let secret = self
                .secret
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            let valid_route = match secret.predecessor.as_ref() {
                Some(_) => replacement.same_route(&secret.wrapping),
                None => {
                    (started_exists && replacement.same_route(&secret.wrapping))
                        || (replacement.key_epoch > secret.wrapping.key_epoch
                            && !replacement.same_route(&secret.wrapping))
                },
            };
            if !valid_route {
                return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
            }
        }

        let expected = self.pin()?.identity();
        let started = self.commit_unreserved(
            expected,
            self.rotation_proposal(transactions[0])?,
            Some(audits[0].clone()),
        )?;

        if !self.has_transaction(transactions[1])? {
            let state = self
                .state
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            let mut secret = self
                .secret
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            let current = match secret.predecessor.as_ref() {
                Some(predecessor) => predecessor,
                None => &secret.wrapping,
            };
            for outcome in state.transactions.values() {
                for identity in &outcome.record.objects {
                    self.storage.rewrap_object(
                        current,
                        &replacement,
                        self.instance,
                        *identity,
                        outcome.record.format_epoch,
                    )?;
                }
                if let Some(audit) = outcome.audit.as_ref() {
                    self.storage.rewrap_audit(
                        current,
                        &replacement,
                        self.instance,
                        audit.position,
                        audit.hash,
                    )?;
                }
                self.storage.rewrap_commit(
                    current,
                    &replacement,
                    self.instance,
                    outcome.record.generation,
                )?;
            }
            if secret.predecessor.is_none() {
                let predecessor = std::mem::replace(&mut secret.wrapping, replacement);
                secret.predecessor = Some(predecessor);
            }
        }

        let verified = self.commit_unreserved(
            self.pin()?.identity(),
            self.rotation_proposal(transactions[1])?,
            Some(audits[1].clone()),
        )?;
        let completed = self.commit_unreserved(
            self.pin()?.identity(),
            self.rotation_proposal(transactions[2])?,
            Some(audits[2].clone()),
        )?;
        let mut secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        if secret.wrapping.provider_key_reference != replacement_route.0
            || secret.wrapping.key_epoch != replacement_route.1
        {
            return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
        }
        secret.predecessor = None;
        Ok(CatalogRotation {
            started,
            verified,
            completed,
        })
    }

    fn refresh_state(&self) -> Result<(), CatalogFailure> {
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

    fn has_transaction(&self, transaction: TransactionId) -> Result<bool, CatalogFailure> {
        self.state
            .lock()
            .map(|state| state.transactions.contains_key(&transaction))
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))
    }

    fn rotation_proposal(
        &self,
        transaction: TransactionId,
    ) -> Result<CatalogProposal, CatalogFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let epoch = state
            .current
            .format_epoch()
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        let objects = state
            .current
            .0
            .objects
            .values()
            .map(|plaintext| CatalogObject::new(plaintext.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        CatalogProposal::new(transaction, epoch, objects)
    }
}

pub(crate) use inspection::inspect_read_only;

fn rotation_transactions(base: TransactionId) -> Result<[TransactionId; 3], CatalogFailure> {
    fn derive(base: TransactionId, stage: u8) -> Result<TransactionId, CatalogFailure> {
        let mut encoded = Vec::with_capacity(ROTATION_TRANSACTION_DOMAIN.len() + 17);
        encoded.extend_from_slice(ROTATION_TRANSACTION_DOMAIN);
        encoded.extend_from_slice(&base.0);
        encoded.push(stage);
        let digest = DataProtection::hash(&encoded)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        let mut identifier = [0_u8; 16];
        identifier.copy_from_slice(&digest[..16]);
        TransactionId::new(identifier)
    }
    Ok([derive(base, 0)?, derive(base, 1)?, derive(base, 2)?])
}

fn rotation_audits(
    replacement: &CatalogWrappingKey,
    intent: &AuditIntent,
) -> Result<[AuditIntent; 3], CatalogFailure> {
    fn prepare(
        replacement: &CatalogWrappingKey,
        intent: &AuditIntent,
        stage: &[u8],
    ) -> Result<AuditIntent, CatalogFailure> {
        let mut encoded = Vec::with_capacity(
            ROTATION_AUDIT_DOMAIN.len() + stage.len() + 1 + 16 + 8 + intent.0.len(),
        );
        encoded.extend_from_slice(ROTATION_AUDIT_DOMAIN);
        encoded.extend_from_slice(stage);
        encoded.push(0);
        encoded.extend_from_slice(&replacement.provider_key_reference);
        encoded.extend_from_slice(&replacement.key_epoch.to_be_bytes());
        encoded.extend_from_slice(&intent.0);
        AuditIntent::new(encoded)
    }
    Ok([
        prepare(replacement, intent, b"started")?,
        prepare(replacement, intent, b"verified")?,
        prepare(replacement, intent, b"completed")?,
    ])
}

fn retained_artifact_bytes(plaintext_bytes: usize) -> Result<usize, CatalogFailure> {
    plaintext_bytes
        .checked_add(FRAME_OVERHEAD_BYTES)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))
}

fn reserve_history(
    retained: usize,
    additional: usize,
    generation_number: u64,
) -> Result<usize, CatalogFailure> {
    let generation_count = usize::try_from(generation_number)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    if generation_count > MAX_GENERATIONS {
        return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
    }
    retained
        .checked_add(additional)
        .filter(|total| *total <= MAX_RETAINED_HISTORY_BYTES)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))
}

fn recovery_resource_claim() -> ResourceAmounts {
    ResourceAmounts::new([
        MAX_RECOVERY_MEMORY_BYTES,
        1,
        1,
        MAX_RECOVERY_MEMORY_BYTES,
        MAX_RECOVERY_ITEMS,
        0,
        1,
        1,
        1,
        8,
        0,
    ])
}

fn rewrap_resource_claim() -> ResourceAmounts {
    recovery_resource_claim().maximum(ResourceAmounts::new([
        MAX_RECOVERY_MEMORY_BYTES,
        1,
        1,
        MAX_RECOVERY_MEMORY_BYTES,
        MAX_RECOVERY_ITEMS,
        0,
        1,
        1,
        1,
        8,
        MAX_RETAINED_HISTORY_BYTES as u64,
    ]))
}

fn commit_resource_claim(
    proposal: &CatalogProposal,
    audit: Option<&AuditIntent>,
) -> Result<ResourceAmounts, CatalogFailure> {
    let object_bytes = proposal
        .objects
        .iter()
        .try_fold(0_usize, |total, object| {
            total.checked_add(object.plaintext.len())
        })
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let artifact_count = proposal
        .objects
        .len()
        .checked_add(2)
        .and_then(|count| count.checked_add(usize::from(audit.is_some())))
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let durable_bytes = object_bytes
        .checked_add(audit.map_or(0, |intent| intent.0.len()))
        .and_then(|bytes| bytes.checked_add(artifact_count.saturating_mul(512)))
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let memory_bytes = durable_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(1_048_576))
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let publication = ResourceAmounts::new([
        u64::try_from(memory_bytes)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
        1,
        1,
        u64::try_from(memory_bytes)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
        u64::try_from(artifact_count)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
        0,
        1,
        1,
        1,
        8,
        u64::try_from(durable_bytes)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
    ]);
    Ok(publication.maximum(recovery_resource_claim()))
}

fn recover(
    storage: &CatalogStorage,
    secret: &CatalogSecret,
    instance: InstanceId,
) -> Result<CatalogState, CatalogFailure> {
    let marker_scan = storage.markers(secret)?;
    if marker_scan.authentication_failures != 0 {
        return Err(CatalogFailure::new(
            CatalogFailureCode::AuthenticationFailed,
        ));
    }
    if marker_scan.verified.is_empty() {
        return Ok(CatalogState {
            current: CatalogSnapshot::origin(),
            audit: Vec::new(),
            transactions: BTreeMap::new(),
            retained_history_bytes: 0,
        });
    }

    let mut by_number = BTreeMap::new();
    let mut highest_number = 0_u64;
    let mut highest_generation = CatalogGenerationId::ORIGIN;
    for (generation, number) in &marker_scan.verified {
        if by_number.insert(*number, *generation).is_some() {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        if *number > highest_number {
            highest_number = *number;
            highest_generation = *generation;
        }
    }
    let mut chain = Vec::new();
    let mut retained_history_bytes = marker_scan
        .verified
        .len()
        .checked_mul(storage::MARKER_BYTES)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let mut generation = highest_generation;
    let mut expected_number = highest_number;
    loop {
        let encoded = storage.read_commit(secret, instance, generation)?;
        retained_history_bytes = reserve_history(
            retained_history_bytes,
            retained_artifact_bytes(encoded.len())?,
            highest_number,
        )?;
        let record = decode_commit(generation, &encoded)?;
        if !record.format_epoch.is_catalog_readable() {
            return Err(CatalogFailure::new(CatalogFailureCode::UnsupportedFormat));
        }
        if record.instance != instance || record.number != expected_number {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        let predecessor = record.predecessor;
        chain.push(record);
        if expected_number == 1 {
            if predecessor != CatalogGenerationId::ORIGIN {
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            }
            break;
        }
        expected_number -= 1;
        if by_number.get(&expected_number) != Some(&predecessor) {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        generation = predecessor;
    }
    chain.reverse();
    let mut predecessor_generation = CatalogGenerationId::ORIGIN;
    let mut predecessor_number = 0_u64;
    let mut predecessor_audit = AuditFrontier::ORIGIN;
    let mut audit = Vec::new();
    let mut audit_bytes = 0_usize;
    let mut transactions: BTreeMap<TransactionId, TransactionOutcome> = BTreeMap::new();
    for record in chain {
        if record.predecessor != predecessor_generation || record.number != predecessor_number + 1 {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        let visible_audit = if record.audit_frontier == predecessor_audit {
            None
        } else {
            if record.audit_frontier.position != predecessor_audit.position + 1 {
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            }
            let encoded = storage.read_audit(
                secret,
                instance,
                record.audit_frontier.position,
                record.audit_frontier.hash,
            )?;
            retained_history_bytes = reserve_history(
                retained_history_bytes,
                retained_artifact_bytes(encoded.len())?,
                highest_number,
            )?;
            let decoded = decode_audit(&encoded)?;
            if decoded.position != record.audit_frontier.position
                || decoded.hash != record.audit_frontier.hash
                || decoded.predecessor_hash != predecessor_audit.hash
                || decoded.transaction != record.transaction
            {
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            }
            // The prior iteration is bounded and one decoded intent is bounded,
            // so this addition cannot overflow on a supported target.
            audit_bytes += decoded.intent.len();
            if audit_bytes > MAX_RECOVERED_AUDIT_BYTES {
                return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
            }
            audit.push(decoded.clone());
            Some(decoded)
        };
        if transaction_digest(
            record.format_epoch,
            &record.objects,
            visible_audit.as_ref().map(|entry| entry.intent()),
        )? != record.transaction_digest
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        predecessor_generation = record.generation;
        predecessor_number = record.number;
        predecessor_audit = record.audit_frontier;
        match transactions.get(&record.transaction) {
            Some(outcome) if outcome.digest != record.transaction_digest => {
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            },
            Some(_) => return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption)),
            None => {
                transactions.insert(
                    record.transaction,
                    TransactionOutcome {
                        digest: record.transaction_digest,
                        record,
                        audit: visible_audit,
                    },
                );
            },
        }
    }
    let latest = transactions
        .values()
        .find(|outcome| outcome.record.generation == highest_generation)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    let current = load_snapshot(storage, secret, instance, &latest.record)?;
    Ok(CatalogState {
        current,
        audit,
        transactions,
        retained_history_bytes,
    })
}

fn load_snapshot(
    storage: &CatalogStorage,
    secret: &CatalogSecret,
    instance: InstanceId,
    record: &CommitRecord,
) -> Result<CatalogSnapshot, CatalogFailure> {
    let mut objects = BTreeMap::new();
    for identity in &record.objects {
        let object = storage.read_object(secret, instance, *identity, record.format_epoch)?;
        objects.insert(*identity, object);
    }
    Ok(snapshot_from_record(record, objects))
}

#[cfg(fuzzing)]
pub fn fuzz_catalog_stateful(data: &[u8]) {
    fuzzing::fuzz_catalog_stateful(data);
}

#[cfg(fuzzing)]
mod fuzzing;

#[cfg(fuzzing)]
pub(crate) use fuzzing::fuzz_authority;
