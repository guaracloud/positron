//! Immutable encrypted Catalog Generations and their single publication authority.

mod codec;
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
use storage::CatalogStorage;

use crate::OwnedPrimaryDataVolume;

use types::AuditFrontier;
pub use types::{
    AuditIntent, CatalogCommit, CatalogFailure, CatalogFailureCode, CatalogGenerationId,
    CatalogObject, CatalogObjectId, CatalogProposal, CatalogSecret, CatalogSnapshot, FormatEpoch,
    GovernanceAuditRecord, InstanceId, TransactionId,
};

#[cfg(fuzzing)]
pub(crate) use storage::with_catalog_fault;

#[cfg(fuzzing)]
pub(crate) use storage::fault::CatalogFileEvent;

const MAX_RECOVERED_AUDIT_BYTES: usize = 16_777_216;

/// The only Release 1 authority that publishes Catalog Generations.
pub struct Catalog {
    _volume: OwnedPrimaryDataVolume,
    instance: InstanceId,
    secret: CatalogSecret,
    storage: CatalogStorage,
    state: Mutex<CatalogState>,
}

struct CatalogState {
    current: CatalogSnapshot,
    audit: Vec<GovernanceAuditRecord>,
    transactions: BTreeMap<TransactionId, TransactionOutcome>,
}

#[derive(Clone)]
struct TransactionOutcome {
    digest: [u8; 32],
    record: CommitRecord,
    audit: Option<GovernanceAuditRecord>,
}

impl std::fmt::Debug for Catalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Catalog { <storage-and-key-redacted> }")
    }
}

impl Catalog {
    /// Opens and recovers the Catalog on an exclusively owned Primary Data Volume.
    pub fn open(
        volume: OwnedPrimaryDataVolume,
        instance: InstanceId,
        secret: CatalogSecret,
    ) -> Result<Self, CatalogFailure> {
        let storage = CatalogStorage::open(&volume)?;
        let state = recover(&storage, &secret, instance)?;
        Ok(Self {
            _volume: volume,
            instance,
            secret,
            storage,
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
        let object_ids: Vec<_> = proposal
            .objects
            .iter()
            .map(CatalogObject::identity)
            .collect();
        let digest = transaction_digest(
            proposal.format_epoch,
            &object_ids,
            audit.as_ref().map(|intent| intent.0.as_slice()),
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;

        // Resolve an earlier acknowledgement-ambiguous marker publication before
        // evaluating idempotency or the expected-generation precondition.
        let recovered = recover(&self.storage, &self.secret, self.instance)?;
        if recovered.current.number() > state.current.number() {
            *state = recovered;
        }

        if let Some(outcome) = state.transactions.get(&proposal.transaction) {
            if outcome.digest != digest {
                return Err(CatalogFailure::new(CatalogFailureCode::IdempotencyConflict));
            }
            return Ok(CatalogCommit {
                snapshot: load_snapshot(&self.storage, &self.secret, &outcome.record)?,
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
        let transaction = self
            .storage
            .open_transaction(proposal.transaction, digest)?;

        let mut objects = BTreeMap::new();
        for object in proposal.objects {
            self.storage.publish_object(
                &transaction,
                &self.secret,
                object.identity,
                proposal.format_epoch,
                &object.plaintext,
            )?;
            objects.insert(object.identity, Arc::from(object.plaintext));
        }
        if let Some((record, encoded)) = &prepared_audit {
            self.storage
                .publish_audit(&transaction, &self.secret, record, encoded)?;
        }

        let mut record = CommitRecord {
            generation: CatalogGenerationId::ORIGIN,
            number,
            predecessor: state.current.identity(),
            instance: self.instance,
            format_epoch: proposal.format_epoch,
            transaction: proposal.transaction,
            transaction_digest: digest,
            object_set_digest: object_set_digest(&object_ids),
            audit_frontier,
            objects: object_ids,
        };
        let encoded_commit = encode_commit(&record);
        record.generation = generation_identity(&encoded_commit);
        self.storage.publish_commit(
            &transaction,
            &self.secret,
            record.generation,
            &encoded_commit,
        )?;
        self.storage
            .publish_marker(&transaction, &self.secret, number, record.generation)?;

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
    let mut generation = highest_generation;
    let mut expected_number = highest_number;
    loop {
        let encoded = storage.read_commit(secret, generation)?;
        let record = decode_commit(generation, &encoded)?;
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
    let mut predecessor = CatalogSnapshot::origin();
    let mut audit = Vec::new();
    let mut audit_bytes = 0_usize;
    let mut transactions: BTreeMap<TransactionId, TransactionOutcome> = BTreeMap::new();
    for record in chain {
        if record.predecessor != predecessor.identity() || record.number != predecessor.number() + 1
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        let visible_audit = if record.audit_frontier == predecessor.0.audit_frontier {
            None
        } else {
            if record.audit_frontier.position != predecessor.0.audit_frontier.position + 1 {
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            }
            let encoded = storage.read_audit(
                secret,
                record.audit_frontier.position,
                record.audit_frontier.hash,
            )?;
            let decoded = decode_audit(&encoded)?;
            if decoded.position != record.audit_frontier.position
                || decoded.hash != record.audit_frontier.hash
                || decoded.predecessor_hash != predecessor.0.audit_frontier.hash
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
        ) != record.transaction_digest
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        let snapshot = load_snapshot(storage, secret, &record)?;
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
        predecessor = snapshot;
    }
    Ok(CatalogState {
        current: predecessor,
        audit,
        transactions,
    })
}

fn load_snapshot(
    storage: &CatalogStorage,
    secret: &CatalogSecret,
    record: &CommitRecord,
) -> Result<CatalogSnapshot, CatalogFailure> {
    let mut objects = BTreeMap::new();
    for identity in &record.objects {
        let object = storage.read_object(secret, *identity, record.format_epoch)?;
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
