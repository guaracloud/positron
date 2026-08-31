use std::collections::BTreeSet;

use super::capacity::lease_claim;
use super::snapshot_lease::snapshot_lease_support::{
    LeaseReservationTransaction, fresh_identity, publish_many_with_expected_catalog, records,
    snapshot_from_record,
};
use super::snapshot_lease_codec::decode;
use super::snapshot_lease_codec::encode;
use super::snapshot_lease_grant::SnapshotLeaseGrant;
use super::snapshot_lease_record::{LeaseBlock, LeaseRecord, SnapshotLeaseId, SnapshotLeaseUsage};
use super::{ActiveSegmentLedger, LedgerCompletionState, LedgerFailure, LedgerFailureCode};

/// A prepared replacement keeps the old durable lease authoritative until the
/// caller has authenticated the candidate cursor. Dropping it releases only
/// the candidate snapshot capacity; no Catalog identity is changed.
pub struct SnapshotLeaseReplacement<'lease, 'kernel, 'catalog> {
    ledger: &'lease ActiveSegmentLedger<'kernel, 'catalog>,
    old_identity: SnapshotLeaseId,
    new_identity: SnapshotLeaseId,
    old_encoded: Vec<u8>,
    encoded: Vec<u8>,
    grant: Option<SnapshotLeaseGrant<'kernel>>,
    observed_at: u64,
    committed: bool,
}

impl<'lease, 'kernel, 'catalog> SnapshotLeaseReplacement<'lease, 'kernel, 'catalog> {
    #[must_use]
    pub const fn old_identity(&self) -> SnapshotLeaseId {
        self.old_identity
    }

    #[must_use]
    pub const fn identity(&self) -> SnapshotLeaseId {
        self.new_identity
    }

    #[must_use]
    pub fn snapshot(&self) -> Option<&super::LedgerSnapshot<'kernel>> {
        self.grant.as_ref().map(SnapshotLeaseGrant::snapshot)
    }

    /// Publishes the replacement and transfers the existing lease reservation
    /// slot to its new identity. Any failed publication restores its original
    /// reservation and leaves the old Catalog record available for resume.
    pub fn commit(&mut self) -> Result<SnapshotLeaseGrant<'kernel>, LedgerFailure> {
        if self.committed || self.grant.is_none() {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let mut state = self
            .ledger
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        self.ledger.retry_pending_releases(&mut state)?;
        if state.lease_reservations.contains_key(&self.new_identity) {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        self.ledger.catalog.refresh_state()?;
        let basis = self.ledger.catalog.pin()?;
        let old_record = records(&basis)?.into_iter().find(|record| {
            record.identity == self.old_identity && record.scope == self.ledger.scope
        });
        let Some(old_record) = old_record else {
            return Err(LedgerFailure::new(LedgerFailureCode::SnapshotExpired));
        };
        if !basis
            .plaintext_objects()
            .any(|bytes| bytes == self.old_encoded.as_slice())
        {
            return Err(LedgerFailure::new(LedgerFailureCode::ConcurrentWriter));
        }
        if !state.lease_reservations.contains_key(&self.old_identity) {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        super::snapshot_lease_record::validate_active_lease(&old_record, self.observed_at)?;
        let amounts = lease_claim(self.encoded.len())?;
        let transaction = LeaseReservationTransaction::begin(&mut state, self.old_identity)?;
        if let Err(failure) = transaction.resize(&mut state, amounts) {
            transaction.cancel(&mut state);
            return Err(failure);
        }
        let publication = publish_many_with_expected_catalog(
            self.ledger.catalog,
            &basis,
            basis.identity(),
            &BTreeSet::from([self.old_identity]),
            vec![self.encoded.clone()],
        );
        if let Err(failure) = publication {
            return Err(rollback_after_replacement_failure(
                &mut state,
                transaction,
                failure,
            ));
        }
        let reservation = state
            .lease_reservations
            .remove(&self.old_identity)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        transaction.commit(&mut state);
        state
            .lease_reservations
            .insert(self.new_identity, reservation);
        state.lease_resume_markers.remove(&self.old_identity);
        state.last_snapshot_lease_time = self.observed_at;
        self.committed = true;
        self.grant
            .take()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
    }

    /// Restores the old durable identity after another source replacement
    /// fails. The caller must retain the old cursor until this returns.
    pub fn rollback(&mut self) -> Result<(), LedgerFailure> {
        if !self.committed {
            return Ok(());
        }
        let mut state = self
            .ledger
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        self.ledger.retry_pending_releases(&mut state)?;
        self.ledger.catalog.refresh_state()?;
        let basis = self.ledger.catalog.pin()?;
        let mut new_record_visible = false;
        for bytes in basis.plaintext_objects() {
            if let Some(record) = decode(bytes)?
                && record.identity == self.new_identity
                && record.scope == self.ledger.scope
            {
                new_record_visible = true;
                break;
            }
        }
        if !new_record_visible {
            return Err(LedgerFailure::new(LedgerFailureCode::SnapshotExpired));
        }
        if !basis
            .plaintext_objects()
            .any(|bytes| bytes == self.encoded.as_slice())
        {
            return Err(LedgerFailure::new(LedgerFailureCode::ConcurrentWriter));
        }
        let transaction = LeaseReservationTransaction::begin(&mut state, self.new_identity)?;
        let old_amounts = lease_claim(self.old_encoded.len())?;
        if let Err(failure) = transaction.resize(&mut state, old_amounts) {
            transaction.cancel(&mut state);
            return Err(failure);
        }
        if let Err(failure) = publish_many_with_expected_catalog(
            self.ledger.catalog,
            &basis,
            basis.identity(),
            &BTreeSet::from([self.new_identity]),
            vec![self.old_encoded.clone()],
        ) {
            return Err(rollback_after_replacement_failure(
                &mut state,
                transaction,
                failure,
            ));
        }
        let reservation = state
            .lease_reservations
            .remove(&self.new_identity)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        transaction.commit(&mut state);
        state
            .lease_reservations
            .insert(self.old_identity, reservation);
        state.lease_resume_markers.remove(&self.new_identity);
        self.committed = false;
        Ok(())
    }
}

fn rollback_after_replacement_failure(
    state: &mut super::state::LedgerState<'_>,
    transaction: LeaseReservationTransaction,
    failure: LedgerFailure,
) -> LedgerFailure {
    match transaction.rollback(state) {
        Ok(()) => failure,
        Err(rollback) => {
            if rollback.completion_state() == LedgerCompletionState::CommitAmbiguous {
                rollback
            } else {
                LedgerFailure::new(LedgerFailureCode::RecoveryRequired)
            }
        },
    }
}

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    /// Captures newer blocks under a candidate lease without changing the
    /// currently resumable Catalog identity. Call [`SnapshotLeaseReplacement::commit`]
    /// only after the corresponding cursor has encoded successfully.
    pub fn prepare_snapshot_lease_replacement<'lease>(
        &'lease self,
        old_identity: SnapshotLeaseId,
        now: u64,
        expiry: u64,
    ) -> Result<SnapshotLeaseReplacement<'lease, 'kernel, 'catalog>, LedgerFailure> {
        let now = self.lease_operation_time(now)?;
        if !super::snapshot_lease_record::valid_lease_interval(now, expiry) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        self.retry_pending_releases(&mut state)?;
        if self.retention_time.is_none() && now < state.last_snapshot_lease_time {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let now = state.last_snapshot_lease_time.max(now);
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let mut old = None;
        for bytes in basis.plaintext_objects() {
            if bytes.get(..8) != Some(b"PSLEASE1") {
                continue;
            }
            let Some(record) = decode(bytes)? else {
                return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
            };
            if record.identity == old_identity && record.scope == self.scope {
                old = Some((bytes.to_owned(), record));
                break;
            }
        }
        let (old_encoded, old_record) =
            old.ok_or_else(|| LedgerFailure::new(LedgerFailureCode::SnapshotExpired))?;
        if now >= old_record.expiry {
            return Err(LedgerFailure::new(LedgerFailureCode::SnapshotExpired));
        }
        super::snapshot_lease_record::validate_active_lease(&old_record, now)?;
        if !state.lease_reservations.contains_key(&old_identity) {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        let new_identity = fresh_identity()?;
        let record = LeaseRecord {
            identity: new_identity,
            scope: self.scope,
            catalog_identity: old_record.catalog_identity,
            catalog_generation: old_record.catalog_generation,
            frontier: state.frontier,
            observed_at: now,
            expiry,
            resume_count: 0,
            repeated_batch_count: 0,
            last_resume_sequence: None,
            last_resume_prior_digest: [0; 32],
            usage: SnapshotLeaseUsage::default(),
            blocks: state.blocks.iter().map(LeaseBlock::from).collect(),
        };
        let encoded = encode(&record)?;
        let snapshot = snapshot_from_record(self, &state, &record)?;
        let grant = SnapshotLeaseGrant {
            identity: new_identity,
            expiry,
            resume_count: 0,
            repeated_batch_count: 0,
            usage: SnapshotLeaseUsage::default(),
            snapshot,
            attempt: None,
        };
        Ok(SnapshotLeaseReplacement {
            ledger: self,
            old_identity,
            new_identity,
            old_encoded,
            encoded,
            grant: Some(grant),
            observed_at: now,
            committed: false,
        })
    }
}
