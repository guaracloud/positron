use super::LedgerFailureCode::ResourceAdmissionRefused;
use super::capacity::lease_claim;
use super::snapshot_lease_codec::encode;
use super::snapshot_lease_grant::SnapshotLeaseGrant;
use super::snapshot_lease_record::{
    LeaseBlock, LeaseRecord, SnapshotLeaseId, SnapshotLeaseUsage, valid_lease_interval,
    validate_active_lease,
};
use crate::{WorkClaim, WorkKind};
use std::collections::BTreeSet;
#[path = "snapshot_lease_support.rs"]
mod snapshot_lease_support;
use super::{ActiveSegmentLedger, LedgerFailure, LedgerFailureCode};
#[cfg(test)]
pub(super) use snapshot_lease_support::publication_visible;
pub(super) use snapshot_lease_support::{expired_in_scope, publish_many, records};
use snapshot_lease_support::{
    fresh_identity, publish, reject_time_regression, remove_reservations, snapshot_from_record,
};
pub(super) use snapshot_lease_support::{map_catalog_failure, rollback_marker_resize};
pub(super) const MAX_SNAPSHOT_LEASES: usize = 64;
#[cfg(test)]
#[path = "snapshot_lease_tests.rs"]
mod tests;

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    /// Creates a durable lease for an already-admitted query task. The caller's
    /// query reservation covers construction CPU; the returned grant retains
    /// only resources that remain live with its immutable snapshot.
    pub fn create_snapshot_lease(
        &self,
        now: u64,
        expiry: u64,
    ) -> Result<SnapshotLeaseGrant<'kernel>, LedgerFailure> {
        if !valid_lease_interval(now, expiry) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        self.retry_pending_releases(&mut state)?;
        reject_time_regression(&state, now)?;
        let basis = self.catalog.pin()?;
        let all_records = records(&basis)?;
        let expired = expired_in_scope(&all_records, self.scope, now);
        for record in all_records
            .iter()
            .filter(|record| record.scope == self.scope && !expired.contains(&record.identity))
        {
            validate_active_lease(record, now)?;
        }
        let active_count = all_records
            .iter()
            .filter(|record| record.scope == self.scope && !expired.contains(&record.identity))
            .count();
        if active_count >= MAX_SNAPSHOT_LEASES {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        let identity = fresh_identity()?;
        let record = LeaseRecord {
            identity,
            scope: self.scope,
            catalog_identity: basis.identity(),
            catalog_generation: basis.number(),
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
        // Admit every capacity needed by the returned grant before publishing its
        // durable identity. Later failures then drop both reservations without
        // leaving a catalog lease that no caller can release.
        let snapshot = snapshot_from_record(self, &state, &record)?;
        let encoded = encode(&record)?;
        let claim = WorkClaim::tenant(
            self.scope.tenant,
            WorkKind::InteractiveQueryTail,
            lease_claim(encoded.len())?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let retained = self
            .authority
            .governor()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        publish(self.catalog, &basis, &expired, Some(encoded))?;
        remove_reservations(&mut state, &expired);
        state.lease_reservations.insert(identity, retained);
        state.last_snapshot_lease_time = now;
        Ok(SnapshotLeaseGrant {
            identity,
            expiry,
            resume_count: 0,
            repeated_batch_count: 0,
            usage: SnapshotLeaseUsage::default(),
            snapshot,
        })
    }

    /// Resumes a durable lease for an already-admitted query task. The caller's
    /// query reservation covers construction CPU; the returned grant retains
    /// only resources that remain live with its immutable snapshot.
    pub fn resume_snapshot_lease(
        &self,
        identity: SnapshotLeaseId,
        now: u64,
    ) -> Result<SnapshotLeaseGrant<'kernel>, LedgerFailure> {
        self.resume_snapshot_lease_marked(identity, now, None)
    }

    /// Resumes a lease while recording the immutable cursor boundary being
    /// attempted. Reusing the same boundary is an at-least-once batch retry;
    /// advancing to a different boundary is a normal page transition.
    ///
    /// `LeaseResumeMarker` remains private to this lease authority: exposing
    /// the durable marker as a cross-crate public wire type would duplicate
    /// cursor protocol ownership. The scalar arguments are therefore the
    /// deliberate narrow boundary into the kernel-owned typed marker.
    pub fn resume_snapshot_lease_with_marker(
        &self,
        identity: SnapshotLeaseId,
        now: u64,
        sequence: u64,
        prior_digest: [u8; 32],
    ) -> Result<SnapshotLeaseGrant<'kernel>, LedgerFailure> {
        self.resume_snapshot_lease_marked(identity, now, Some((sequence, prior_digest)))
    }

    fn resume_snapshot_lease_marked(
        &self,
        identity: SnapshotLeaseId,
        now: u64,
        marker: Option<(u64, [u8; 32])>,
    ) -> Result<SnapshotLeaseGrant<'kernel>, LedgerFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        self.retry_pending_releases(&mut state)?;
        reject_time_regression(&state, now)?;
        self.catalog
            .refresh_state()
            .map_err(|failure| LedgerFailure::new(map_catalog_failure(failure.code())))?;
        let basis = self.catalog.pin()?;
        let all_records = records(&basis)?;
        let expired = expired_in_scope(&all_records, self.scope, now);
        if !expired.is_empty() {
            publish(self.catalog, &basis, &expired, None)?;
            remove_reservations(&mut state, &expired);
        }
        state.last_snapshot_lease_time = now;
        let mut record = all_records
            .into_iter()
            .find(|record| {
                record.identity == identity
                    && record.scope == self.scope
                    && !expired.contains(&record.identity)
            })
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::SnapshotExpired))?;
        validate_active_lease(&record, now)?;
        if !state.lease_reservations.contains_key(&identity) {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        if record.observed_at == 0 {
            self.normalize_legacy_lease(&mut state, &mut record, now)?;
        }
        let snapshot = snapshot_from_record(self, &state, &record)?;
        let (resume_count, repeated_batch_count) = if let Some((sequence, prior_digest)) = marker {
            let previous = state
                .lease_resume_markers
                .get(&identity)
                .copied()
                .unwrap_or(super::snapshot_lease_record::LeaseResumeMarker {
                    sequence: record.last_resume_sequence.unwrap_or_default(),
                    prior_digest: record.last_resume_prior_digest,
                    attempts: record.resume_count,
                    repeats: record.repeated_batch_count,
                    usage: record.usage,
                });
            if previous.usage != record.usage {
                return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
            }
            if previous.attempts > 0
                && (sequence < previous.sequence
                    || (sequence == previous.sequence && prior_digest != previous.prior_digest))
            {
                return Err(LedgerFailure::new(LedgerFailureCode::StaleResumeMarker));
            }
            let repeated = previous.attempts > 0
                && previous.sequence == sequence
                && previous.prior_digest == prior_digest;
            let resume_count = previous
                .attempts
                .checked_add(1)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            let repeated_batch_count = previous
                .repeats
                .checked_add(u64::from(repeated))
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            let mut updated = record.clone();
            updated.resume_count = resume_count;
            updated.repeated_batch_count = repeated_batch_count;
            updated.last_resume_sequence = Some(sequence);
            updated.last_resume_prior_digest = prior_digest;
            let encoded = encode(&updated)?;
            let amounts = lease_claim(encoded.len())?;
            let previous_amounts = {
                let reservation = state
                    .lease_reservations
                    .get_mut(&identity)
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
                let previous = reservation.granted();
                if previous != amounts {
                    reservation
                        .try_resize(amounts)
                        .map_err(|_| LedgerFailure::new(ResourceAdmissionRefused))?;
                }
                previous
            };
            let marker_basis = match self.catalog.pin() {
                Ok(basis) => basis,
                Err(_) => {
                    rollback_marker_resize(&mut state, identity, previous_amounts)?;
                    return Err(LedgerFailure::new(LedgerFailureCode::StorageUnavailable));
                },
            };
            if let Err(failure) = publish_many(
                self.catalog,
                &marker_basis,
                &BTreeSet::from([identity]),
                vec![encoded],
            ) {
                if failure.completion_state() != super::LedgerCompletionState::CommitAmbiguous {
                    rollback_marker_resize(&mut state, identity, previous_amounts)?;
                }
                return Err(failure);
            }
            state.lease_resume_markers.insert(
                identity,
                super::snapshot_lease_record::LeaseResumeMarker {
                    sequence,
                    prior_digest,
                    attempts: resume_count,
                    repeats: repeated_batch_count,
                    usage: updated.usage,
                },
            );
            (resume_count, repeated_batch_count)
        } else {
            (record.resume_count, record.repeated_batch_count)
        };
        Ok(SnapshotLeaseGrant {
            identity,
            expiry: record.expiry,
            resume_count,
            repeated_batch_count,
            usage: record.usage,
            snapshot,
        })
    }

    pub fn release_snapshot_lease(&self, identity: SnapshotLeaseId) -> Result<(), LedgerFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        state.pending_lease_releases.register(identity)?;
        self.retry_pending_releases(&mut state)
    }

    pub(super) fn retry_pending_releases(
        &self,
        state: &mut super::state::LedgerState<'kernel>,
    ) -> Result<(), LedgerFailure> {
        let pending = state
            .pending_lease_releases
            .identities()
            .collect::<BTreeSet<_>>();
        if pending.is_empty() {
            return Ok(());
        }
        self.catalog
            .refresh_state()
            .map_err(|failure| LedgerFailure::new(map_catalog_failure(failure.code())))?;
        let basis = self.catalog.pin()?;
        let remove = records(&basis)?
            .into_iter()
            .filter(|record| record.scope == self.scope && pending.contains(&record.identity))
            .map(|record| record.identity)
            .collect::<BTreeSet<_>>();
        if !remove.is_empty() {
            publish(self.catalog, &basis, &remove, None)?;
        }
        for identity in pending {
            state.lease_reservations.remove(&identity);
            state.lease_resume_markers.remove(&identity);
        }
        state.pending_lease_releases.clear();
        Ok(())
    }

    fn normalize_legacy_lease(
        &self,
        state: &mut super::state::LedgerState<'kernel>,
        record: &mut LeaseRecord,
        now: u64,
    ) -> Result<(), LedgerFailure> {
        let mut normalized = record.clone();
        normalized.observed_at = now;
        let encoded = encode(&normalized)?;
        let claim = WorkClaim::tenant(
            self.scope.tenant,
            WorkKind::InteractiveQueryTail,
            lease_claim(encoded.len())?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let retained = self
            .authority
            .governor()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        self.catalog
            .refresh_state()
            .map_err(|failure| LedgerFailure::new(map_catalog_failure(failure.code())))?;
        let basis = self.catalog.pin()?;
        publish_many(
            self.catalog,
            &basis,
            &BTreeSet::from([record.identity]),
            vec![encoded],
        )?;
        let previous = state.lease_reservations.insert(record.identity, retained);
        let Some(previous) = previous else {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        };
        drop(previous);
        *record = normalized;
        Ok(())
    }
}
