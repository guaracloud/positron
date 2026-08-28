use super::capacity::lease_claim;
use super::snapshot_lease_attempt::SnapshotLeaseAttempt;
use super::snapshot_lease_codec::encode;
use super::snapshot_lease_grant::SnapshotLeaseGrant;
use super::snapshot_lease_pending::{
    cleanup_expired_on_resume_failure, register_all, register_lease_reservation, remove_all,
};
use super::snapshot_lease_record::{
    LeaseBlock, LeaseRecord, SnapshotLeaseId, SnapshotLeaseUsage, resume_marker_for,
    valid_lease_interval, validate_active_lease,
};
use crate::{WorkClaim, WorkKind};
use std::collections::BTreeSet;
#[path = "snapshot_lease_lifecycle.rs"]
mod snapshot_lease_lifecycle;
#[path = "snapshot_lease_support.rs"]
pub(crate) mod snapshot_lease_support;
use super::{ActiveSegmentLedger, LedgerCompletionState, LedgerFailure, LedgerFailureCode};
use crate::CatalogGenerationId;
pub(super) use snapshot_lease_support::map_catalog_failure;
pub(super) use snapshot_lease_support::{
    LeaseReservationTransaction, expired_in_scope, publish_many, records,
};
use snapshot_lease_support::{
    fresh_identity, publish, reject_time_regression, remove_reservations, snapshot_from_record,
};
use snapshot_lease_support::{
    publish_many_with_expected_catalog, publish_many_with_expected_catalog_snapshot,
};
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
        self.create_snapshot_lease_internal(now, expiry, None)
    }

    /// Creates a lease only if the durable Catalog is still the generation
    /// that the caller validated for admission.
    pub fn create_snapshot_lease_at_catalog(
        &self,
        now: u64,
        expiry: u64,
        expected_catalog: CatalogGenerationId,
    ) -> Result<SnapshotLeaseGrant<'kernel>, LedgerFailure> {
        self.create_snapshot_lease_internal(now, expiry, Some(expected_catalog))
    }

    fn create_snapshot_lease_internal(
        &self,
        mut now: u64,
        expiry: u64,
        expected_catalog: Option<CatalogGenerationId>,
    ) -> Result<SnapshotLeaseGrant<'kernel>, LedgerFailure> {
        if !valid_lease_interval(now, expiry) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        self.retry_pending_releases(&mut state)?;
        now = state.last_snapshot_lease_time.max(now);
        if !valid_lease_interval(now, expiry) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        if expected_catalog.is_some_and(|expected| expected != basis.identity()) {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
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
        let state = &mut *state;
        let (reservations, pending) = (
            &mut state.lease_reservations,
            &mut state.pending_lease_releases,
        );
        register_lease_reservation(reservations, pending, identity, retained, &expired)?;
        let publication = (|| {
            publish(self.catalog, &basis, &expired, Some(encoded))?;
            #[cfg(any(test, fuzzing, feature = "test-support"))]
            super::fault::emit_event(
                super::fault::LedgerFileEvent::BeforeLeaseCreationReconciliation,
            )?;
            Ok::<(), LedgerFailure>(())
        })();
        if let Err(failure) = publication {
            if failure.completion_state() != LedgerCompletionState::CommitAmbiguous {
                state.lease_reservations.remove(&identity);
                state.pending_lease_releases.remove(identity);
                remove_all(&mut state.pending_lease_releases, expired.iter().copied());
            }
            return Err(failure);
        }
        remove_reservations(state, &expired);
        state.pending_lease_releases.remove(identity);
        state.last_snapshot_lease_time = now;
        Ok(SnapshotLeaseGrant {
            identity,
            expiry,
            resume_count: 0,
            repeated_batch_count: 0,
            usage: SnapshotLeaseUsage::default(),
            snapshot,
            attempt: None,
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
        self.resume_snapshot_lease_marked(identity, now, None, None)
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
        self.resume_snapshot_lease_marked(identity, now, Some((sequence, prior_digest)), None)
    }

    /// Resumes a lease with a marker only when the durable Catalog still
    /// matches the generation admitted by the query context.
    pub fn resume_snapshot_lease_with_marker_at_catalog(
        &self,
        identity: SnapshotLeaseId,
        now: u64,
        sequence: u64,
        prior_digest: [u8; 32],
        expected_catalog: CatalogGenerationId,
        expected_generation: u64,
    ) -> Result<SnapshotLeaseGrant<'kernel>, LedgerFailure> {
        self.resume_snapshot_lease_marked(
            identity,
            now,
            Some((sequence, prior_digest)),
            Some((expected_catalog, expected_generation)),
        )
    }

    fn resume_snapshot_lease_marked(
        &self,
        identity: SnapshotLeaseId,
        now: u64,
        marker: Option<(u64, [u8; 32])>,
        expected_catalog: Option<(CatalogGenerationId, u64)>,
    ) -> Result<SnapshotLeaseGrant<'kernel>, LedgerFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        self.retry_pending_releases(&mut state)?;
        reject_time_regression(&state, now)?;
        let mut active_attempt = marker
            .map(|_| SnapshotLeaseAttempt::acquire(&self.lease_attempts, identity, 0))
            .transpose()?;
        self.catalog
            .refresh_state()
            .map_err(|failure| LedgerFailure::new(map_catalog_failure(failure.code())))?;
        let basis = self.catalog.pin()?;
        if expected_catalog.is_some_and(|(identity, generation)| {
            basis.identity() != identity || basis.number() != generation
        }) {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let all_records = records(&basis)?;
        let expired = expired_in_scope(&all_records, self.scope, now);
        let mut marker_basis = basis;
        if !expired.is_empty() {
            register_all(&mut state.pending_lease_releases, expired.iter().copied())?;
            marker_basis = match publish_many_with_expected_catalog_snapshot(
                self.catalog,
                &marker_basis,
                marker_basis.identity(),
                &expired,
            ) {
                Ok(snapshot) => snapshot,
                Err(failure) => {
                    return Err(cleanup_expired_on_resume_failure(
                        &mut state.pending_lease_releases,
                        &expired,
                        failure,
                    ));
                },
            };
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
        let (resume_count, repeated_batch_count, attempt) =
            if let Some((sequence, prior_digest)) = marker {
                let durable_marker = resume_marker_for(&record);
                let previous = match state.lease_resume_markers.get(&identity).copied() {
                    Some(cached) if cached == durable_marker => cached,
                    _ => {
                        state.lease_resume_markers.insert(identity, durable_marker);
                        durable_marker
                    },
                };
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
                let mut attempt = active_attempt
                    .take()
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
                attempt.set_resume_count(resume_count);
                let mut updated = record.clone();
                updated.resume_count = resume_count;
                updated.repeated_batch_count = repeated_batch_count;
                updated.last_resume_sequence = Some(sequence);
                updated.last_resume_prior_digest = prior_digest;
                let encoded = encode(&updated)?;
                let amounts = lease_claim(encoded.len())?;
                #[cfg(any(test, fuzzing, feature = "test-support"))]
                crate::catalog::before_lease_marker_basis(self.catalog)
                    .map_err(|failure| LedgerFailure::new(map_catalog_failure(failure.code())))?;
                if expired.is_empty() {
                    marker_basis = self
                        .catalog
                        .pin()
                        .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
                    if expected_catalog.is_some_and(|(expected_identity, expected_generation)| {
                        marker_basis.identity() != expected_identity
                            || marker_basis.number() != expected_generation
                    }) {
                        return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
                    }
                }
                let transaction = LeaseReservationTransaction::begin(&mut state, identity)?;
                if let Err(failure) = transaction.resize(&mut state, amounts) {
                    transaction.cancel(&mut state);
                    return Err(failure);
                }
                let expected_identity = if expired.is_empty() {
                    expected_catalog.map_or(marker_basis.identity(), |(expected_identity, _)| {
                        expected_identity
                    })
                } else {
                    marker_basis.identity()
                };
                let publication = (|| {
                    #[cfg(any(test, fuzzing, feature = "test-support"))]
                    super::fault::emit_event(
                        super::fault::LedgerFileEvent::BeforeLeaseMarkerPublication,
                    )?;
                    publish_many_with_expected_catalog(
                        self.catalog,
                        &marker_basis,
                        expected_identity,
                        &BTreeSet::from([identity]),
                        vec![encoded],
                    )
                })();
                if let Err(failure) = publication {
                    if failure.completion_state() == super::LedgerCompletionState::CommitAmbiguous {
                        state.lease_resume_markers.remove(&identity);
                    } else {
                        transaction.rollback(&mut state)?;
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
                transaction.commit(&mut state);
                (resume_count, repeated_batch_count, Some(attempt))
            } else {
                (record.resume_count, record.repeated_batch_count, None)
            };
        Ok(SnapshotLeaseGrant {
            identity,
            expiry: record.expiry,
            resume_count,
            repeated_batch_count,
            usage: record.usage,
            snapshot,
            attempt,
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
}
