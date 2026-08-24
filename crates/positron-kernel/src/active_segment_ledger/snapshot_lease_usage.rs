use std::collections::BTreeSet;

use super::capacity::lease_claim;
use super::snapshot_lease::{map_catalog_failure, publish_many, records, rollback_marker_resize};
use super::snapshot_lease_codec::encode;
use super::snapshot_lease_record::{
    LeaseResumeMarker, SnapshotLeaseId, SnapshotLeaseUsage, validate_active_lease,
};
use super::{ActiveSegmentLedger, LedgerFailure, LedgerFailureCode};

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    /// Returns the physical work charged to an active lease.
    ///
    /// Usage is durable lease state rather than cursor state, so reconnecting
    /// with an older immutable cursor cannot reset its budget accounting.
    pub fn snapshot_lease_usage(
        &self,
        identity: SnapshotLeaseId,
        now: u64,
    ) -> Result<SnapshotLeaseUsage, LedgerFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        self.retry_pending_releases(&mut state)?;
        if now < state.last_snapshot_lease_time {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        self.catalog
            .refresh_state()
            .map_err(|failure| LedgerFailure::new(map_catalog_failure(failure.code())))?;
        let basis = self.catalog.pin()?;
        let record = records(&basis)?
            .into_iter()
            .find(|record| record.identity == identity && record.scope == self.scope)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::SnapshotExpired))?;
        if now >= record.expiry {
            return Err(LedgerFailure::new(LedgerFailureCode::SnapshotExpired));
        }
        validate_active_lease(&record, now)?;
        if !state.lease_reservations.contains_key(&identity) {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        Ok(record.usage)
    }

    /// Adds physical work to the bounded durable usage record of a lease.
    ///
    /// The marker replacement and reservation resize are committed as one
    /// bounded publication. A failed, non-ambiguous publication restores the
    /// previous reservation before returning the failure.
    pub fn record_snapshot_lease_usage(
        &self,
        identity: SnapshotLeaseId,
        delta: SnapshotLeaseUsage,
    ) -> Result<SnapshotLeaseUsage, LedgerFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        self.retry_pending_releases(&mut state)?;
        self.catalog
            .refresh_state()
            .map_err(|failure| LedgerFailure::new(map_catalog_failure(failure.code())))?;
        let basis = self.catalog.pin()?;
        let record = records(&basis)?
            .into_iter()
            .find(|record| record.identity == identity && record.scope == self.scope)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::SnapshotExpired))?;
        let now = state.last_snapshot_lease_time;
        if now >= record.expiry {
            return Err(LedgerFailure::new(LedgerFailureCode::SnapshotExpired));
        }
        validate_active_lease(&record, now)?;
        if !state.lease_reservations.contains_key(&identity) {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        let usage = record.usage.merge(delta)?;
        if usage == record.usage {
            return Ok(usage);
        }

        let mut updated = record.clone();
        updated.usage = usage;
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
                    .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
            }
            previous
        };
        if let Err(failure) = publish_many(
            self.catalog,
            &basis,
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
            LeaseResumeMarker {
                sequence: updated.last_resume_sequence.unwrap_or_default(),
                prior_digest: updated.last_resume_prior_digest,
                attempts: updated.resume_count,
                repeats: updated.repeated_batch_count,
                usage,
            },
        );
        Ok(usage)
    }
}
