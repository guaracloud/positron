use std::collections::BTreeSet;

use super::capacity::lease_claim;
use super::snapshot_lease::{map_catalog_failure, publish_many, records, rollback_marker_resize};
use super::snapshot_lease_codec::encode;
use super::snapshot_lease_record::{
    LeaseRecord, LeaseResumeMarker, SnapshotLeaseId, SnapshotLeaseUsage, validate_active_lease,
};
use super::{ActiveSegmentLedger, LedgerFailure, LedgerFailureCode};

fn cache_marker(state: &mut super::state::LedgerState<'_>, record: &LeaseRecord) {
    state.lease_resume_markers.insert(
        record.identity,
        LeaseResumeMarker {
            sequence: record.last_resume_sequence.unwrap_or_default(),
            prior_digest: record.last_resume_prior_digest,
            attempts: record.resume_count,
            repeats: record.repeated_batch_count,
            usage: record.usage,
        },
    );
}

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
        let expected_encoded = encoded.clone();
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
            if failure.completion_state() == super::LedgerCompletionState::CommitAmbiguous {
                return self.reconcile_ambiguous_usage(
                    &mut state,
                    identity,
                    &record,
                    &updated,
                    &expected_encoded,
                    previous_amounts,
                );
            }
            rollback_marker_resize(&mut state, identity, previous_amounts)?;
            return Err(failure);
        }
        cache_marker(&mut state, &updated);
        Ok(usage)
    }

    pub(super) fn reconcile_ambiguous_usage(
        &self,
        state: &mut super::state::LedgerState<'_>,
        identity: SnapshotLeaseId,
        previous: &LeaseRecord,
        expected: &LeaseRecord,
        expected_encoded: &[u8],
        previous_amounts: crate::ResourceAmounts,
    ) -> Result<SnapshotLeaseUsage, LedgerFailure> {
        let observed = self
            .catalog
            .refresh_state()
            .ok()
            .and_then(|()| self.catalog.pin().ok())
            .and_then(|snapshot| {
                snapshot.plaintext_objects().find_map(|bytes| {
                    let record = super::snapshot_lease_codec::decode(bytes).ok().flatten()?;
                    (record.identity == identity && record.scope == self.scope).then_some(record)
                })
            });

        if let Some(record) = observed.as_ref() {
            if record.usage == expected.usage
                && super::snapshot_lease_codec::encode(record)
                    .ok()
                    .is_some_and(|encoded| encoded == expected_encoded)
            {
                cache_marker(state, record);
                return Ok(record.usage);
            }
            if record.usage == previous.usage {
                cache_marker(state, record);
                rollback_marker_resize(state, identity, previous_amounts)?;
                return Err(LedgerFailure::ambiguous(
                    LedgerFailureCode::StorageUnavailable,
                ));
            }
        }

        // The durable outcome cannot be proven. Drop the in-memory marker so a
        // bounded refresh on the next attempt cannot turn an ambiguous write
        // into a false integrity failure. Keep the enlarged reservation until
        // that retry reconciles the durable record.
        state.lease_resume_markers.remove(&identity);
        Err(LedgerFailure::ambiguous(
            LedgerFailureCode::StorageUnavailable,
        ))
    }
}
