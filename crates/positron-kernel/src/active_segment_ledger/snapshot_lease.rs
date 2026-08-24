use std::collections::BTreeSet;

use positron_domain::routing::CommitPosition;

use crate::catalog::{
    CatalogFailureCode, CatalogObject, CatalogProposal, FormatEpoch, TransactionId,
};
use crate::data_protection::DataProtection;
use crate::{WorkClaim, WorkKind};

use super::LedgerFailureCode::ResourceAdmissionRefused;
use super::capacity::{lease_claim, snapshot_retained_claim};
use super::snapshot_lease_codec::{decode, encode};
use super::snapshot_lease_record::{
    LeaseBlock, LeaseRecord, SnapshotLeaseId, valid_lease_interval, validate_active_lease,
};
use super::{
    ActiveSegmentLedger, FORMAT_EPOCH, LedgerFailure, LedgerFailureCode, LedgerSnapshot,
    SegmentScope, map_frame_failure,
};
pub(super) const MAX_SNAPSHOT_LEASES: usize = 64;

pub struct SnapshotLeaseGrant<'kernel> {
    identity: SnapshotLeaseId,
    expiry: u64,
    resume_count: u64,
    repeated_batch_count: u64,
    snapshot: LedgerSnapshot<'kernel>,
}

impl std::fmt::Debug for SnapshotLeaseGrant<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotLeaseGrant")
            .field("identity", &self.identity)
            .field("expiry", &self.expiry)
            .field("snapshot", &"<pinned>")
            .finish()
    }
}

impl<'kernel> SnapshotLeaseGrant<'kernel> {
    #[must_use]
    pub const fn identity(&self) -> SnapshotLeaseId {
        self.identity
    }

    #[must_use]
    pub const fn expiry(&self) -> u64 {
        self.expiry
    }

    #[must_use]
    pub const fn resume_count(&self) -> u64 {
        self.resume_count
    }

    #[must_use]
    pub const fn repeated_batch_count(&self) -> u64 {
        self.repeated_batch_count
    }

    #[must_use]
    pub const fn snapshot(&self) -> &LedgerSnapshot<'kernel> {
        &self.snapshot
    }

    #[must_use]
    pub fn into_snapshot(self) -> LedgerSnapshot<'kernel> {
        self.snapshot
    }
}

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
                });
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

    fn retry_pending_releases(
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

fn rollback_marker_resize(
    state: &mut super::state::LedgerState<'_>,
    identity: SnapshotLeaseId,
    previous_amounts: crate::ResourceAmounts,
) -> Result<(), LedgerFailure> {
    let reservation = state
        .lease_reservations
        .get_mut(&identity)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    if reservation.granted() != previous_amounts {
        reservation
            .try_resize(previous_amounts)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
    }
    Ok(())
}

fn snapshot_from_record<'kernel>(
    ledger: &ActiveSegmentLedger<'kernel, '_>,
    state: &super::state::LedgerState<'kernel>,
    record: &LeaseRecord,
) -> Result<LedgerSnapshot<'kernel>, LedgerFailure> {
    if record.blocks.len() > state.blocks.len() || record.frontier > state.frontier {
        return Err(LedgerFailure::new(LedgerFailureCode::SnapshotExpired));
    }
    let blocks = state
        .blocks
        .get(..record.blocks.len())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    if !blocks.iter().zip(&record.blocks).all(|(actual, expected)| {
        actual.identity == expected.identity
            && actual.position == expected.position
            && actual.segment == expected.segment
    }) || blocks
        .last()
        .map_or(CommitPosition::origin(), |block| block.position)
        != record.frontier
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let bytes = blocks
        .iter()
        .try_fold(0_usize, |total, block| {
            total.checked_add(block.payload.len())
        })
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let claim = WorkClaim::tenant(
        record.scope.tenant,
        WorkKind::InteractiveQueryTail,
        snapshot_retained_claim(bytes, blocks.len())?,
    )
    .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let capacity = ledger
        .authority
        .governor()
        .reserve(claim)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    Ok(LedgerSnapshot {
        _capacity: capacity,
        scope: record.scope,
        frontier: record.frontier,
        catalog_generation: record.catalog_generation,
        catalog_identity: record.catalog_identity,
        blocks: blocks.to_vec(),
    })
}

fn publish(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    remove: &BTreeSet<SnapshotLeaseId>,
    add: Option<Vec<u8>>,
) -> Result<(), LedgerFailure> {
    publish_many(catalog, basis, remove, add.into_iter().collect())
}

pub(super) fn publish_many(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    remove: &BTreeSet<SnapshotLeaseId>,
    add: Vec<Vec<u8>>,
) -> Result<(), LedgerFailure> {
    let mut objects = basis
        .plaintext_objects()
        .filter(|bytes| {
            decode(bytes)
                .ok()
                .flatten()
                .is_none_or(|record| !remove.contains(&record.identity))
        })
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    for encoded in &add {
        objects.push(CatalogObject::new(encoded.clone())?);
    }
    let transaction = TransactionId::new(fresh_identity()?.to_bytes())?;
    match catalog.commit(
        basis.identity(),
        CatalogProposal::new(transaction, FormatEpoch::new(FORMAT_EPOCH)?, objects)?,
        None,
    ) {
        Ok(_) => Ok(()),
        Err(failure) => {
            let code = map_catalog_failure(failure.code());
            if catalog.refresh_state().is_err() {
                return Err(LedgerFailure::ambiguous(code));
            }
            let current = catalog.pin().map_err(|_| LedgerFailure::ambiguous(code))?;
            if publication_visible(&current, remove, &add) {
                Ok(())
            } else {
                Err(LedgerFailure::new(code))
            }
        },
    }
}

fn publication_visible(
    snapshot: &crate::CatalogSnapshot,
    remove: &BTreeSet<SnapshotLeaseId>,
    additions: &[Vec<u8>],
) -> bool {
    let replacement_ids = additions
        .iter()
        .filter_map(|bytes| decode(bytes).ok().flatten())
        .map(|record| record.identity)
        .collect::<BTreeSet<_>>();
    let objects = snapshot.plaintext_objects().collect::<Vec<_>>();
    let mut decoded = Vec::new();
    for bytes in &objects {
        match decode(bytes) {
            Ok(Some(record)) => decoded.push(record.identity),
            Ok(None) => {},
            Err(_) => return false,
        }
    }
    remove.iter().all(|identity| {
        replacement_ids.contains(identity) || !decoded.iter().any(|candidate| candidate == identity)
    }) && additions
        .iter()
        .all(|addition| objects.contains(&addition.as_slice()))
}

fn map_catalog_failure(code: CatalogFailureCode) -> LedgerFailureCode {
    match code {
        CatalogFailureCode::InvalidInput => LedgerFailureCode::InvalidInput,
        CatalogFailureCode::LimitExceeded => LedgerFailureCode::LimitExceeded,
        CatalogFailureCode::StaleGeneration => LedgerFailureCode::StaleGeneration,
        CatalogFailureCode::IdempotencyConflict => LedgerFailureCode::IdempotencyConflict,
        CatalogFailureCode::StorageUnavailable => LedgerFailureCode::StorageUnavailable,
        CatalogFailureCode::IntegrityCorruption => LedgerFailureCode::IntegrityCorruption,
        CatalogFailureCode::AuthenticationFailed => LedgerFailureCode::AuthenticationFailed,
        CatalogFailureCode::ConcurrentWriter => LedgerFailureCode::ConcurrentWriter,
        CatalogFailureCode::ResourceAdmissionRefused => LedgerFailureCode::ResourceAdmissionRefused,
        CatalogFailureCode::UnsupportedFormat => LedgerFailureCode::UnsupportedFormat,
    }
}

pub(super) fn expired_in_scope(
    records: &[LeaseRecord],
    scope: SegmentScope,
    now: u64,
) -> BTreeSet<SnapshotLeaseId> {
    records
        .iter()
        .filter(|record| record.scope == scope && now >= record.expiry)
        .map(|record| record.identity)
        .collect()
}

fn reject_time_regression(
    state: &super::state::LedgerState<'_>,
    now: u64,
) -> Result<(), LedgerFailure> {
    if now < state.last_snapshot_lease_time {
        return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
    }
    Ok(())
}

fn remove_reservations(
    state: &mut super::state::LedgerState<'_>,
    identities: &BTreeSet<SnapshotLeaseId>,
) {
    for identity in identities {
        state.lease_reservations.remove(identity);
        state.lease_resume_markers.remove(identity);
    }
}

pub(super) fn records(
    snapshot: &crate::CatalogSnapshot,
) -> Result<Vec<LeaseRecord>, LedgerFailure> {
    let mut records = Vec::new();
    for bytes in snapshot.plaintext_objects() {
        if let Some(record) = decode(bytes)? {
            records.push(record);
        }
    }
    Ok(records)
}

fn fresh_identity() -> Result<SnapshotLeaseId, LedgerFailure> {
    let random = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let bytes = random
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
    SnapshotLeaseId::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::{CatalogFailureCode, LedgerFailureCode, map_catalog_failure};

    #[test]
    fn catalog_failure_mapping_preserves_typed_lease_failures() {
        let cases = [
            (
                CatalogFailureCode::InvalidInput,
                LedgerFailureCode::InvalidInput,
            ),
            (
                CatalogFailureCode::LimitExceeded,
                LedgerFailureCode::LimitExceeded,
            ),
            (
                CatalogFailureCode::StaleGeneration,
                LedgerFailureCode::StaleGeneration,
            ),
            (
                CatalogFailureCode::IdempotencyConflict,
                LedgerFailureCode::IdempotencyConflict,
            ),
            (
                CatalogFailureCode::StorageUnavailable,
                LedgerFailureCode::StorageUnavailable,
            ),
            (
                CatalogFailureCode::IntegrityCorruption,
                LedgerFailureCode::IntegrityCorruption,
            ),
            (
                CatalogFailureCode::AuthenticationFailed,
                LedgerFailureCode::AuthenticationFailed,
            ),
            (
                CatalogFailureCode::ConcurrentWriter,
                LedgerFailureCode::ConcurrentWriter,
            ),
            (
                CatalogFailureCode::ResourceAdmissionRefused,
                LedgerFailureCode::ResourceAdmissionRefused,
            ),
            (
                CatalogFailureCode::UnsupportedFormat,
                LedgerFailureCode::UnsupportedFormat,
            ),
        ];

        for (catalog, expected) in cases {
            assert_eq!(map_catalog_failure(catalog), expected);
        }
    }
}
