use std::collections::BTreeSet;

use positron_domain::routing::CommitPosition;

use crate::catalog::{
    CatalogFailureCode, CatalogObject, CatalogProposal, FormatEpoch, TransactionId,
};
use crate::data_protection::DataProtection;

use super::super::format::SegmentState;
use super::super::recovery::RecoveryMode;
use super::super::snapshot_lease_codec::decode;
use super::super::snapshot_lease_record::{LeaseRecord, SnapshotLeaseId};
use super::super::{
    ActiveSegmentLedger, CommittedBlock, FORMAT_EPOCH, LedgerFailure, LedgerFailureCode,
    LedgerSnapshot, SegmentScope, map_frame_failure,
};

fn rollback_lease_reservation(
    state: &mut super::super::state::LedgerState<'_>,
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

pub(crate) struct LeaseReservationTransaction {
    identity: SnapshotLeaseId,
    original: crate::ResourceAmounts,
}

impl LeaseReservationTransaction {
    pub(crate) fn begin(
        state: &mut super::super::state::LedgerState<'_>,
        identity: SnapshotLeaseId,
    ) -> Result<Self, LedgerFailure> {
        let original = state
            .lease_reservation_baselines
            .get(&identity)
            .copied()
            .or_else(|| {
                state
                    .lease_reservations
                    .get(&identity)
                    .map(|value| value.granted())
            })
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        state.lease_reservation_baselines.insert(identity, original);
        Ok(Self { identity, original })
    }

    pub(crate) fn resize(
        &self,
        state: &mut super::super::state::LedgerState<'_>,
        amounts: crate::ResourceAmounts,
    ) -> Result<(), LedgerFailure> {
        let reservation = state
            .lease_reservations
            .get_mut(&self.identity)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        if reservation.granted() != amounts {
            reservation
                .try_resize_preserving_capacity(amounts)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        }
        Ok(())
    }

    pub(crate) fn commit(self, state: &mut super::super::state::LedgerState<'_>) {
        state.lease_reservation_baselines.remove(&self.identity);
    }

    pub(crate) fn cancel(self, state: &mut super::super::state::LedgerState<'_>) {
        state.lease_reservation_baselines.remove(&self.identity);
    }

    pub(crate) fn rollback(
        self,
        state: &mut super::super::state::LedgerState<'_>,
    ) -> Result<(), LedgerFailure> {
        rollback_lease_reservation(state, self.identity, self.original)?;
        state.lease_reservation_baselines.remove(&self.identity);
        Ok(())
    }
}

pub(crate) fn snapshot_from_record<'kernel>(
    ledger: &ActiveSegmentLedger<'kernel, '_>,
    state: &super::super::state::LedgerState<'kernel>,
    record: &LeaseRecord,
) -> Result<LedgerSnapshot<'kernel>, LedgerFailure> {
    if record.scope != ledger.scope || record.frontier > state.frontier {
        return Err(LedgerFailure::new(LedgerFailureCode::SnapshotExpired));
    }
    let maximum_bytes = record.blocks.iter().try_fold(0_usize, |total, expected| {
        let bytes = state
            .blocks
            .iter()
            .find(|actual| {
                actual.identity == expected.identity
                    && actual.position == expected.position
                    && actual.segment == expected.segment
            })
            .map_or(super::super::MAX_STORE_BLOCK_BYTES, |block| {
                block.payload.len()
            });
        total
            .checked_add(bytes)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
    })?;
    let recovery = resume_recovery_plan(ledger, state, record)?;
    let admitted = if recovery.segments.is_empty() {
        // Creating a lease clones only already-retained blocks. The caller's
        // admitted query task covers construction work, while this claim must
        // precede and cover the retained clone allocation itself.
        super::super::capacity::snapshot_retained_claim(maximum_bytes, record.blocks.len())?
    } else {
        let recovery_working_bytes = recovery
            .encoded_bytes
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(maximum_bytes))
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let recovery_items = recovery
            .segments
            .len()
            .checked_mul(super::super::MAX_RETAINED_BLOCKS)
            .and_then(|items| items.checked_add(record.blocks.len()))
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        super::super::capacity::snapshot_resume_claim(
            recovery_working_bytes,
            recovery.encoded_bytes,
            recovery_items,
            recovery.segments.len(),
        )?
    };
    let maximum_claim = crate::WorkClaim::tenant(
        record.scope.tenant,
        crate::WorkKind::InteractiveQueryTail,
        admitted,
    )
    .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut capacity = ledger
        .authority
        .governor()
        .reserve(maximum_claim)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    let blocks = blocks_for_record(ledger, state, record, &recovery.segments)?;
    let bytes = blocks
        .iter()
        .try_fold(0_usize, |total, block| {
            total.checked_add(block.payload.len())
        })
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    capacity
        .try_resize_preserving_capacity(super::super::capacity::snapshot_retained_claim(
            bytes,
            blocks.len(),
        )?)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    Ok(LedgerSnapshot {
        _capacity: capacity,
        _protection: super::super::snapshot_protection::SnapshotProtection::for_blocks(
            ledger.authority.snapshot_protection(),
            ledger.authority.snapshot_barrier(),
            &blocks,
        )?,
        scope: record.scope,
        frontier: record.frontier,
        catalog_generation: record.catalog_generation,
        catalog_identity: record.catalog_identity,
        blocks,
    })
}

struct ResumeRecoveryPlan {
    segments: Vec<super::super::format::SegmentMetadata>,
    encoded_bytes: usize,
}

fn resume_recovery_plan(
    ledger: &ActiveSegmentLedger<'_, '_>,
    state: &super::super::state::LedgerState<'_>,
    record: &LeaseRecord,
) -> Result<ResumeRecoveryPlan, LedgerFailure> {
    let mut missing = BTreeSet::new();
    for expected in &record.blocks {
        let exact = state.blocks.iter().any(|actual| {
            actual.identity == expected.identity
                && actual.position == expected.position
                && actual.segment == expected.segment
        });
        if exact {
            continue;
        }
        if state.blocks.iter().any(|actual| {
            actual.position == expected.position && actual.segment == expected.segment
        }) || state
            .blocks
            .iter()
            .any(|actual| actual.segment == expected.segment)
        {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        missing.insert(expected.segment);
    }
    if missing.is_empty() {
        return Ok(ResumeRecoveryPlan {
            segments: Vec::new(),
            encoded_bytes: 0,
        });
    }
    ledger.catalog.refresh_state()?;
    let basis = ledger.catalog.pin()?;
    let metadata = ledger
        .storage
        .catalog_segments_observed(&basis, record.scope)?;
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(missing.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut encoded_bytes = 0_usize;
    for identity in missing {
        let segment = metadata
            .iter()
            .find(|candidate| candidate.id == identity && candidate.state == SegmentState::Retired)
            .copied()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::SnapshotExpired))?;
        encoded_bytes = encoded_bytes
            .checked_add(ledger.storage.retired_recovery_encoded_bytes(segment)?)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        segments.push(segment);
    }
    Ok(ResumeRecoveryPlan {
        segments,
        encoded_bytes,
    })
}

fn blocks_for_record<'kernel>(
    ledger: &ActiveSegmentLedger<'kernel, '_>,
    state: &super::super::state::LedgerState<'kernel>,
    record: &LeaseRecord,
    missing_metadata: &[super::super::format::SegmentMetadata],
) -> Result<Vec<CommittedBlock>, LedgerFailure> {
    let mut missing_segments = BTreeSet::new();
    for expected in &record.blocks {
        let exact = state.blocks.iter().any(|actual| {
            actual.identity == expected.identity
                && actual.position == expected.position
                && actual.segment == expected.segment
        });
        if exact {
            continue;
        }
        if state
            .blocks
            .iter()
            .any(|actual| actual.segment == expected.segment)
        {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        missing_segments.insert(expected.segment);
    }

    let mut recovered = Vec::new();
    recovered
        .try_reserve_exact(record.blocks.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if !missing_segments.is_empty() {
        for metadata in missing_metadata.iter().copied() {
            let (_key, recovered_segment) = ledger.storage.recover_segment_with_mode(
                metadata,
                &ledger.protection,
                ledger.catalog.instance(),
                RecoveryMode::Observe,
            )?;
            recovered.extend(recovered_segment.blocks);
        }
    }

    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(record.blocks.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for expected in &record.blocks {
        let block = state
            .blocks
            .iter()
            .find(|actual| {
                actual.identity == expected.identity
                    && actual.position == expected.position
                    && actual.segment == expected.segment
            })
            .or_else(|| {
                recovered.iter().find(|actual| {
                    actual.identity == expected.identity
                        && actual.position == expected.position
                        && actual.segment == expected.segment
                })
            })
            .ok_or_else(|| {
                if recovered
                    .iter()
                    .any(|actual| actual.segment == expected.segment)
                {
                    LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)
                } else {
                    LedgerFailure::new(LedgerFailureCode::SnapshotExpired)
                }
            })?;
        blocks.push(block.clone());
    }
    let mut previous_position = None;
    for block in &blocks {
        if previous_position.is_some_and(|previous| block.position <= previous) {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        previous_position = Some(block.position);
    }
    if blocks
        .last()
        .map_or(CommitPosition::origin(), |block| block.position)
        != record.frontier
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    Ok(blocks)
}

pub(crate) fn active_segments(
    snapshot: &crate::CatalogSnapshot,
    scope: SegmentScope,
    now: u64,
) -> Result<BTreeSet<super::super::SegmentId>, LedgerFailure> {
    let mut segments = BTreeSet::new();
    for record in records(snapshot)? {
        if record.scope == scope && now < record.expiry {
            for block in record.blocks {
                segments.insert(block.segment);
            }
        }
    }
    Ok(segments)
}

pub(super) fn publish(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    remove: &BTreeSet<SnapshotLeaseId>,
    add: Option<Vec<u8>>,
) -> Result<(), LedgerFailure> {
    publish_many(catalog, basis, remove, add.into_iter().collect())
}

pub(crate) fn publish_many(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    remove: &BTreeSet<SnapshotLeaseId>,
    add: Vec<Vec<u8>>,
) -> Result<(), LedgerFailure> {
    publish_many_with_expected_catalog(catalog, basis, basis.identity(), remove, add)
}

pub(crate) fn publish_many_with_expected_catalog(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    expected_catalog: crate::CatalogGenerationId,
    remove: &BTreeSet<SnapshotLeaseId>,
    add: Vec<Vec<u8>>,
) -> Result<(), LedgerFailure> {
    publish_many_with_expected_catalog_inner(catalog, basis, expected_catalog, remove, add, true)
        .map(|_| ())
}

pub(crate) fn publish_many_with_expected_catalog_snapshot(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    expected_catalog: crate::CatalogGenerationId,
    remove: &BTreeSet<SnapshotLeaseId>,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    publish_many_with_expected_catalog_inner(
        catalog,
        basis,
        expected_catalog,
        remove,
        Vec::new(),
        false,
    )
}

fn publish_many_with_expected_catalog_inner(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    expected_catalog: crate::CatalogGenerationId,
    remove: &BTreeSet<SnapshotLeaseId>,
    add: Vec<Vec<u8>>,
    reconcile_visible: bool,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    let capacity = basis
        .plaintext_objects()
        .count()
        .checked_add(add.len())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(capacity)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for bytes in basis.plaintext_objects() {
        if decode(bytes)?.is_none_or(|record| !remove.contains(&record.identity)) {
            objects.push(CatalogObject::new(bytes.to_vec())?);
        }
    }
    for encoded in &add {
        objects.push(CatalogObject::new(encoded.clone())?);
    }
    let transaction = TransactionId::new(fresh_identity()?.to_bytes())?;
    match catalog.commit(
        expected_catalog,
        CatalogProposal::new(transaction, FormatEpoch::new(FORMAT_EPOCH)?, objects)?,
        None,
    ) {
        Ok(commit) => Ok(commit.snapshot().clone()),
        Err(failure) => {
            let code = map_catalog_failure(failure.code());
            if code == LedgerFailureCode::StaleGeneration {
                return Err(LedgerFailure::new(code));
            }
            if !reconcile_visible {
                return Err(match code {
                    LedgerFailureCode::StorageUnavailable => LedgerFailure::ambiguous(code),
                    _ => LedgerFailure::new(code),
                });
            }
            if catalog.refresh_state().is_err() {
                return Err(LedgerFailure::ambiguous(code));
            }
            let current = catalog.pin().map_err(|_| LedgerFailure::ambiguous(code))?;
            if publication_visible(&current, remove, &add)? {
                Ok(current)
            } else {
                Err(LedgerFailure::new(code))
            }
        },
    }
}

pub(crate) fn publication_visible(
    snapshot: &crate::CatalogSnapshot,
    remove: &BTreeSet<SnapshotLeaseId>,
    additions: &[Vec<u8>],
) -> Result<bool, LedgerFailure> {
    let published_records = records(snapshot)?;
    for identity in remove {
        let replaced =
            additions
                .iter()
                .try_fold(false, |found, addition| -> Result<bool, LedgerFailure> {
                    if found {
                        return Ok(true);
                    }
                    Ok(decode(addition)?.is_some_and(|record| record.identity == *identity))
                })?;
        if !replaced {
            let remains = published_records
                .iter()
                .any(|record| record.identity == *identity);
            if remains {
                return Ok(false);
            }
        }
    }
    for addition in additions {
        if !snapshot
            .plaintext_objects()
            .any(|published| published == addition.as_slice())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn map_catalog_failure(code: CatalogFailureCode) -> LedgerFailureCode {
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

pub(crate) fn expired_in_scope(
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

pub(super) fn reject_time_regression(
    state: &super::super::state::LedgerState<'_>,
    now: u64,
) -> Result<(), LedgerFailure> {
    if now < state.last_snapshot_lease_time {
        return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
    }
    Ok(())
}

pub(super) fn remove_reservations(
    state: &mut super::super::state::LedgerState<'_>,
    identities: &BTreeSet<SnapshotLeaseId>,
) {
    for identity in identities {
        state.lease_reservations.remove(identity);
        state.lease_reservation_baselines.remove(identity);
        state.lease_resume_markers.remove(identity);
        state.pending_lease_releases.remove(*identity);
    }
}

pub(crate) fn records(
    snapshot: &crate::CatalogSnapshot,
) -> Result<Vec<LeaseRecord>, LedgerFailure> {
    let mut records = Vec::new();
    records
        .try_reserve_exact(snapshot.plaintext_objects().count())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for bytes in snapshot.plaintext_objects() {
        if let Some(record) = decode(bytes)? {
            records.push(record);
        }
    }
    Ok(records)
}

pub(crate) fn fresh_identity() -> Result<SnapshotLeaseId, LedgerFailure> {
    let random = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let bytes = random
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
    SnapshotLeaseId::new(bytes)
}
