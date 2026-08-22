use positron_domain::identity::TenantId;
use positron_kernel::{
    ResourceAmounts, ResourceDimension, ResourceGovernor, ResourceReservation,
    TransferredResourceReservation, WorkClaim, WorkKind,
};
use positron_signals::SchemaBudget;
use std::mem::size_of;

use super::SchemaSessionFailure;

/// Allocation-free bounds collected during the immutable replay preflight.
///
/// The serving replay allocates its candidate catalog, frontier copy, and
/// retained reservation slots only after this full peak is admitted.  The
/// block stream is immutable, so the second pass can revisit it without
/// retaining per-block vectors before admission. Bootstrap's separate
/// reachable-index allocation is admitted by `SchemaReplayBuilder`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReplaySnapshotBounds {
    pub(super) block_count: usize,
    pub(super) total_payload_bytes: usize,
    pub(super) maximum_payload_bytes: usize,
    pub(super) mandatory_work: u64,
    pub(super) optional_work: u64,
    pub(super) scratch_memory_bytes: usize,
}

impl ReplaySnapshotBounds {
    pub(super) fn new(
        block_count: usize,
        total_payload_bytes: usize,
        maximum_payload_bytes: usize,
        mandatory_work: u64,
        optional_work: u64,
        catalog_memory_bytes: usize,
    ) -> Result<Self, SchemaSessionFailure> {
        if total_payload_bytes < maximum_payload_bytes {
            return Err(SchemaSessionFailure::ReplayLimitExceeded);
        }
        let candidate_frontiers = super::MAX_REPLAY_SHARDS
            .checked_mul(size_of::<positron_signals::SchemaCheckpointFrontier>())
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
        let retained_slots = block_count
            .checked_mul(size_of::<TransferredResourceReservation>())
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
        let per_block = SchemaBudget::replay_working_memory_bytes(maximum_payload_bytes)
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
        let scratch_memory_bytes = catalog_memory_bytes
            .checked_add(candidate_frontiers)
            .and_then(|bytes| bytes.checked_add(retained_slots))
            .and_then(|bytes| bytes.checked_add(per_block))
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
        Ok(Self {
            block_count,
            total_payload_bytes,
            maximum_payload_bytes,
            mandatory_work,
            optional_work,
            scratch_memory_bytes,
        })
    }
}

pub(super) fn reserve_replay_decode_capacity(
    tenant: TenantId,
    payload_bytes: usize,
    governor: ResourceGovernor<'_>,
) -> Result<ResourceReservation<'_>, SchemaSessionFailure> {
    let memory = u64::try_from(
        SchemaBudget::replay_working_memory_bytes(payload_bytes)
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?,
    )
    .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    let complete_work = SchemaBudget::replay_schema_work_units(payload_bytes)
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    reserve_with_work(tenant, memory, complete_work, governor).or_else(|_| {
        let reduced_work = SchemaBudget::replay_decode_work_units(payload_bytes)
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
        reserve_with_work(tenant, memory, reduced_work, governor)
    })
}

/// Admits one replay transaction for all blocks selected by a snapshot.  The
/// returned flag records whether optional text evidence was admitted; the
/// mandatory decode/discovery/reachable-index work is never run without a
/// reservation for its full cumulative bound.
pub(super) fn reserve_replay_snapshot_capacity<'authority>(
    tenant: TenantId,
    bounds: ReplaySnapshotBounds,
    governor: ResourceGovernor<'authority>,
) -> Result<(ResourceReservation<'authority>, bool), SchemaSessionFailure> {
    let memory = u64::try_from(bounds.scratch_memory_bytes)
        .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    match bounds.mandatory_work.checked_add(bounds.optional_work) {
        Some(complete_work) => reserve_with_work(tenant, memory, complete_work, governor)
            .map(|reservation| (reservation, true))
            .or_else(|_| {
                reserve_with_work(tenant, memory, bounds.mandatory_work, governor)
                    .map(|reservation| (reservation, false))
            }),
        None => reserve_with_work(tenant, memory, bounds.mandatory_work, governor)
            .map(|reservation| (reservation, false)),
    }
}

pub(super) fn replay_snapshot_block_work(
    payload_bytes: usize,
) -> Result<(u64, u64), SchemaSessionFailure> {
    let mandatory_work = SchemaBudget::replay_decode_work_units(payload_bytes)
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?
        .checked_add(1)
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    let optional_work = SchemaBudget::text_index_work_units(payload_bytes)
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    Ok((mandatory_work, optional_work))
}

fn reserve_with_work(
    tenant: TenantId,
    memory: u64,
    cpu_work: u64,
    governor: ResourceGovernor<'_>,
) -> Result<ResourceReservation<'_>, SchemaSessionFailure> {
    let amounts = ResourceAmounts::new([memory, 0, 0, 0, 0, 0, 0, 0, cpu_work, 0, 0]);
    let claim = WorkClaim::tenant(tenant, WorkKind::Ingest, amounts)
        .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    governor
        .reserve(claim)
        .map_err(|_| SchemaSessionFailure::StateUnavailable)
}

pub(super) fn reserve_query_index_capacity(
    tenant: TenantId,
    payload_bytes: usize,
    governor: ResourceGovernor<'_>,
) -> Result<ResourceReservation<'_>, SchemaSessionFailure> {
    reserve_replay_decode_capacity(tenant, payload_bytes, governor)
}

pub(super) fn ensure_replay_capacity(
    capacity: &ResourceReservation<'_>,
    payload_bytes: usize,
) -> Result<(), SchemaSessionFailure> {
    let required = u64::try_from(
        SchemaBudget::replay_working_memory_bytes(payload_bytes)
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?,
    )
    .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    if capacity.granted().get(ResourceDimension::MemoryBytes) < required {
        Err(SchemaSessionFailure::StateUnavailable)
    } else {
        Ok(())
    }
}

pub(super) fn resize_replay_work(
    recovery: &mut ResourceReservation<'_>,
    payload_bytes: usize,
) -> Result<(), SchemaSessionFailure> {
    // Repair reservations are interruptible: a failed growth cancels the
    // existing grant. Bootstrap therefore admits the structural bound before
    // decode and lets the observed summary fail closed to reduced pruning
    // when its complete text bound cannot fit that one reservation.
    let reduced_work = SchemaBudget::replay_decode_work_units(payload_bytes)
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    let current = recovery.granted().get(ResourceDimension::MemoryBytes);
    let reduced = ResourceAmounts::new([current, 0, 0, 0, 0, 0, 0, 0, reduced_work, 0, 0]);
    recovery
        .try_resize(reduced)
        .map(|_| ())
        .map_err(|_| SchemaSessionFailure::StateUnavailable)
}

#[cfg(test)]
mod tests {
    use super::{ReplaySnapshotBounds, reserve_replay_snapshot_capacity};
    use positron_kernel::ResourceDimension;

    #[test]
    fn replay_snapshot_memory_admission_counts_tiny_block_slots_exactly() {
        let bounds = ReplaySnapshotBounds::new(64, 64, 1, 64, 128, 0).expect("bounds");
        let exact_memory = u64::try_from(bounds.scratch_memory_bytes).expect("bound");
        let exact_fixture = crate::tests::support::fixture_with_ordinary_memory(
            exact_memory.checked_add(20).expect("protected headroom"),
        )
        .expect("exact replay-capable fixture");
        let exact = reserve_replay_snapshot_capacity(
            exact_fixture.tenant,
            bounds,
            exact_fixture.authority.governor(),
        )
        .expect("exact scratch bound is admitted");
        assert_eq!(
            exact.0.granted().get(ResourceDimension::MemoryBytes),
            exact_memory
        );
        drop(exact);

        // The fixture keeps seven bytes of the fixed ordinary class headroom
        // available for a request that spills out of the shared pool. Leave
        // less than that headroom so the admitted scratch bound itself is the
        // limiting resource, rather than relying on an oversized fixture.
        let under_fixture = crate::tests::support::fixture_with_ordinary_memory(
            exact_memory.checked_add(13).expect("protected headroom"),
        )
        .expect("under-bound replay fixture");
        assert!(
            reserve_replay_snapshot_capacity(
                under_fixture.tenant,
                bounds,
                under_fixture.authority.governor(),
            )
            .is_err()
        );
    }
}
