use positron_domain::identity::TenantId;
use positron_kernel::{
    ResourceAmounts, ResourceDimension, ResourceGovernor, ResourceReservation, WorkClaim, WorkKind,
};
use positron_signals::SchemaBudget;

use super::SchemaSessionFailure;

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
