//! Minimal native Log Signal Store.

mod codec;
mod failure;
#[cfg(fuzzing)]
mod fuzzing;
mod metadata;
mod policy_provenance;
mod scan;
mod schema;
mod schema_scan;
mod types;

#[cfg(fuzzing)]
pub use fuzzing::fuzz_log_store_block;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    CommittedBlock, LedgerSnapshot, LifecycleClock, LifecycleClockSource, PreparedStoreBlock,
    ResourceAmounts, ResourceDimension, ResourceGovernor, ResourceReservation, SegmentScope,
    StoreBlockIdentity, WorkClaim, WorkKind,
};

pub use failure::{LogStoreFailure, LogStoreFailureCode};
pub use metadata::LogMetadata;
pub use policy_provenance::PolicyProvenance;
pub use scan::{LogScan, LogScanResult, ScanCancellation, ScanLimit, ScannedLogRecord};
pub use schema::{
    OccurrenceSelector, SchemaBudget, SchemaBudgetPressure, SchemaCatalog,
    SchemaCheckpointFrontier, SchemaDelta, SchemaDiscovery, SchemaDiscoveryRequest, SchemaEntry,
    SchemaFailure, SchemaObservation, SchemaPath, SchemaPathDigest, SchemaPathSummary,
    SchemaPromotionDecision, SchemaPromotionReason, SchemaQuery, SchemaQueryResult,
    SchemaQueryUpdate, SchemaRepresentation, SchemaSessionStore, SchemaValue,
};
pub use types::{
    AttributeRepresentation, LogRecord, PreparedLogBlock, StoredLogAttribute, StoredLogRecord,
};

/// The concrete Release 1 Log Signal Store adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogStore;

impl LogStore {
    /// Constructs the stateless Log Store adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the single effective Release 1 Value Limit Profile.
    pub const fn value_limit_profile() -> positron_domain::value::ValueLimitProfile {
        types::value_profile()
    }

    /// Prepares one canonical, checked Log Store Block for kernel durability.
    pub fn prepare<'capacity, S: LifecycleClockSource>(
        &self,
        capacity: ResourceReservation<'capacity>,
        clock: &LifecycleClock<S>,
        tenant: TenantId,
        shard: VirtualShardId,
        identity: StoreBlockIdentity,
        records: Vec<LogRecord>,
    ) -> Result<PreparedLogBlock<'capacity>, LogStoreFailure> {
        self.prepare_internal(capacity, clock, tenant, shard, identity, records)
    }

    /// Prepares a block and its bounded schema delta without mutating live schema state.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_with_schema_delta<'capacity, S: LifecycleClockSource>(
        &self,
        capacity: ResourceReservation<'capacity>,
        clock: &LifecycleClock<S>,
        tenant: TenantId,
        shard: VirtualShardId,
        identity: StoreBlockIdentity,
        mut records: Vec<LogRecord>,
        schema: &SchemaCatalog,
    ) -> Result<(PreparedLogBlock<'capacity>, SchemaDelta), LogStoreFailure> {
        let delta = self.stage_schema_group(&mut records, schema)?;
        self.prepare_internal(capacity, clock, tenant, shard, identity, records)
            .map(|prepared| (prepared, delta))
    }

    /// Stages one complete group's root-atomic schema decisions against an immutable view.
    pub(crate) fn stage_schema_group(
        &self,
        records: &mut [LogRecord],
        schema: &SchemaCatalog,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        let mut delta = SchemaDelta::empty(schema.tenant(), true);
        let mut meter = schema::delta::DiscoveryMeter::new();
        for record in records.iter_mut() {
            let mut attributes = Vec::new();
            attributes
                .try_reserve_exact(record.attributes().len())
                .map_err(|_| LogStoreFailure::resource_exhausted())?;
            for attribute in record.attributes() {
                attributes.push(
                    attribute
                        .occurrences()
                        .try_clone()
                        .map_err(LogStoreFailure::domain)?,
                );
            }
            let observation = schema
                .stage_record(&attributes, &mut delta, &mut meter)
                .map_err(map_schema_failure)?;
            for (attribute, (_, representation)) in record
                .attributes_mut()
                .iter_mut()
                .zip(observation.attributes())
            {
                attribute.set_representation(match representation {
                    SchemaRepresentation::Cataloged => AttributeRepresentation::Generic,
                    SchemaRepresentation::Overflow => AttributeRepresentation::SchemaOverflow,
                });
            }
        }
        Ok(delta)
    }

    /// Applies a previously staged delta after its v2 block is durably resolved.
    pub(crate) fn apply_schema_delta(
        &self,
        schema: &mut SchemaCatalog,
        delta: SchemaDelta,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<(), LogStoreFailure> {
        if schema.tenant() != delta.tenant() {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        let (delta, block_index) = delta.into_block_index(identity, digest);
        schema
            .apply_delta(delta, block_index)
            .map_err(map_schema_failure)
    }

    /// Reconstructs one committed v2 block's schema delta without changing Store Block grammar.
    pub(crate) fn replay_schema_block(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        schema: &SchemaCatalog,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        let decoded = codec::decode_block(tenant, snapshot, block.payload(), usize::MAX)?;
        if schema.tenant() != tenant {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        let mut delta = SchemaDelta::empty(tenant, true);
        let mut meter = schema::delta::DiscoveryMeter::new();
        for record in decoded.records {
            schema
                .stage_replayed_record(record.attributes(), &mut delta, &mut meter)
                .map_err(map_schema_failure)?;
        }
        Ok(delta)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_internal<'capacity, S: LifecycleClockSource>(
        &self,
        capacity: ResourceReservation<'capacity>,
        clock: &LifecycleClock<S>,
        tenant: TenantId,
        shard: VirtualShardId,
        identity: StoreBlockIdentity,
        records: Vec<LogRecord>,
    ) -> Result<PreparedLogBlock<'capacity>, LogStoreFailure> {
        if !capacity.authorizes_ingest_preparation(tenant, 1_048_576) {
            return Err(LogStoreFailure::resource_admission_refused());
        }
        let encoded_bytes = codec::encoded_block_length(&records)?;
        let stored = records
            .into_iter()
            .map(|record| {
                clock
                    .assign_ingest_time()
                    .map(|ingest_time| StoredLogRecord::new(record, ingest_time))
                    .map_err(|_| LogStoreFailure::clock_unavailable())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bytes = codec::encode_block(tenant, &stored, encoded_bytes)?;
        let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
        let block =
            PreparedStoreBlock::new_with_preparation_capacity(scope, identity, bytes, capacity)
                .map_err(LogStoreFailure::kernel)?;
        Ok(PreparedLogBlock::new(block))
    }

    /// Scans verified committed blocks up to the caller's explicit result bound.
    pub fn scan<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: LogScan,
    ) -> Result<LogScanResult<'kernel>, LogStoreFailure> {
        self.scan_cancellable(governor, tenant, snapshot, scan, &scan::NeverCancelled)
    }

    /// Scans verified committed blocks with cooperative caller cancellation.
    pub fn scan_cancellable<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: LogScan,
        cancellation: &dyn ScanCancellation,
    ) -> Result<LogScanResult<'kernel>, LogStoreFailure> {
        let scope = snapshot.scope();
        if scope.tenant_id() != tenant || scope.signal_kind() != SignalKind::Logs {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        check_scan_cancellation(cancellation)?;
        let encoded_bytes = snapshot
            .blocks()
            .iter()
            .filter(|block| {
                scan.frontier()
                    .is_none_or(|frontier| block.position() <= frontier)
            })
            .try_fold(0_u64, |total, block| {
                total.checked_add(u64::try_from(block.payload().len()).ok()?)
            })
            .ok_or_else(LogStoreFailure::limit_exceeded)?;
        let memory = encoded_bytes
            .checked_add(
                u64::try_from(scan.limit().value())
                    .map_err(|_| LogStoreFailure::limit_exceeded())?
                    .saturating_mul(512),
            )
            .ok_or_else(LogStoreFailure::limit_exceeded)?
            .max(1);
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, memory)
            .map_err(|_| LogStoreFailure::limit_exceeded())?;
        let claim = WorkClaim::tenant(tenant, WorkKind::InteractiveQueryTail, amounts)
            .map_err(|_| LogStoreFailure::limit_exceeded())?;
        let capacity = governor
            .reserve(claim)
            .map_err(|_| LogStoreFailure::resource_admission_refused())?;
        check_scan_cancellation(cancellation)?;
        let mut records = Vec::new();
        let mut scanned_bytes = 0_u64;
        let limit = scan.limit().value();
        let mut complete = true;
        for block in snapshot.blocks() {
            check_scan_cancellation(cancellation)?;
            if scan
                .frontier()
                .is_some_and(|frontier| block.position() > frontier)
            {
                continue;
            }
            scanned_bytes = scanned_bytes
                .checked_add(
                    u64::try_from(block.payload().len())
                        .map_err(|_| LogStoreFailure::limit_exceeded())?,
                )
                .ok_or_else(LogStoreFailure::limit_exceeded)?;
            let remaining = limit.saturating_sub(records.len());
            let decoded = codec::decode_block_cancellable(
                tenant,
                snapshot,
                block.payload(),
                remaining,
                cancellation,
            )?;
            if decoded.truncated {
                complete = false;
            }
            for record in decoded.records {
                if records.len() == limit {
                    complete = false;
                    break;
                }
                records.push(ScannedLogRecord::new(record, block.position()));
            }
            if !complete {
                break;
            }
        }
        check_scan_cancellation(cancellation)?;
        Ok(LogScanResult::new(
            records,
            complete,
            scanned_bytes,
            false,
            capacity,
        ))
    }
}

fn check_scan_cancellation(cancellation: &dyn ScanCancellation) -> Result<(), LogStoreFailure> {
    if cancellation.is_cancelled() {
        Err(LogStoreFailure::cancelled())
    } else {
        Ok(())
    }
}

fn map_schema_failure(failure: SchemaFailure) -> LogStoreFailure {
    match failure {
        SchemaFailure::AllocationUnavailable => LogStoreFailure::resource_exhausted(),
        SchemaFailure::LimitExceeded
        | SchemaFailure::InvalidBudget
        | SchemaFailure::PathTooLong => LogStoreFailure::limit_exceeded(),
        SchemaFailure::InvalidPath | SchemaFailure::InvalidValue => {
            LogStoreFailure::invalid_input()
        },
        SchemaFailure::MalformedCatalog => LogStoreFailure::invalid_input(),
    }
}

#[cfg(test)]
mod tests;
