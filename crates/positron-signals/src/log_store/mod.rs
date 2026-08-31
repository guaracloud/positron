//! Minimal native Log Signal Store.

mod codec;
mod failure;
#[cfg(fuzzing)]
mod fuzzing;
mod metadata;
mod retention;
mod scan;
mod schema;
mod schema_scan;
mod schema_work;
mod text_scan;
mod types;

#[cfg(fuzzing)]
pub use fuzzing::{fuzz_log_retention_block, fuzz_log_store_block};

use positron_domain::identity::TenantId;
#[cfg(any(test, fuzzing))]
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{LedgerSnapshot, ResourceGovernor, StoreBlockIdentity};
#[cfg(any(test, fuzzing))]
use positron_kernel::{
    LifecycleClock, LifecycleClockSource, PreparedStoreBlock, ResourceReservation, SegmentScope,
};

pub use failure::{LogStoreFailure, LogStoreFailureCode};
pub use metadata::LogMetadata;
pub use positron_policy::PolicyProvenance;
pub use retention::{LogRetentionBucket, LogRetentionOutcome, LogRetentionPolicy};
pub use scan::{
    LogScan, LogScanResult, ScanCancellation, ScanLimit, ScanObservationFailureCode, ScanObserver,
    ScannedLogRecord,
};
pub use schema::{
    OccurrenceSelector, SchemaBudget, SchemaBudgetPressure, SchemaCatalog,
    SchemaCheckpointFrontier, SchemaDelta, SchemaDiscovery, SchemaDiscoveryRequest, SchemaEntry,
    SchemaFailure, SchemaObservation, SchemaPath, SchemaPathDigest, SchemaPathSummary,
    SchemaPromotionDecision, SchemaPromotionReason, SchemaQuery, SchemaQueryResult,
    SchemaQueryUpdate, SchemaRepresentation, SchemaSessionStore, SchemaTraversalFailure,
    SchemaValue, TextSearchCandidate,
};
pub use types::{
    AttributeRepresentation, LogRecord, PreparedLogBlock, StoredLogAttribute, StoredLogRecord,
};

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_text_search_pruning(body: &str, literals: &[Vec<u8>]) {
    let Ok(Some(candidate)) = schema::TextSearchCandidate::any_of_bytes(literals) else {
        return;
    };
    let Ok(summary) = schema::TextBlockSummary::from_bodies([Some(body)]) else {
        return;
    };
    struct Observer;
    impl ScanObserver for Observer {
        fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
            Ok(())
        }
    }
    let Ok(Some(might_contain)) = summary.might_contain_observed(&candidate, &Observer) else {
        return;
    };
    if !might_contain
        && candidate.literals().iter().any(|literal| {
            body.as_bytes()
                .windows(literal.len())
                .any(|window| window == literal)
        })
    {
        panic!("text pruning produced a false negative");
    }
}

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

    /// Prepares canonical Log Store bytes under a kernel-issued Ingest Time.
    pub fn prepare<'capacity>(
        &self,
        preparation: positron_kernel::StoreBlockPreparation<'capacity>,
        records: Vec<LogRecord>,
    ) -> Result<PreparedLogBlock<'capacity>, LogStoreFailure> {
        if preparation.scope().signal_kind() != positron_domain::routing::SignalKind::Logs {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        if records.is_empty() {
            return Err(LogStoreFailure::invalid_input());
        }
        let tenant = preparation.scope().tenant_id();
        let ingest_time = preparation.ingest_time();
        let encoded_bytes = codec::encoded_block_length(&records)?;
        let stored = records
            .into_iter()
            .map(|record| StoredLogRecord::new(record, ingest_time))
            .collect::<Vec<_>>();
        let bytes = codec::encode_block(tenant, &stored, encoded_bytes)?;
        let block = preparation.finish(bytes).map_err(LogStoreFailure::kernel)?;
        Ok(PreparedLogBlock::new(block))
    }

    #[cfg(any(test, fuzzing))]
    #[doc(hidden)]
    pub fn prepare_unretained_for_test<'capacity, S: LifecycleClockSource>(
        &self,
        capacity: ResourceReservation<'capacity>,
        clock: &LifecycleClock<S>,
        tenant: TenantId,
        shard: VirtualShardId,
        identity: StoreBlockIdentity,
        records: Vec<LogRecord>,
    ) -> Result<PreparedLogBlock<'capacity>, LogStoreFailure> {
        self.prepare_unretained_internal(capacity, clock, tenant, shard, identity, records)
    }

    /// Prepares a block and its bounded schema delta without mutating live schema state.
    #[cfg(any(test, fuzzing))]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_schema_delta<'capacity, S: LifecycleClockSource>(
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
        self.prepare_unretained_internal(capacity, clock, tenant, shard, identity, records)
            .map(|prepared| (prepared, delta))
    }

    /// Applies a previously staged delta after its v2 block is durably resolved.
    #[doc(hidden)]
    pub fn apply_schema_delta(
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

    #[doc(hidden)]
    pub fn apply_schema_delta_replay_observed(
        &self,
        schema: &mut SchemaCatalog,
        delta: SchemaDelta,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
        observer: &dyn ScanObserver,
    ) -> Result<(), LogStoreFailure> {
        if schema.tenant() != delta.tenant() {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        let (delta, block_index) = delta.into_block_index(identity, digest);
        schema
            .apply_replay_delta(delta, block_index, observer)
            .map_err(map_schema_failure)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, fuzzing))]
    fn prepare_unretained_internal<'capacity, S: LifecycleClockSource>(
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
        self.scan_observed(
            governor,
            tenant,
            snapshot,
            scan,
            cancellation,
            &scan::Unobserved,
        )
    }

    /// Scans with cooperative cancellation and caller-owned bounded work observation.
    pub fn scan_observed<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: LogScan,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<LogScanResult<'kernel>, LogStoreFailure> {
        self.scan_observed_inner(
            governor,
            tenant,
            snapshot,
            scan,
            cancellation,
            observer,
            None,
        )
    }

    /// Enforces retention for one tenant-scoped Log Store ledger.
    pub fn enforce_retention<'kernel, 'catalog>(
        &self,
        ledger: &positron_kernel::ActiveSegmentLedger<'kernel, 'catalog>,
        tenant: TenantId,
        policy: LogRetentionPolicy,
    ) -> Result<LogRetentionOutcome, LogStoreFailure> {
        self.enforce_retention_observed(
            ledger,
            tenant,
            policy,
            &scan::NeverCancelled,
            &scan::Unobserved,
        )
    }

    /// Enforces retention with cooperative cancellation and bounded work observation.
    pub fn enforce_retention_observed<'kernel, 'catalog>(
        &self,
        ledger: &positron_kernel::ActiveSegmentLedger<'kernel, 'catalog>,
        tenant: TenantId,
        policy: LogRetentionPolicy,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<LogRetentionOutcome, LogStoreFailure> {
        retention::enforce_retention(ledger, tenant, policy, cancellation, observer)
    }
}

const SCANNED_RECORD_SLOT_BYTES: u64 = 512;

pub(super) fn retained_scan_bytes(
    limit: ScanLimit,
    records: &mut [ScannedLogRecord],
) -> Result<u64, LogStoreFailure> {
    let slots = u64::try_from(limit.value())
        .map_err(|_| LogStoreFailure::limit_exceeded())?
        .checked_mul(SCANNED_RECORD_SLOT_BYTES)
        .ok_or_else(LogStoreFailure::limit_exceeded)?;
    records.iter_mut().try_fold(slots, |total, record| {
        let retained = record.stored().retained_dynamic_bytes()?;
        record.set_body_retained_bytes(retained.body_heap);
        total
            .checked_add(retained.total)
            .ok_or_else(LogStoreFailure::limit_exceeded)
    })
}

pub(super) fn check_scan_cancellation(
    cancellation: &dyn ScanCancellation,
) -> Result<(), LogStoreFailure> {
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
        SchemaFailure::Observed(failure) => LogStoreFailure::observation(failure),
    }
}

#[cfg(test)]
mod tests;
