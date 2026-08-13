//! Minimal native Log Signal Store.

mod codec;
mod failure;
#[cfg(fuzzing)]
mod fuzzing;
mod scan;
mod types;

#[cfg(fuzzing)]
pub use fuzzing::fuzz_log_store_block;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    LedgerSnapshot, LifecycleClock, LifecycleClockSource, PreparedStoreBlock, ResourceAmounts,
    ResourceDimension, ResourceGovernor, SegmentScope, StoreBlockIdentity, WorkClaim, WorkKind,
};

pub use failure::{LogStoreFailure, LogStoreFailureCode};
pub use scan::{LogScan, LogScanResult, ScanLimit};
pub use types::{
    AttributeRepresentation, LogRecord, PolicyProvenance, PreparedLogBlock, StoredLogAttribute,
    StoredLogRecord,
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

    /// Prepares one canonical, checked Log Store Block for kernel durability.
    pub fn prepare<S: LifecycleClockSource>(
        &self,
        clock: &LifecycleClock<S>,
        tenant: TenantId,
        shard: VirtualShardId,
        identity: StoreBlockIdentity,
        records: Vec<LogRecord>,
    ) -> Result<PreparedLogBlock, LogStoreFailure> {
        let stored = records
            .into_iter()
            .map(|record| {
                clock
                    .assign_ingest_time()
                    .map(|ingest_time| StoredLogRecord::new(record, ingest_time))
                    .map_err(|_| LogStoreFailure::clock_unavailable())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bytes = codec::encode_block(tenant, &stored)?;
        let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
        let block =
            PreparedStoreBlock::new(scope, identity, bytes).map_err(LogStoreFailure::kernel)?;
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
        let scope = snapshot.scope();
        if scope.tenant_id() != tenant || scope.signal_kind() != SignalKind::Logs {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        let encoded_bytes = snapshot
            .blocks()
            .iter()
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
        let mut records = Vec::new();
        let limit = scan.limit().value();
        let mut complete = true;
        for block in snapshot.blocks() {
            let remaining = limit.saturating_sub(records.len());
            let decoded = codec::decode_block(tenant, snapshot, block.payload(), remaining)?;
            if decoded.truncated {
                complete = false;
            }
            for record in decoded.records {
                if records.len() == limit {
                    complete = false;
                    break;
                }
                records.push(record);
            }
            if !complete {
                break;
            }
        }
        Ok(LogScanResult::new(records, complete, capacity))
    }
}

#[cfg(test)]
mod tests;
