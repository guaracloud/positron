//! Minimal native Log Signal Store.

mod codec;
mod failure;
#[cfg(fuzzing)]
mod fuzzing;
mod types;

#[cfg(fuzzing)]
pub use fuzzing::fuzz_log_store_block;

use positron_domain::identity::TenantId;
use positron_domain::routing::SignalKind;
use positron_kernel::{LedgerSnapshot, PreparedStoreBlock, StoreBlockIdentity};

pub use failure::{LogStoreFailure, LogStoreFailureCode};
pub use types::{
    AttributeRepresentation, LogRecord, LogScan, LogScanResult, PolicyProvenance, PreparedLogBlock,
    ScanLimit, StoredLogAttribute,
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
    pub fn prepare(
        &self,
        tenant: TenantId,
        identity: StoreBlockIdentity,
        records: Vec<LogRecord>,
    ) -> Result<PreparedLogBlock, LogStoreFailure> {
        let bytes = codec::encode_block(tenant, &records)?;
        let block = PreparedStoreBlock::new(identity, bytes).map_err(LogStoreFailure::kernel)?;
        Ok(PreparedLogBlock::new(block))
    }

    /// Scans verified committed blocks up to the caller's explicit result bound.
    pub fn scan(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: LogScan,
    ) -> Result<LogScanResult, LogStoreFailure> {
        let scope = snapshot.scope();
        if scope.tenant_id() != tenant || scope.signal_kind() != SignalKind::Logs {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        let mut records = Vec::new();
        let limit = scan.limit().value();
        let mut complete = true;
        for block in snapshot.blocks() {
            let decoded = codec::decode_block(tenant, block.payload())?;
            for record in decoded {
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
        Ok(LogScanResult::new(records, complete))
    }
}

#[cfg(test)]
mod tests;
