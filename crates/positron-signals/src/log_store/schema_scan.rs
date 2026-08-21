use positron_domain::identity::TenantId;
use positron_domain::routing::SignalKind;
use positron_kernel::{
    LedgerSnapshot, ResourceAmounts, ResourceDimension, ResourceGovernor, WorkClaim, WorkKind,
};

use super::{
    LogScan, LogScanResult, LogStore, LogStoreFailure, ScannedLogRecord, SchemaCatalog,
    SchemaQuery, codec,
};

impl LogStore {
    /// Scans durable v2 records with explicit typed occurrence semantics.
    ///
    /// Promoted type dictionaries prune impossible variants. Generic and
    /// Schema Overflow records use the same exact decoder and report reduced
    /// pruning without changing logical results.
    pub fn scan_schema<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: LogScan,
        schema: &SchemaCatalog,
        query: &SchemaQuery,
    ) -> Result<LogScanResult<'kernel>, LogStoreFailure> {
        let scope = snapshot.scope();
        if scope.tenant_id() != tenant
            || scope.signal_kind() != SignalKind::Logs
            || schema.tenant() != tenant
        {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
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
        let output_memory = u64::try_from(scan.limit().value())
            .map_err(|_| LogStoreFailure::limit_exceeded())?
            .checked_mul(512)
            .ok_or_else(LogStoreFailure::limit_exceeded)?;
        let memory = encoded_bytes
            .checked_add(output_memory)
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
        records
            .try_reserve_exact(scan.limit().value())
            .map_err(|_| LogStoreFailure::resource_exhausted())?;
        let mut scanned_bytes = 0_u64;
        let mut complete = true;
        let mut reduced_pruning = false;
        'blocks: for block in snapshot.blocks() {
            if scan
                .frontier()
                .is_some_and(|frontier| block.position() > frontier)
            {
                continue;
            }
            let digest = block.content_digest().map_err(LogStoreFailure::kernel)?;
            let coverage = query.expected_scalar().map_or_else(
                || {
                    schema.verified_block_kind(
                        block.identity(),
                        digest,
                        query.path(),
                        query.expected_kind(),
                    )
                },
                |expected| {
                    schema.verified_block_value(block.identity(), digest, query.path(), expected)
                },
            );
            match coverage {
                Some(false) => continue,
                Some(true) => {},
                None => reduced_pruning = true,
            }
            scanned_bytes = scanned_bytes
                .checked_add(
                    u64::try_from(block.payload().len())
                        .map_err(|_| LogStoreFailure::limit_exceeded())?,
                )
                .ok_or_else(LogStoreFailure::limit_exceeded)?;
            // The v2 decoder enforces the canonical per-block record ceiling.
            // A schema scan must inspect every valid record before applying its
            // predicate, so an additional result-sized decode limit would be
            // both redundant and incorrect.
            let decoded = codec::decode_block(tenant, snapshot, block.payload(), usize::MAX)?;
            for (ordinal, record) in decoded.records.into_iter().enumerate() {
                let result = schema.query_stored_record(&record, query);
                reduced_pruning |= result.reduced_pruning();
                if result.is_match() {
                    if records.len() == scan.limit().value() {
                        complete = false;
                        break 'blocks;
                    }
                    let ordinal = u16::try_from(ordinal)
                        .ok()
                        .and_then(|ordinal| {
                            positron_domain::routing::RecordOrdinal::new(ordinal).ok()
                        })
                        .ok_or_else(LogStoreFailure::malformed_block)?;
                    records.push(ScannedLogRecord::new(record, block.position(), ordinal));
                }
            }
        }
        let retained_size_bytes = super::retained_scan_bytes(scan.limit(), &mut records)?;
        Ok(LogScanResult::new(
            records,
            complete,
            scanned_bytes,
            retained_size_bytes,
            reduced_pruning,
            capacity,
        ))
    }
}
