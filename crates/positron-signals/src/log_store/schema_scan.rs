use super::scan::admit_block_bytes;
use positron_domain::identity::TenantId;
use positron_domain::routing::SignalKind;
use positron_domain::value::{NativeValueObserver, ObservedValueFailure};
use positron_kernel::{
    LedgerSnapshot, ResourceAmounts, ResourceDimension, ResourceGovernor, WorkClaim, WorkKind,
};

use super::{
    LogScan, LogScanResult, LogStore, LogStoreFailure, ScanCancellation,
    ScanObservationFailureCode, ScanObserver, ScannedLogRecord, SchemaCatalog, SchemaQuery, codec,
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
        let mut observer = super::scan::Unobserved;
        self.scan_schema_inner(
            governor,
            tenant,
            snapshot,
            scan,
            schema,
            query,
            &super::scan::NeverCancelled,
            &mut observer,
            SchemaScanLimit::Results,
        )
    }

    /// Runs the schema-aware scan with the same cooperative cancellation and
    /// cumulative work authority used by ordinary authenticated decoding.
    #[allow(clippy::too_many_arguments)]
    pub fn scan_schema_observed<'kernel, O>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: LogScan,
        schema: &SchemaCatalog,
        query: &SchemaQuery,
        cancellation: &dyn ScanCancellation,
        observer: &mut O,
    ) -> Result<LogScanResult<'kernel>, LogStoreFailure>
    where
        O: ScanObserver + NativeValueObserver<Error = ScanObservationFailureCode>,
    {
        self.scan_schema_inner(
            governor,
            tenant,
            snapshot,
            scan,
            schema,
            query,
            cancellation,
            observer,
            SchemaScanLimit::DecodedRecords,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_schema_inner<'kernel, O>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: LogScan,
        schema: &SchemaCatalog,
        query: &SchemaQuery,
        cancellation: &dyn ScanCancellation,
        observer: &mut O,
        limit_kind: SchemaScanLimit,
    ) -> Result<LogScanResult<'kernel>, LogStoreFailure>
    where
        O: ScanObserver + NativeValueObserver<Error = ScanObservationFailureCode>,
    {
        let scope = snapshot.scope();
        if scope.tenant_id() != tenant
            || scope.signal_kind() != SignalKind::Logs
            || schema.tenant() != tenant
        {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        check_cancellation(cancellation)?;
        let mut encoded_bytes = 0_u64;
        for block in snapshot.blocks() {
            check_cancellation(cancellation)?;
            if scan
                .frontier()
                .is_some_and(|frontier| block.position() > frontier)
            {
                continue;
            }
            encoded_bytes = encoded_bytes
                .checked_add(
                    u64::try_from(block.payload().len())
                        .map_err(|_| LogStoreFailure::limit_exceeded())?,
                )
                .ok_or_else(LogStoreFailure::limit_exceeded)?;
        }
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
        check_cancellation(cancellation)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(scan.limit().value())
            .map_err(|_| LogStoreFailure::resource_exhausted())?;
        let mut scanned_bytes = 0_u64;
        let mut decoded_records = 0_usize;
        let mut complete = true;
        let mut scanned_bytes_limited = false;
        let mut reduced_pruning = false;
        'blocks: for block in snapshot.blocks() {
            check_cancellation(cancellation)?;
            if scan
                .frontier()
                .is_some_and(|frontier| block.position() > frontier)
            {
                continue;
            }
            let remaining = match limit_kind {
                SchemaScanLimit::DecodedRecords => {
                    scan.limit().value().saturating_sub(decoded_records)
                },
                SchemaScanLimit::Results => usize::MAX,
            };
            if remaining == 0 {
                complete = false;
                break;
            }
            let next_scanned_bytes = match admit_block_bytes(
                scanned_bytes,
                block.payload().len(),
                scan.scanned_bytes_limit(),
            )? {
                Some(next) => next,
                None => {
                    complete = false;
                    scanned_bytes_limited = true;
                    break;
                },
            };
            observer
                .observe_scanned_bytes(
                    u64::try_from(block.payload().len())
                        .map_err(|_| LogStoreFailure::limit_exceeded())?,
                )
                .map_err(LogStoreFailure::observation)?;
            scanned_bytes = next_scanned_bytes;
            let digest = block.content_digest().map_err(LogStoreFailure::kernel)?;
            let coverage = schema
                .verified_query_coverage_observed(block.identity(), digest, query, observer)
                .map_err(LogStoreFailure::observation)?;
            match coverage {
                Some(false) => continue,
                Some(true) => {},
                None => reduced_pruning = true,
            }
            let decode =
                codec::BlockDecode::observed(tenant, block.payload(), cancellation, &*observer)?;
            let oversized = decode.record_count() > remaining;
            let decoded = decode.decode(snapshot, remaining, cancellation)?;
            decoded_records = decoded_records
                .checked_add(decoded.records.len())
                .ok_or_else(LogStoreFailure::limit_exceeded)?;
            for (ordinal, record) in decoded.records.into_iter().enumerate() {
                let result = schema
                    .query_stored_record_observed(&record, query, observer)
                    .map_err(map_traversal_failure)?;
                reduced_pruning |= result.reduced_pruning();
                if result.is_match() {
                    if matches!(limit_kind, SchemaScanLimit::Results)
                        && records.len() == scan.limit().value()
                    {
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
            if oversized {
                complete = false;
                break;
            }
        }
        check_cancellation(cancellation)?;
        let retained_size_bytes = super::retained_scan_bytes(scan.limit(), &mut records)?;
        Ok(LogScanResult::new(
            records,
            u64::try_from(decoded_records).map_err(|_| LogStoreFailure::limit_exceeded())?,
            complete,
            scanned_bytes,
            scanned_bytes_limited,
            retained_size_bytes,
            reduced_pruning,
            capacity,
        ))
    }
}

#[derive(Clone, Copy)]
enum SchemaScanLimit {
    DecodedRecords,
    Results,
}

fn check_cancellation(cancellation: &dyn ScanCancellation) -> Result<(), LogStoreFailure> {
    if cancellation.is_cancelled() {
        Err(LogStoreFailure::cancelled())
    } else {
        Ok(())
    }
}

fn map_traversal_failure(
    failure: ObservedValueFailure<ScanObservationFailureCode>,
) -> LogStoreFailure {
    match failure {
        ObservedValueFailure::Domain(failure) => LogStoreFailure::domain(failure),
        ObservedValueFailure::Observer(failure) => LogStoreFailure::observation(failure),
    }
}

#[cfg(test)]
mod tests {
    use positron_domain::identity::TenantId;

    use super::{ScanObservationFailureCode, map_traversal_failure};
    use crate::log_store::LogStoreFailureCode;
    use positron_domain::value::ObservedValueFailure;

    #[test]
    fn traversal_failures_preserve_domain_and_observer_public_classes() {
        let domain = TenantId::from_bytes([0; 16]).expect_err("zero tenant must be rejected");
        assert_eq!(
            map_traversal_failure(ObservedValueFailure::Domain(domain)).code(),
            LogStoreFailureCode::InvalidInput
        );
        assert_eq!(
            map_traversal_failure(ObservedValueFailure::Observer(
                ScanObservationFailureCode::BudgetExhausted,
            ))
            .code(),
            LogStoreFailureCode::BudgetExhausted
        );
    }
}
