use super::scan::{admit_block_bytes, includes_block};
use positron_domain::routing::SignalKind;
use positron_kernel::{
    LedgerSnapshot, ResourceAmounts, ResourceDimension, ResourceGovernor, WorkClaim, WorkKind,
};

use super::{
    LogScan, LogScanResult, LogStore, LogStoreFailure, ScanCancellation, ScanObserver,
    ScannedLogRecord, SchemaCatalog, TextSearchCandidate, check_scan_cancellation,
    retained_scan_bytes,
};

impl LogStore {
    /// Scans authenticated blocks using the governed Log Store text summary
    /// as a candidate-only pruning optimization.
    #[allow(clippy::too_many_arguments)]
    pub fn scan_text_observed<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: positron_domain::identity::TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: LogScan,
        schema: &SchemaCatalog,
        candidate: &TextSearchCandidate,
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
            Some((schema, candidate)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn scan_observed_inner<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: positron_domain::identity::TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: LogScan,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
        text: Option<(&SchemaCatalog, &TextSearchCandidate)>,
    ) -> Result<LogScanResult<'kernel>, LogStoreFailure> {
        let scope = snapshot.scope();
        if scope.tenant_id() != tenant || scope.signal_kind() != SignalKind::Logs {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        if let Some((schema, _)) = text
            && schema.tenant() != tenant
        {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        check_scan_cancellation(cancellation)?;
        let mut encoded_bytes = 0_u64;
        for block in snapshot.blocks() {
            check_scan_cancellation(cancellation)?;
            if !includes_block(scan, block.position()) {
                continue;
            }
            encoded_bytes = encoded_bytes
                .checked_add(
                    u64::try_from(block.payload().len())
                        .map_err(|_| LogStoreFailure::limit_exceeded())?,
                )
                .ok_or_else(LogStoreFailure::limit_exceeded)?;
        }
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
        records
            .try_reserve_exact(scan.limit().value())
            .map_err(|_| LogStoreFailure::resource_exhausted())?;
        let mut scanned_bytes = 0_u64;
        let limit = scan.limit().value();
        let mut complete = true;
        let mut scanned_bytes_limited = false;
        let mut reduced_pruning = false;
        for block in snapshot.blocks() {
            check_scan_cancellation(cancellation)?;
            if !includes_block(scan, block.position()) {
                continue;
            }
            let remaining = limit.saturating_sub(records.len());
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
            if let Some((schema, candidate)) = text {
                observer
                    .observe_work(1)
                    .map_err(LogStoreFailure::observation)?;
                let digest = block.content_digest().map_err(LogStoreFailure::kernel)?;
                match schema
                    .verified_text_coverage_observed(block.identity(), digest, candidate, observer)
                    .map_err(LogStoreFailure::observation)?
                {
                    Some(false) => continue,
                    Some(true) => {},
                    None => reduced_pruning = true,
                }
            }
            let decode = super::codec::BlockDecode::observed(
                tenant,
                block.payload(),
                cancellation,
                observer,
            )?;
            let block_records = decode.record_count();
            if block_records > remaining {
                let decoded = decode.decode(snapshot, remaining, cancellation)?;
                for (ordinal, record) in decoded.records.into_iter().enumerate() {
                    let ordinal = u16::try_from(ordinal)
                        .ok()
                        .and_then(|ordinal| {
                            positron_domain::routing::RecordOrdinal::new(ordinal).ok()
                        })
                        .ok_or_else(LogStoreFailure::malformed_block)?;
                    records.push(ScannedLogRecord::new(record, block.position(), ordinal));
                }
                complete = false;
                break;
            }
            let decoded = decode.decode(snapshot, remaining, cancellation)?;
            for (ordinal, record) in decoded.records.into_iter().enumerate() {
                let ordinal = u16::try_from(ordinal)
                    .ok()
                    .and_then(|ordinal| positron_domain::routing::RecordOrdinal::new(ordinal).ok())
                    .ok_or_else(LogStoreFailure::malformed_block)?;
                records.push(ScannedLogRecord::new(record, block.position(), ordinal));
            }
        }
        check_scan_cancellation(cancellation)?;
        let decoded_records =
            u64::try_from(records.len()).map_err(|_| LogStoreFailure::limit_exceeded())?;
        let retained_size_bytes = retained_scan_bytes(scan.limit(), &mut records)?;
        Ok(LogScanResult::new(
            records,
            decoded_records,
            complete,
            scanned_bytes,
            scanned_bytes_limited,
            retained_size_bytes,
            reduced_pruning,
            capacity,
        ))
    }
}
