use positron_domain::identity::TenantId;
use positron_kernel::{LedgerSnapshot, ResourceGovernor};
use positron_signals::{LogScan, LogScanResult, LogStore, ScanLimit};

use crate::execution_support::{QueryScanObserver, map_store_failure};
use crate::{QueryCancellation, QueryFailure};

pub(super) const MAX_SCAN_RECORDS: usize = 1_024;

#[expect(
    clippy::too_many_arguments,
    reason = "the scan adapter forwards one bounded request to the three canonical signal-store paths"
)]
pub(crate) fn execute_scan<'kernel>(
    governor: ResourceGovernor<'kernel>,
    tenant: TenantId,
    snapshot: &LedgerSnapshot<'kernel>,
    after: Option<positron_domain::routing::CommitPosition>,
    frontier: positron_domain::routing::CommitPosition,
    scan_limit: ScanLimit,
    scanned_remaining: u64,
    schema: Option<&positron_signals::SchemaCatalog>,
    schema_query: Option<&positron_signals::SchemaQuery>,
    text_candidate: Option<&positron_signals::TextSearchCandidate>,
    cancellation: &QueryCancellation,
    observer: &mut QueryScanObserver<'_>,
) -> Result<LogScanResult<'kernel>, QueryFailure> {
    let scan = match after {
        Some(after) => LogScan::between(scan_limit, after, frontier),
        None => LogScan::through(scan_limit, frontier),
    }
    .with_scanned_bytes(scanned_remaining);
    let result = match (schema, schema_query, text_candidate) {
        (Some(schema), None, Some(candidate)) => LogStore::new().scan_text_observed(
            governor,
            tenant,
            snapshot,
            scan,
            schema,
            candidate,
            cancellation,
            observer,
        ),
        (Some(schema), Some(query), _) => LogStore::new().scan_schema_observed(
            governor,
            tenant,
            snapshot,
            scan,
            schema,
            query,
            cancellation,
            observer,
        ),
        _ => {
            LogStore::new().scan_observed(governor, tenant, snapshot, scan, cancellation, observer)
        },
    };
    result.map_err(map_store_failure)
}
