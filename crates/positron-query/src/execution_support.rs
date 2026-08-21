use positron_domain::time::{IngestTimeCandidate, QueryTime};

use crate::cursor::CursorState;
use crate::{LogicalPlan, QueryFailure, QueryFailureCode, QueryRecord, TemporalAxis};

pub(crate) fn query_record(
    record: &positron_signals::ScannedLogRecord,
    plan: &LogicalPlan,
) -> Option<QueryRecord> {
    if let Some(crate::plan::FilterPredicate::BodyEquals(expected)) = plan.filter()
        && record.body().and_then(|body| body.as_str()) != Some(expected.as_str())
    {
        return None;
    }
    let observed = record.observed_time();
    let ordering_time = match plan.temporal_axis() {
        TemporalAxis::QueryTime => Some(
            QueryTime::for_log(
                &record.event_time(),
                observed.as_ref(),
                IngestTimeCandidate::new(record.ingest_time().instant()),
            )
            .instant(),
        ),
        TemporalAxis::EventTime => record.event_time().instant(),
    }?;
    if !plan.temporal_range().contains(ordering_time) {
        return None;
    }
    let body = plan
        .projection()
        .contains(&crate::plan::ProjectionColumn::Body)
        .then(|| {
            record
                .body()
                .and_then(|body| body.as_str())
                .map(str::to_owned)
        })
        .flatten();
    Some(QueryRecord::new(
        body,
        ordering_time,
        record.commit_position(),
    ))
}

pub(crate) fn charge_scan(
    state: &mut CursorState,
    result: &positron_signals::LogScanResult<'_>,
    cpu_work_units: u64,
) -> Result<(), QueryFailure> {
    state.scanned_bytes = state
        .scanned_bytes
        .checked_add(result.scanned_bytes())
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    state.decoded_records = state
        .decoded_records
        .checked_add(
            u64::try_from(result.records().len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?,
        )
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    state.cpu_work_units = state
        .cpu_work_units
        .checked_add(cpu_work_units)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    Ok(())
}

pub(crate) fn charge_work(
    state: &mut CursorState,
    cpu_work_units: u64,
) -> Result<(), QueryFailure> {
    state.cpu_work_units = state
        .cpu_work_units
        .checked_add(cpu_work_units)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    Ok(())
}

pub(crate) fn charge_output(
    state: &mut CursorState,
    page: &[QueryRecord],
) -> Result<(), QueryFailure> {
    state.output_rows = state
        .output_rows
        .checked_add(
            u64::try_from(page.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?,
        )
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    let page_bytes = page.iter().try_fold(0_u64, |total, record| {
        total.checked_add(u64::try_from(record.body_text().map_or(0, str::len)).ok()?)
    });
    state.output_bytes = state
        .output_bytes
        .checked_add(page_bytes.ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    Ok(())
}

pub(crate) fn exhausted(state: &CursorState) -> bool {
    state.scanned_bytes > state.budget.scanned_bytes()
        || state.decoded_records > state.budget.decoded_records()
        || state.output_rows > state.budget.output_rows()
        || state.output_bytes > state.budget.output_bytes()
        || state.cpu_work_units > state.budget.cpu_work_units()
        || state.elapsed_wall_seconds >= state.budget.wall_seconds()
}

pub(crate) fn batch_digest(
    protector: &positron_kernel::ControlTokenProtector<'_>,
    prior: [u8; 32],
    sequence: u64,
    records: &[QueryRecord],
) -> Result<[u8; 32], QueryFailure> {
    let mut encoding = Vec::new();
    encoding.extend_from_slice(&prior);
    encoding.extend_from_slice(&sequence.to_be_bytes());
    encoding.extend_from_slice(
        &u64::try_from(records.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
            .to_be_bytes(),
    );
    for record in records {
        let (query_time, position) = record.order_key();
        encoding.extend_from_slice(&query_time.value().to_be_bytes());
        encoding.extend_from_slice(&position.value().to_be_bytes());
        let body = record.body_text().unwrap_or_default().as_bytes();
        encoding.extend_from_slice(
            &u64::try_from(body.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
                .to_be_bytes(),
        );
        encoding.extend_from_slice(body);
    }
    protector
        .digest(b"query-result-batch-v1", &encoding)
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
}

pub(crate) fn map_ledger_failure(failure: positron_kernel::LedgerFailure) -> QueryFailure {
    match failure.code() {
        positron_kernel::LedgerFailureCode::SnapshotExpired => {
            QueryFailure::new(QueryFailureCode::SnapshotExpired)
        },
        positron_kernel::LedgerFailureCode::LimitExceeded => {
            QueryFailure::new(QueryFailureCode::InvalidBudget)
        },
        positron_kernel::LedgerFailureCode::ResourceAdmissionRefused => {
            QueryFailure::new(QueryFailureCode::ResourceAdmissionRefused)
        },
        _ => QueryFailure::new(QueryFailureCode::StoreUnavailable),
    }
}

pub(crate) fn map_store_failure(failure: positron_signals::LogStoreFailure) -> QueryFailure {
    match failure.code() {
        positron_signals::LogStoreFailureCode::MalformedBlock => {
            QueryFailure::new(QueryFailureCode::MalformedPersistentData)
        },
        positron_signals::LogStoreFailureCode::ResourceAdmissionRefused => {
            QueryFailure::new(QueryFailureCode::ResourceAdmissionRefused)
        },
        positron_signals::LogStoreFailureCode::LimitExceeded
        | positron_signals::LogStoreFailureCode::ResourceExhausted => {
            QueryFailure::new(QueryFailureCode::BudgetExhausted)
        },
        _ => QueryFailure::new(QueryFailureCode::StoreUnavailable),
    }
}
