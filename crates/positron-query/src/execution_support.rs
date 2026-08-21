use positron_domain::time::{IngestTimeCandidate, QueryTime};
use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::cursor::CursorState;
use crate::{LogicalPlan, QueryFailure, QueryFailureCode, QueryRecord, TemporalAxis};

const MAX_GROUPS: usize = 1_024;
const GROUP_ENTRY_BASE_BYTES: u64 = 32;
const GROUP_VALUE_SLOT_BYTES: u64 = 16;

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
    let selected_columns = plan
        .aggregate()
        .map(crate::plan::AggregateSpec::group_by)
        .unwrap_or_else(|| plan.projection());
    let body = selected_columns
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
        selected_columns.contains(&crate::plan::ProjectionColumn::QueryTime),
        selected_columns.contains(&crate::plan::ProjectionColumn::CommitPosition),
    ))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum GroupValue {
    Body(Option<String>),
    QueryTime(positron_domain::time::UnixNanoseconds),
    CommitPosition(positron_domain::routing::CommitPosition),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct GroupKey(Vec<GroupValue>);

impl GroupKey {
    fn for_record(record: &QueryRecord, columns: &[crate::plan::ProjectionColumn]) -> Self {
        Self(
            columns
                .iter()
                .map(|column| match column {
                    crate::plan::ProjectionColumn::Body => {
                        GroupValue::Body(record.body_text().map(str::to_owned))
                    },
                    crate::plan::ProjectionColumn::QueryTime => {
                        GroupValue::QueryTime(record.query_time())
                    },
                    crate::plan::ProjectionColumn::CommitPosition => {
                        GroupValue::CommitPosition(record.commit_position())
                    },
                })
                .collect(),
        )
    }

    fn retained_bytes(&self) -> Result<u64, QueryFailure> {
        self.0
            .iter()
            .try_fold(GROUP_ENTRY_BASE_BYTES, |total, value| {
                let value_bytes = match value {
                    GroupValue::Body(body) => u64::try_from(body.as_deref().map_or(0, str::len))
                        .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?,
                    GroupValue::QueryTime(_) | GroupValue::CommitPosition(_) => 8,
                };
                total
                    .checked_add(GROUP_VALUE_SLOT_BYTES)
                    .and_then(|bytes| bytes.checked_add(value_bytes))
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))
            })
    }

    fn into_record(self, count: u64) -> QueryRecord {
        let mut body = None;
        let mut query_time = None;
        let mut commit_position = None;
        for value in self.0 {
            match value {
                GroupValue::Body(value) => body = value,
                GroupValue::QueryTime(value) => query_time = Some(value),
                GroupValue::CommitPosition(value) => commit_position = Some(value),
            }
        }
        QueryRecord::grouped_count_record(body, query_time, commit_position, count)
    }
}

pub(crate) fn aggregate_records(
    records: Vec<QueryRecord>,
    aggregate: &crate::plan::AggregateSpec,
    memory_budget: u64,
    cancellation: &crate::QueryCancellation,
) -> Result<Vec<QueryRecord>, QueryFailure> {
    if cancellation.is_cancelled() {
        return Err(QueryFailure::new(QueryFailureCode::Cancelled));
    }
    if aggregate.group_by().is_empty() {
        return Ok(vec![QueryRecord::count_record(
            u64::try_from(records.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?,
        )]);
    }
    let mut groups = BTreeMap::<GroupKey, u64>::new();
    let mut retained_bytes = 0_u64;
    for record in &records {
        if cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        let key = GroupKey::for_record(record, aggregate.group_by());
        let key_bytes = key.retained_bytes()?;
        let at_capacity = groups.len() >= MAX_GROUPS;
        match groups.entry(key) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let count = entry
                    .get()
                    .checked_add(1)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
                *entry.get_mut() = count;
            },
            std::collections::btree_map::Entry::Vacant(entry) => {
                if at_capacity {
                    return Err(QueryFailure::new(QueryFailureCode::BudgetExhausted));
                }
                retained_bytes = retained_bytes
                    .checked_add(key_bytes)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
                if retained_bytes > memory_budget {
                    return Err(QueryFailure::new(QueryFailureCode::BudgetExhausted));
                }
                entry.insert(1);
            },
        }
    }
    let mut grouped = Vec::with_capacity(groups.len());
    for (key, count) in groups {
        if cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        grouped.push(key.into_record(count));
    }
    Ok(grouped)
}

pub(crate) fn compare_records(
    left: &QueryRecord,
    right: &QueryRecord,
    ordering: crate::plan::OrderSpec,
) -> Ordering {
    let primary = left.query_time().cmp(&right.query_time());
    let primary = match ordering.primary_direction() {
        crate::plan::OrderDirection::Ascending => primary,
        crate::plan::OrderDirection::Descending => primary.reverse(),
    };
    if primary != Ordering::Equal {
        return primary;
    }
    let commit = left.commit_position().cmp(&right.commit_position());
    match ordering.commit_direction() {
        crate::plan::OrderDirection::Ascending => commit,
        crate::plan::OrderDirection::Descending => commit.reverse(),
    }
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
    cancellation: &crate::QueryCancellation,
) -> Result<(), QueryFailure> {
    state.output_rows = state
        .output_rows
        .checked_add(
            u64::try_from(page.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?,
        )
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    let mut page_bytes = 0_u64;
    for record in page {
        if cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        page_bytes = page_bytes
            .checked_add(record.emitted_size_bytes()?)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    }
    state.output_bytes = state
        .output_bytes
        .checked_add(page_bytes)
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
    cancellation: &crate::QueryCancellation,
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
        if cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        let (query_time, position) = record.order_key();
        encoding.extend_from_slice(&query_time.value().to_be_bytes());
        encoding.extend_from_slice(&position.value().to_be_bytes());
        let body = record.body_text().unwrap_or_default().as_bytes();
        encoding.push(u8::from(record.body_text().is_some()));
        encoding.extend_from_slice(
            &u64::try_from(body.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
                .to_be_bytes(),
        );
        encoding.extend_from_slice(body);
        encoding.push(u8::from(record.count().is_some()));
        if let Some(count) = record.count() {
            encoding.extend_from_slice(&count.to_be_bytes());
        }
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
