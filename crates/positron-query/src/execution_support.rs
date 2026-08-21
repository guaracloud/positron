use positron_domain::time::{IngestTimeCandidate, QueryTime};
use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::cursor::CursorState;
use crate::{LogicalPlan, QueryFailure, QueryFailureCode, QueryRecord, TemporalAxis};

const MAX_GROUPS: usize = 1_024;

pub(crate) fn query_record(
    record: &positron_signals::ScannedLogRecord,
    plan: &LogicalPlan,
    memory: &mut crate::memory::QueryMemory,
) -> Result<Option<QueryRecord>, QueryFailure> {
    if let Some(crate::plan::FilterPredicate::BodyEquals(expected)) = plan.filter()
        && record.body() != Some(expected)
    {
        return Ok(None);
    }
    let observed = record.observed_time();
    let Some(ordering_time) = (match plan.temporal_axis() {
        TemporalAxis::QueryTime => Some(
            QueryTime::for_log(
                &record.event_time(),
                observed.as_ref(),
                IngestTimeCandidate::new(record.ingest_time().instant()),
            )
            .instant(),
        ),
        TemporalAxis::EventTime => record.event_time().instant(),
    }) else {
        return Ok(None);
    };
    if !plan.temporal_range().contains(ordering_time) {
        return Ok(None);
    }
    let selected_columns = plan
        .aggregate()
        .map(crate::plan::AggregateSpec::group_by)
        .unwrap_or_else(|| plan.projection());
    let body_selected = selected_columns.contains(&crate::plan::ProjectionColumn::Body);
    let body = if body_selected {
        record
            .body()
            .map(|body| try_retained_value(body, memory))
            .transpose()?
    } else {
        None
    };
    Ok(Some(QueryRecord::new(
        body,
        body_selected,
        ordering_time,
        record.commit_position(),
        record.record_ordinal(),
        selected_columns.contains(&crate::plan::ProjectionColumn::QueryTime),
        selected_columns.contains(&crate::plan::ProjectionColumn::CommitPosition),
    )))
}

fn try_retained_value(
    value: &positron_domain::value::ValidatedAttributeValue,
    memory: &mut crate::memory::QueryMemory,
) -> Result<positron_domain::value::ValidatedAttributeValue, QueryFailure> {
    let bytes = u64::try_from(
        value
            .retained_heap_bytes()
            .map_err(map_domain_value_failure)?,
    )
    .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    memory.acquire(bytes)?;
    match value.try_clone() {
        Ok(retained) => Ok(retained),
        Err(failure) => {
            memory.release(bytes)?;
            Err(map_domain_value_failure(failure))
        },
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum GroupValue {
    Body(Option<positron_domain::value::ValidatedAttributeValue>),
    QueryTime(positron_domain::time::UnixNanoseconds),
    CommitPosition(positron_domain::routing::CommitPosition),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct GroupKey(Vec<GroupValue>);

impl GroupKey {
    fn for_record(
        record: QueryRecord,
        columns: &[crate::plan::ProjectionColumn],
    ) -> Result<(Self, u64), QueryFailure> {
        let (mut body, query_time, commit_position) = record.into_group_fields();
        let body_bytes = u64::try_from(
            body.as_ref()
                .map_or(Ok(0), |body| body.retained_heap_bytes())
                .map_err(map_domain_value_failure)?,
        )
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(columns.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        for column in columns {
            values.push(match column {
                crate::plan::ProjectionColumn::Body => GroupValue::Body(body.take()),
                crate::plan::ProjectionColumn::QueryTime => GroupValue::QueryTime(query_time),
                crate::plan::ProjectionColumn::CommitPosition => {
                    GroupValue::CommitPosition(commit_position)
                },
            });
        }
        Ok((Self(values), body_bytes))
    }

    fn into_record(self, count: u64) -> QueryRecord {
        let mut body = None;
        let mut body_selected = false;
        let mut query_time = None;
        let mut commit_position = None;
        for value in self.0 {
            match value {
                GroupValue::Body(value) => {
                    body = value;
                    body_selected = true;
                },
                GroupValue::QueryTime(value) => query_time = Some(value),
                GroupValue::CommitPosition(value) => commit_position = Some(value),
            }
        }
        QueryRecord::grouped_count_record(body, body_selected, query_time, commit_position, count)
    }
}

pub(crate) fn aggregate_records(
    records: crate::memory::RecordBuffer,
    aggregate: &crate::plan::AggregateSpec,
    memory: &mut crate::memory::QueryMemory,
    cancellation: &crate::QueryCancellation,
) -> Result<crate::memory::RecordBuffer, QueryFailure> {
    if cancellation.is_cancelled() {
        return Err(QueryFailure::new(QueryFailureCode::Cancelled));
    }
    if aggregate.group_by().is_empty() {
        let count = u64::try_from(records.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
        let (_, slot_bytes, dynamic_bytes) = records.into_parts();
        memory.release(slot_bytes)?;
        memory.release(dynamic_bytes)?;
        let mut counted = crate::memory::RecordBuffer::allocate(1, memory)?;
        counted.push_acquired(QueryRecord::count_record(count), 0)?;
        return Ok(counted);
    }
    let mut groups = BTreeMap::<GroupKey, u64>::new();
    let (records, record_slots, _) = records.into_parts();
    let key_slots = u64::try_from(aggregate.group_by().len())
        .ok()
        .and_then(|count| count.checked_mul(crate::memory::GROUP_VALUE_SLOT_BYTES))
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    for record in records {
        if cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        memory.acquire(key_slots)?;
        let (key, body_bytes) = match GroupKey::for_record(record, aggregate.group_by()) {
            Ok(key) => key,
            Err(failure) => {
                memory.release(key_slots)?;
                return Err(failure);
            },
        };
        let at_capacity = groups.len() >= MAX_GROUPS;
        match groups.entry(key) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let count = entry
                    .get()
                    .checked_add(1)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
                *entry.get_mut() = count;
                memory.release(key_slots)?;
                memory.release(body_bytes)?;
            },
            std::collections::btree_map::Entry::Vacant(entry) => {
                if at_capacity {
                    return Err(QueryFailure::new(QueryFailureCode::BudgetExhausted));
                }
                memory.acquire(crate::memory::GROUP_ENTRY_BYTES)?;
                entry.insert(1);
            },
        }
    }
    memory.release(record_slots)?;
    let mut grouped = crate::memory::RecordBuffer::allocate(groups.len(), memory)?;
    for (key, count) in groups {
        if cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        let record = key.into_record(count);
        let dynamic_bytes = record.retained_dynamic_bytes()?;
        grouped.push_acquired(record, dynamic_bytes)?;
        memory.release(key_slots)?;
        memory.release(crate::memory::GROUP_ENTRY_BYTES)?;
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
    let commit = match ordering.commit_direction() {
        crate::plan::OrderDirection::Ascending => commit,
        crate::plan::OrderDirection::Descending => commit.reverse(),
    };
    if commit != Ordering::Equal {
        return commit;
    }
    let ordinal = left.record_ordinal().cmp(&right.record_ordinal());
    match ordering.commit_direction() {
        crate::plan::OrderDirection::Ascending => ordinal,
        crate::plan::OrderDirection::Descending => ordinal.reverse(),
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
    plan: &LogicalPlan,
    records: &[QueryRecord],
    cancellation: &crate::QueryCancellation,
) -> Result<[u8; 32], QueryFailure> {
    let mut encoding = Vec::new();
    encoding.extend_from_slice(&prior);
    encoding.extend_from_slice(&sequence.to_be_bytes());
    encode_result_contract(&mut encoding, plan)?;
    encoding.extend_from_slice(
        &u64::try_from(records.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
            .to_be_bytes(),
    );
    for record in records {
        if cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        let (query_time, position, ordinal) = record.order_key();
        encoding.extend_from_slice(&query_time.value().to_be_bytes());
        encoding.extend_from_slice(&position.value().to_be_bytes());
        encoding.extend_from_slice(&ordinal.value().to_be_bytes());
        encoding.push(u8::from(record.body_value().is_some()));
        if let Some(body) = record.body_value() {
            body.append_canonical_encoding(&mut encoding)
                .map_err(map_domain_value_failure)?;
        }
        encoding.push(u8::from(record.count().is_some()));
        if let Some(count) = record.count() {
            encoding.extend_from_slice(&count.to_be_bytes());
        }
    }
    protector
        .digest(b"query-result-batch-v1", &encoding)
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
}

fn map_domain_value_failure(failure: positron_domain::outcome::DomainFailure) -> QueryFailure {
    if failure.code() == positron_domain::outcome::DomainFailureCode::AllocationUnavailable {
        QueryFailure::new(QueryFailureCode::ResourceExhausted)
    } else {
        QueryFailure::new(QueryFailureCode::Internal)
    }
}

fn encode_result_contract(encoding: &mut Vec<u8>, plan: &LogicalPlan) -> Result<(), QueryFailure> {
    let schema = plan
        .aggregate()
        .map(crate::plan::AggregateSpec::group_by)
        .unwrap_or_else(|| plan.projection());
    encoding.extend_from_slice(
        &u64::try_from(schema.len() + usize::from(plan.aggregate().is_some()))
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
            .to_be_bytes(),
    );
    for column in schema {
        encoding.push(projection_column_tag(*column));
        encoding.push(result_value_type_tag(crate::stream::column_type(*column)));
    }
    if plan.aggregate().is_some() {
        encoding.push(3);
        encoding.push(result_value_type_tag(
            crate::ResultValueType::UnsignedInteger,
        ));
        encoding.extend_from_slice(
            &u64::try_from(schema.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
                .to_be_bytes(),
        );
        for column in schema {
            encoding.push(projection_column_tag(*column));
            encoding.push(result_value_type_tag(crate::stream::column_type(*column)));
            encoding.push(order_direction_tag(crate::plan::OrderDirection::Ascending));
        }
    } else {
        encoding.extend_from_slice(&3_u64.to_be_bytes());
        encoding.push(match plan.temporal_axis() {
            crate::TemporalAxis::QueryTime => 4,
            crate::TemporalAxis::EventTime => 5,
        });
        encoding.push(result_value_type_tag(
            crate::ResultValueType::UnixNanoseconds,
        ));
        encoding.push(order_direction_tag(plan.ordering().primary_direction()));
        encoding.push(2);
        encoding.push(result_value_type_tag(
            crate::ResultValueType::CommitPosition,
        ));
        encoding.push(order_direction_tag(plan.ordering().commit_direction()));
        encoding.push(6);
        encoding.push(result_value_type_tag(crate::ResultValueType::RecordOrdinal));
        encoding.push(order_direction_tag(plan.ordering().commit_direction()));
    }
    Ok(())
}

const fn projection_column_tag(column: crate::plan::ProjectionColumn) -> u8 {
    match column {
        crate::plan::ProjectionColumn::Body => 0,
        crate::plan::ProjectionColumn::QueryTime => 1,
        crate::plan::ProjectionColumn::CommitPosition => 2,
    }
}

const fn result_value_type_tag(value_type: crate::ResultValueType) -> u8 {
    match value_type {
        crate::ResultValueType::NativeValue => 0,
        crate::ResultValueType::UnixNanoseconds => 1,
        crate::ResultValueType::CommitPosition => 2,
        crate::ResultValueType::RecordOrdinal => 3,
        crate::ResultValueType::UnsignedInteger => 4,
    }
}

const fn order_direction_tag(direction: crate::plan::OrderDirection) -> u8 {
    match direction {
        crate::plan::OrderDirection::Ascending => 0,
        crate::plan::OrderDirection::Descending => 1,
    }
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
    QueryFailure::new(map_store_failure_code(failure.code()))
}

const fn map_store_failure_code(code: positron_signals::LogStoreFailureCode) -> QueryFailureCode {
    match code {
        positron_signals::LogStoreFailureCode::MalformedBlock => {
            QueryFailureCode::MalformedPersistentData
        },
        positron_signals::LogStoreFailureCode::ResourceAdmissionRefused => {
            QueryFailureCode::ResourceAdmissionRefused
        },
        positron_signals::LogStoreFailureCode::LimitExceeded => QueryFailureCode::BudgetExhausted,
        positron_signals::LogStoreFailureCode::ResourceExhausted => {
            QueryFailureCode::ResourceExhausted
        },
        positron_signals::LogStoreFailureCode::Cancelled => QueryFailureCode::Cancelled,
        _ => QueryFailureCode::StoreUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::map_store_failure_code;
    use crate::QueryFailureCode;

    #[test]
    fn storage_failures_preserve_resource_and_cancellation_truth() {
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::ResourceExhausted),
            QueryFailureCode::ResourceExhausted
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::LimitExceeded),
            QueryFailureCode::BudgetExhausted
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::Cancelled),
            QueryFailureCode::Cancelled
        );
    }
}
