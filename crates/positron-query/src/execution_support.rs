use positron_domain::time::{IngestTimeCandidate, QueryTime};
use std::cmp::Ordering;

use crate::cursor::CursorState;
use crate::{LogicalPlan, QueryFailure, QueryFailureCode, QueryRecord, TemporalAxis};

const MAX_GROUPS: usize = 1_024;
const DIGEST_STATE_BYTES: u64 = 256;
const DIGEST_CONTRACT_BYTES: usize = 128;
const DIGEST_CHUNK_BYTES: usize = 1_024;

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
    let query_time = QueryTime::for_log(
        &record.event_time(),
        observed.as_ref(),
        IngestTimeCandidate::new(record.ingest_time().instant()),
    )
    .instant();
    let event_time = record.event_time().instant();
    let Some(ordering_time) = (match plan.temporal_axis() {
        TemporalAxis::QueryTime => Some(query_time),
        TemporalAxis::EventTime => event_time,
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
        crate::stream::QueryRecordTimes {
            query: query_time,
            event: event_time,
            ordering: ordering_time,
        },
        record.commit_position(),
        record.record_ordinal(),
        crate::stream::QueryRecordSelection {
            body: body_selected,
            query_time: selected_columns.contains(&crate::plan::ProjectionColumn::QueryTime),
            event_time: selected_columns.contains(&crate::plan::ProjectionColumn::EventTime),
            commit_position: selected_columns
                .contains(&crate::plan::ProjectionColumn::CommitPosition),
        },
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum GroupValue {
    Body(Option<positron_domain::value::ValidatedAttributeValue>),
    QueryTime(positron_domain::time::UnixNanoseconds),
    EventTime(Option<positron_domain::time::UnixNanoseconds>),
    CommitPosition(positron_domain::routing::CommitPosition),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupKey(Vec<GroupValue>);

impl GroupKey {
    fn for_record(
        record: QueryRecord,
        columns: &[crate::plan::ProjectionColumn],
    ) -> Result<(Self, u64), QueryFailure> {
        let (mut body, query_time, event_time, commit_position) = record.into_group_fields();
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
                crate::plan::ProjectionColumn::EventTime => GroupValue::EventTime(event_time),
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
        let mut event_time = None;
        let mut commit_position = None;
        for value in self.0 {
            match value {
                GroupValue::Body(value) => {
                    body = value;
                    body_selected = true;
                },
                GroupValue::QueryTime(value) => query_time = Some(value),
                GroupValue::EventTime(value) => event_time = Some(value),
                GroupValue::CommitPosition(value) => commit_position = Some(value),
            }
        }
        QueryRecord::grouped_count_record(
            body,
            body_selected,
            query_time,
            event_time,
            commit_position,
            count,
        )
    }

    fn comparison_encoding(
        &self,
        memory: &mut crate::memory::QueryMemory,
    ) -> Result<(Vec<u8>, u64), QueryFailure> {
        let encoded_bytes = self.0.iter().try_fold(0_usize, |total, value| {
            total
                .checked_add(group_value_comparison_size(value)?)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))
        })?;
        let memory_bytes = u64::try_from(encoded_bytes)
            .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
        memory.acquire(memory_bytes)?;
        let mut encoding = Vec::new();
        encoding
            .try_reserve_exact(encoded_bytes)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        for value in &self.0 {
            append_group_value_comparison(value, &mut encoding)?;
        }
        if encoding.len() != encoded_bytes {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        Ok((encoding, memory_bytes))
    }
}

struct GroupEntry {
    key: GroupKey,
    comparison: Vec<u8>,
    comparison_bytes: u64,
    count: u64,
}

pub(crate) fn aggregate_records<'kernel, 'catalog, 'ledger>(
    service: &crate::QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    records: crate::memory::RecordBuffer,
    aggregate: &crate::plan::AggregateSpec,
    memory: &mut crate::memory::QueryMemory,
) -> Result<crate::memory::RecordBuffer, QueryFailure> {
    if state.cancellation.is_cancelled() {
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
    let (records, record_slots, _) = records.into_parts();
    let group_capacity = records.len().min(MAX_GROUPS);
    let group_slots = u64::try_from(group_capacity)
        .ok()
        .and_then(|count| count.checked_mul(crate::memory::GROUP_ENTRY_BYTES))
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    memory.acquire(group_slots)?;
    let mut groups = Vec::<GroupEntry>::new();
    groups
        .try_reserve_exact(group_capacity)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let key_slots = u64::try_from(aggregate.group_by().len())
        .ok()
        .and_then(|count| count.checked_mul(crate::memory::GROUP_VALUE_SLOT_BYTES))
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    for record in records {
        if state.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        memory.acquire(key_slots)?;
        let (key, body_bytes) = GroupKey::for_record(record, aggregate.group_by())?;
        let (comparison, comparison_bytes) = key.comparison_encoding(memory)?;
        match find_group(service, state, &groups, &comparison)? {
            Ok(index) => {
                let entry = groups
                    .get_mut(index)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
                let count = entry
                    .count
                    .checked_add(1)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
                entry.count = count;
                drop(comparison);
                memory.release(comparison_bytes)?;
                memory.release(key_slots)?;
                memory.release(body_bytes)?;
            },
            Err(index) => {
                if groups.len() >= MAX_GROUPS {
                    return Err(QueryFailure::new(QueryFailureCode::BudgetExhausted));
                }
                charge_group_moves(service, state, groups.len().saturating_sub(index))?;
                groups.insert(
                    index,
                    GroupEntry {
                        key,
                        comparison,
                        comparison_bytes,
                        count: 1,
                    },
                );
            },
        }
    }
    memory.release(record_slots)?;
    let mut grouped = crate::memory::RecordBuffer::allocate(groups.len(), memory)?;
    for entry in groups {
        if state.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        let record = entry.key.into_record(entry.count);
        let dynamic_bytes = record.retained_dynamic_bytes()?;
        grouped.push_acquired(record, dynamic_bytes)?;
        drop(entry.comparison);
        memory.release(entry.comparison_bytes)?;
        memory.release(key_slots)?;
    }
    memory.release(group_slots)?;
    Ok(grouped)
}

fn find_group<'kernel, 'catalog, 'ledger>(
    service: &crate::QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    groups: &[GroupEntry],
    wanted: &[u8],
) -> Result<Result<usize, usize>, QueryFailure> {
    let mut start = 0_usize;
    let mut end = groups.len();
    while start < end {
        let middle = start
            .checked_add((end - start) / 2)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let existing = groups
            .get(middle)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        match compare_group_bytes(service, state, &existing.comparison, wanted)? {
            Ordering::Less => start = middle + 1,
            Ordering::Greater => end = middle,
            Ordering::Equal => return Ok(Ok(middle)),
        }
    }
    Ok(Err(start))
}

fn compare_group_bytes<'kernel, 'catalog, 'ledger>(
    service: &crate::QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    left: &[u8],
    right: &[u8],
) -> Result<Ordering, QueryFailure> {
    for (left, right) in left.iter().zip(right) {
        charge_group_unit(service, state)?;
        match left.cmp(right) {
            Ordering::Equal => {},
            ordering => return Ok(ordering),
        }
    }
    charge_group_unit(service, state)?;
    Ok(left.len().cmp(&right.len()))
}

fn charge_group_moves<'kernel, 'catalog, 'ledger>(
    service: &crate::QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    moves: usize,
) -> Result<(), QueryFailure> {
    for _ in 0..moves {
        charge_group_unit(service, state)?;
    }
    Ok(())
}

fn charge_group_unit<'kernel, 'catalog, 'ledger>(
    service: &crate::QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
) -> Result<(), QueryFailure> {
    if state.cancellation.is_cancelled() {
        return Err(QueryFailure::new(QueryFailureCode::Cancelled));
    }
    let units = service.work_units(crate::QueryWorkStage::Operators)?;
    if state.cancellation.is_cancelled() {
        return Err(QueryFailure::new(QueryFailureCode::Cancelled));
    }
    charge_work(state, units)?;
    if exhausted(state) {
        return Err(QueryFailure::new(QueryFailureCode::BudgetExhausted));
    }
    if state.cancellation.is_cancelled() {
        return Err(QueryFailure::new(QueryFailureCode::Cancelled));
    }
    Ok(())
}

fn group_value_comparison_size(value: &GroupValue) -> Result<usize, QueryFailure> {
    match value {
        GroupValue::Body(None) => Ok(2),
        GroupValue::Body(Some(value)) => value
            .comparison_encoded_size_bytes()
            .map_err(map_domain_value_failure)?
            .checked_add(2)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted)),
        GroupValue::QueryTime(_) | GroupValue::CommitPosition(_) => Ok(9),
        GroupValue::EventTime(None) => Ok(2),
        GroupValue::EventTime(Some(_)) => Ok(10),
    }
}

fn append_group_value_comparison(
    value: &GroupValue,
    output: &mut Vec<u8>,
) -> Result<(), QueryFailure> {
    match value {
        GroupValue::Body(body) => {
            output.push(0);
            output.push(u8::from(body.is_some()));
            if let Some(body) = body {
                body.append_comparison_encoding(output)
                    .map_err(map_domain_value_failure)?;
            }
        },
        GroupValue::QueryTime(value) => {
            output.push(1);
            let ordered = (value.value() as u64) ^ (1_u64 << 63);
            output.extend_from_slice(&ordered.to_be_bytes());
        },
        GroupValue::EventTime(value) => {
            output.push(2);
            output.push(u8::from(value.is_some()));
            if let Some(value) = value {
                let ordered = (value.value() as u64) ^ (1_u64 << 63);
                output.extend_from_slice(&ordered.to_be_bytes());
            }
        },
        GroupValue::CommitPosition(value) => {
            output.push(3);
            output.extend_from_slice(&value.value().to_be_bytes());
        },
    }
    Ok(())
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
    memory: &mut crate::memory::QueryMemory,
) -> Result<[u8; 32], QueryFailure> {
    memory.acquire(DIGEST_STATE_BYTES)?;
    let result = batch_digest_with_acquired_state(
        protector,
        prior,
        sequence,
        plan,
        records,
        cancellation,
        memory,
    );
    memory.release(DIGEST_STATE_BYTES)?;
    result
}

fn batch_digest_with_acquired_state(
    protector: &positron_kernel::ControlTokenProtector<'_>,
    prior: [u8; 32],
    sequence: u64,
    plan: &LogicalPlan,
    records: &[QueryRecord],
    cancellation: &crate::QueryCancellation,
    memory: &mut crate::memory::QueryMemory,
) -> Result<[u8; 32], QueryFailure> {
    check_digest_cancellation(cancellation)?;
    let mut digest = protector
        .query_result_digest()
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    digest.update(&prior);
    digest.update(&sequence.to_be_bytes());
    update_result_contract_digest(&mut digest, plan, cancellation, memory)?;
    digest.update(
        &u64::try_from(records.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
            .to_be_bytes(),
    );
    for record in records {
        check_digest_cancellation(cancellation)?;
        let (query_time, position, ordinal) = record.order_key();
        digest.update(&query_time.value().to_be_bytes());
        digest.update(&position.value().to_be_bytes());
        digest.update(&ordinal.value().to_be_bytes());
        digest.update(&[u8::from(record.body_value().is_some())]);
        if let Some(body) = record.body_value() {
            update_native_value_digest(&mut digest, body, cancellation, memory)?;
        }
        digest.update(&[u8::from(record.query_time_selected())]);
        if record.query_time_selected() {
            digest.update(&record.query_time().value().to_be_bytes());
        }
        digest.update(&[u8::from(record.event_time_selected())]);
        if record.event_time_selected() {
            digest.update(&[u8::from(record.event_time().is_some())]);
            if let Some(event_time) = record.event_time() {
                digest.update(&event_time.value().to_be_bytes());
            }
        }
        digest.update(&[u8::from(record.count().is_some())]);
        if let Some(count) = record.count() {
            digest.update(&count.to_be_bytes());
        }
    }
    check_digest_cancellation(cancellation)?;
    digest
        .finalize()
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
}

fn update_result_contract_digest(
    digest: &mut positron_kernel::QueryResultDigest,
    plan: &LogicalPlan,
    cancellation: &crate::QueryCancellation,
    memory: &mut crate::memory::QueryMemory,
) -> Result<(), QueryFailure> {
    check_digest_cancellation(cancellation)?;
    let scratch_bytes = u64::try_from(DIGEST_CONTRACT_BYTES)
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    memory.acquire(scratch_bytes)?;
    let mut encoding = Vec::new();
    if encoding.try_reserve_exact(DIGEST_CONTRACT_BYTES).is_err() {
        memory.release(scratch_bytes)?;
        return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
    }
    let encoded = encode_result_contract(&mut encoding, plan);
    if encoding.len() > DIGEST_CONTRACT_BYTES {
        drop(encoding);
        memory.release(scratch_bytes)?;
        return Err(QueryFailure::new(QueryFailureCode::Internal));
    }
    if let Err(failure) = encoded {
        drop(encoding);
        memory.release(scratch_bytes)?;
        return Err(failure);
    }
    digest.update(&encoding);
    drop(encoding);
    memory.release(scratch_bytes)?;
    Ok(())
}

fn update_native_value_digest(
    digest: &mut positron_kernel::QueryResultDigest,
    value: &positron_domain::value::ValidatedAttributeValue,
    cancellation: &crate::QueryCancellation,
    memory: &mut crate::memory::QueryMemory,
) -> Result<(), QueryFailure> {
    check_digest_cancellation(cancellation)?;
    let encoded_bytes = value
        .canonical_encoded_size_bytes()
        .map_err(map_domain_value_failure)?;
    let memory_bytes =
        u64::try_from(encoded_bytes).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    memory.acquire(memory_bytes)?;
    let mut encoding = Vec::new();
    if encoding.try_reserve_exact(encoded_bytes).is_err() {
        memory.release(memory_bytes)?;
        return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
    }
    if let Err(failure) = value.append_canonical_encoding(&mut encoding) {
        drop(encoding);
        memory.release(memory_bytes)?;
        return Err(map_domain_value_failure(failure));
    }
    if encoding.len() != encoded_bytes {
        drop(encoding);
        memory.release(memory_bytes)?;
        return Err(QueryFailure::new(QueryFailureCode::Internal));
    }
    for chunk in encoding.chunks(DIGEST_CHUNK_BYTES) {
        check_digest_cancellation(cancellation)?;
        digest.update(chunk);
    }
    drop(encoding);
    memory.release(memory_bytes)?;
    Ok(())
}

fn check_digest_cancellation(cancellation: &crate::QueryCancellation) -> Result<(), QueryFailure> {
    if cancellation.is_cancelled() {
        Err(QueryFailure::new(QueryFailureCode::Cancelled))
    } else {
        Ok(())
    }
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
        crate::plan::ProjectionColumn::EventTime => 3,
        crate::plan::ProjectionColumn::CommitPosition => 2,
    }
}

const fn result_value_type_tag(value_type: crate::ResultValueType) -> u8 {
    match value_type {
        crate::ResultValueType::NativeValue => 0,
        crate::ResultValueType::UnixNanoseconds => 1,
        crate::ResultValueType::OptionalUnixNanoseconds => 5,
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
