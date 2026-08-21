use std::cmp::Ordering;

use positron_domain::time::{EventTime, QueryTime};
use positron_kernel::IngestTime;

use crate::cursor::CursorState;
use crate::{QueryFailure, QueryFailureCode, QueryRecord};

use super::accounting::{charge_work, exhausted};
use super::vocabulary::{query_time_provenance_tag, source_time_quality_tag};

const MAX_GROUPS: usize = 1_024;
const GROUP_ENCODING_CHUNK_BYTES: u64 = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
enum GroupValue {
    Body(Option<positron_domain::value::ValidatedAttributeValue>),
    QueryTime(QueryTime),
    EventTime(EventTime),
    IngestTime(IngestTime),
    CommitPosition(positron_domain::routing::CommitPosition),
}

const _: () = assert!(
    std::mem::size_of::<GroupValue>() <= crate::memory::GROUP_VALUE_SLOT_BYTES as usize,
    "the canonical group-value slot charge must cover every retained key component"
);

#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupKey {
    values: Vec<GroupValue>,
    body_retained_bytes: u64,
}

impl GroupKey {
    fn for_record(
        record: QueryRecord,
        columns: &[crate::plan::ProjectionColumn],
    ) -> Result<(Self, u64), QueryFailure> {
        let fields = record.into_group_fields()?;
        let mut body = fields.body;
        let body_retained_bytes = fields.body_retained_bytes;
        let mut values = Vec::new();
        values
            .try_reserve_exact(columns.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        for column in columns {
            values.push(match column {
                crate::plan::ProjectionColumn::Body => GroupValue::Body(body.take()),
                crate::plan::ProjectionColumn::QueryTime => {
                    GroupValue::QueryTime(fields.query_time)
                },
                crate::plan::ProjectionColumn::EventTime => {
                    GroupValue::EventTime(fields.event_time)
                },
                crate::plan::ProjectionColumn::IngestTime => {
                    GroupValue::IngestTime(fields.ingest_time)
                },
                crate::plan::ProjectionColumn::CommitPosition => {
                    GroupValue::CommitPosition(fields.commit_position)
                },
            });
        }
        Ok((
            Self {
                values,
                body_retained_bytes,
            },
            body_retained_bytes,
        ))
    }

    fn into_record(self, count: u64) -> QueryRecord {
        let mut body = None;
        let mut body_selected = false;
        let mut query_time = None;
        let mut event_time = None;
        let mut ingest_time = None;
        let mut commit_position = None;
        for value in self.values {
            match value {
                GroupValue::Body(value) => {
                    body = value;
                    body_selected = true;
                },
                GroupValue::QueryTime(value) => query_time = Some(value),
                GroupValue::EventTime(value) => event_time = Some(value),
                GroupValue::IngestTime(value) => ingest_time = Some(value),
                GroupValue::CommitPosition(value) => commit_position = Some(value),
            }
        }
        QueryRecord::grouped_count_record(
            crate::stream::GroupedCountFields {
                body,
                body_retained_bytes: self.body_retained_bytes,
                body_selected,
                query_time,
                event_time,
                ingest_time,
                commit_position,
            },
            count,
        )
    }

    fn comparison_encoding(
        &self,
        service: &crate::QueryService<'_, '_, '_>,
        state: &mut CursorState,
        memory: &mut crate::memory::QueryMemory,
    ) -> Result<(Vec<u8>, u64), QueryFailure> {
        let mut encoding = Vec::new();
        let mut memory_bytes = 0_u64;
        for value in &self.values {
            if let Err(failure) = append_group_value_comparison(
                value,
                service,
                state,
                memory,
                &mut encoding,
                &mut memory_bytes,
            ) {
                drop(encoding);
                memory.release(memory_bytes)?;
                return Err(failure);
            }
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
        let (comparison, comparison_bytes) = key.comparison_encoding(service, state, memory)?;
        match find_group(service, state, &groups, &comparison)? {
            Ok(index) => {
                let entry = groups
                    .get_mut(index)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
                entry.count = entry
                    .count
                    .checked_add(1)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
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

fn append_group_value_comparison(
    value: &GroupValue,
    service: &crate::QueryService<'_, '_, '_>,
    state: &mut CursorState,
    memory: &mut crate::memory::QueryMemory,
    output: &mut Vec<u8>,
    memory_bytes: &mut u64,
) -> Result<(), QueryFailure> {
    let mut append = |bytes: &[u8]| {
        append_metered_group_bytes(service, state, memory, output, memory_bytes, bytes)
    };
    match value {
        GroupValue::Body(body) => {
            append(&[0, u8::from(body.is_some())])?;
            if let Some(body) = body {
                body.visit_comparison_encoding(&mut append)?;
            }
        },
        GroupValue::QueryTime(value) => {
            append(&[1])?;
            let ordered = (value.instant().value() as u64) ^ (1_u64 << 63);
            append(&ordered.to_be_bytes())?;
            append(&[query_time_provenance_tag(value.provenance())])?;
        },
        GroupValue::EventTime(value) => {
            append(&[2, u8::from(value.instant().is_some())])?;
            if let Some(value) = value.instant() {
                let ordered = (value.value() as u64) ^ (1_u64 << 63);
                append(&ordered.to_be_bytes())?;
            }
            append(&[source_time_quality_tag(value.quality())])?;
        },
        GroupValue::IngestTime(value) => {
            append(&[4])?;
            let ordered = (value.instant().value() as u64) ^ (1_u64 << 63);
            append(&ordered.to_be_bytes())?;
        },
        GroupValue::CommitPosition(value) => {
            append(&[3])?;
            append(&value.value().to_be_bytes())?;
        },
    }
    Ok(())
}

fn append_metered_group_bytes(
    service: &crate::QueryService<'_, '_, '_>,
    state: &mut CursorState,
    memory: &mut crate::memory::QueryMemory,
    output: &mut Vec<u8>,
    memory_bytes: &mut u64,
    bytes: &[u8],
) -> Result<(), QueryFailure> {
    charge_group_unit(service, state)?;
    for byte in bytes {
        if state.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        let length = u64::try_from(output.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
        if length == *memory_bytes {
            let next_memory_bytes = memory_bytes
                .checked_add(GROUP_ENCODING_CHUNK_BYTES)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
            memory.acquire(GROUP_ENCODING_CHUNK_BYTES)?;
            let reserve = usize::try_from(GROUP_ENCODING_CHUNK_BYTES)
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
            if output.try_reserve_exact(reserve).is_err() {
                memory.release(GROUP_ENCODING_CHUNK_BYTES)?;
                return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
            }
            *memory_bytes = next_memory_bytes;
        }
        output.push(*byte);
    }
    Ok(())
}
