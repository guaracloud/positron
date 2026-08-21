use positron_domain::time::{IngestTimeCandidate, QueryTime};

use crate::{LogicalPlan, QueryFailure, QueryFailureCode, QueryRecord, TemporalAxis};

use super::failure::map_domain_value_failure;

pub(crate) fn query_record(
    record: &positron_signals::ScannedLogRecord,
    plan: &LogicalPlan,
    memory: &mut crate::memory::QueryMemory,
) -> Result<Option<QueryRecord>, QueryFailure> {
    if let Some(filter) = plan.filter() {
        let matched = match filter {
            crate::plan::FilterPredicate::BodyEquals(expected) => record.body() == Some(expected),
            crate::plan::FilterPredicate::AttributeEquals(query) => {
                query.matches_stored_record(record.stored())
            },
        };
        if !matched {
            return Ok(None);
        }
    }
    let observed = record.observed_time();
    let ingest_time = record.ingest_time();
    let query_time = QueryTime::for_log(
        &record.event_time(),
        observed.as_ref(),
        IngestTimeCandidate::new(ingest_time.instant()),
    );
    let event_time = record.event_time();
    let Some(ordering_time) = (match plan.temporal_axis() {
        TemporalAxis::QueryTime => Some(query_time.instant()),
        TemporalAxis::EventTime => event_time.instant(),
        TemporalAxis::IngestTime => Some(ingest_time.instant()),
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
    let (attributes, attribute_retained_bytes) =
        project_attributes(record.stored(), selected_columns, memory)?;
    let (body, body_retained_bytes) = if body_selected {
        match record
            .body()
            .map(|body| try_retained_value(body, memory))
            .transpose()
        {
            Ok(value) => value.map_or((None, 0), |(body, bytes)| (Some(body), bytes)),
            Err(failure) => {
                memory.release(attribute_retained_bytes)?;
                return Err(failure);
            },
        }
    } else {
        (None, 0)
    };
    Ok(Some(QueryRecord::new(
        body,
        body_retained_bytes,
        crate::stream::QueryRecordTimes {
            query: query_time,
            event: event_time,
            ingest: ingest_time,
            ordering: ordering_time,
        },
        record.commit_position(),
        record.record_ordinal(),
        crate::stream::QueryRecordSelection {
            body: body_selected,
            query_time: selected_columns.contains(&crate::plan::ProjectionColumn::QueryTime),
            event_time: selected_columns.contains(&crate::plan::ProjectionColumn::EventTime),
            ingest_time: selected_columns.contains(&crate::plan::ProjectionColumn::IngestTime),
            commit_position: selected_columns
                .contains(&crate::plan::ProjectionColumn::CommitPosition),
            attributes,
            attribute_retained_bytes,
        },
    )))
}

fn project_attributes(
    record: &positron_signals::StoredLogRecord,
    columns: &[crate::plan::ProjectionColumn],
    memory: &mut crate::memory::QueryMemory,
) -> Result<(Vec<crate::stream::AttributeProjection>, u64), QueryFailure> {
    let slot_size = u64::try_from(std::mem::size_of::<crate::stream::AttributeProjection>())
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    let slots = u64::try_from(columns.len())
        .ok()
        .and_then(|count| count.checked_mul(slot_size))
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    memory.acquire(slots)?;
    let mut values = Vec::new();
    if values.try_reserve_exact(columns.len()).is_err() {
        memory.release(slots)?;
        return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
    }
    let mut retained = slots;
    for column in columns {
        let crate::plan::ProjectionColumn::Attribute(path) = column else {
            values.push(crate::stream::AttributeProjection::Intrinsic);
            continue;
        };
        let estimated = match record.projected_attribute_retained_bytes(path) {
            Ok(value) => value,
            Err(failure) => {
                memory.release(retained)?;
                return Err(map_schema_failure(failure));
            },
        };
        let bytes = match estimated.map(u64::try_from).transpose() {
            Ok(value) => value.unwrap_or(0),
            Err(_) => {
                memory.release(retained)?;
                return Err(QueryFailure::new(QueryFailureCode::BudgetExhausted));
            },
        };
        if let Err(failure) = memory.acquire(bytes) {
            memory.release(retained)?;
            return Err(failure);
        }
        retained = match retained.checked_add(bytes) {
            Some(value) => value,
            None => {
                memory.release(bytes)?;
                memory.release(retained)?;
                return Err(QueryFailure::new(QueryFailureCode::BudgetExhausted));
            },
        };
        match record.project_attribute(path) {
            Ok(value) => values.push(crate::stream::AttributeProjection::Attribute(value)),
            Err(failure) => {
                memory.release(retained)?;
                return Err(map_schema_failure(failure));
            },
        }
    }
    Ok((values, retained))
}

fn map_schema_failure(failure: positron_signals::SchemaFailure) -> QueryFailure {
    match failure {
        positron_signals::SchemaFailure::AllocationUnavailable => {
            QueryFailure::new(QueryFailureCode::ResourceExhausted)
        },
        positron_signals::SchemaFailure::LimitExceeded => {
            QueryFailure::new(QueryFailureCode::BudgetExhausted)
        },
        _ => QueryFailure::new(QueryFailureCode::Internal),
    }
}

fn try_retained_value(
    value: &positron_domain::value::ValidatedAttributeValue,
    memory: &mut crate::memory::QueryMemory,
) -> Result<(positron_domain::value::ValidatedAttributeValue, u64), QueryFailure> {
    let bytes = u64::try_from(
        value
            .retained_heap_bytes()
            .map_err(map_domain_value_failure)?,
    )
    .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    memory.acquire(bytes)?;
    match value.try_clone() {
        Ok(retained) => Ok((retained, bytes)),
        Err(failure) => {
            memory.release(bytes)?;
            Err(map_domain_value_failure(failure))
        },
    }
}
