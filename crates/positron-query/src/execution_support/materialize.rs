use positron_domain::time::{IngestTimeCandidate, QueryTime};

use crate::{LogicalPlan, QueryFailure, QueryFailureCode, QueryRecord, TemporalAxis};

use super::failure::map_domain_value_failure;

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
    let (body, body_retained_bytes) = if body_selected {
        record
            .body()
            .map(|body| try_retained_value(body, memory))
            .transpose()?
            .map_or((None, 0), |(body, bytes)| (Some(body), bytes))
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
        },
    )))
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
