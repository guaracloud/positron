use positron_domain::time::{IngestTimeCandidate, QueryTime};

use crate::{
    LogicalPlan, QueryBudgetDimension, QueryFailure, QueryFailureCode, QueryRecord, TemporalAxis,
};

struct TransformWorkObserver<'a, 'kernel, 'catalog, 'ledger> {
    service: &'a crate::QueryService<'kernel, 'catalog, 'ledger>,
    state: &'a mut crate::cursor::CursorState,
}

impl crate::transform::TransformObserver for TransformWorkObserver<'_, '_, '_, '_> {
    fn step(&mut self) -> Result<(), QueryFailure> {
        if self.state.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        let units = self.service.work_units(crate::QueryWorkStage::Operators)?;
        super::charge_work(self.state, units)?;
        if super::exhausted(self.state) {
            return Err(QueryFailure::budget_exhausted(
                QueryBudgetDimension::CpuWorkUnits,
            ));
        }
        Ok(())
    }
}

pub(crate) fn query_record(
    service: &crate::QueryService<'_, '_, '_>,
    state: &mut crate::cursor::CursorState,
    record: &mut positron_signals::ScannedLogRecord,
    predicate_applied: bool,
    memory: &mut crate::memory::QueryMemory,
) -> Result<Option<QueryRecord>, QueryFailure> {
    let transformed_body = match state.plan.transform() {
        Some(transform) => record
            .body()
            .map(|body| {
                let mut observer = TransformWorkObserver { service, state };
                transform.apply(body, &mut observer)
            })
            .transpose()?,
        None => None,
    };
    let body = transformed_body.as_ref().or_else(|| record.body());
    if !predicate_applied && let Some(filter) = state.plan.filter() {
        let matched = match filter {
            crate::plan::FilterPredicate::BodyEquals(expected) => match body {
                Some(value) => {
                    let mut observer = super::QueryValueObserver::new(
                        service,
                        &mut state.cpu_work_units,
                        state.budget.cpu_work_units(),
                        state.cancellation.clone(),
                        crate::QueryWorkStage::Operators,
                    );
                    value
                        .equals_observed(expected, &mut observer)
                        .map_err(super::map_observed_failure)?
                },
                None => false,
            },
            crate::plan::FilterPredicate::BodyContains(expected) => match body {
                Some(value) => {
                    let mut observer = super::QueryValueObserver::new(
                        service,
                        &mut state.cpu_work_units,
                        state.budget.cpu_work_units(),
                        state.cancellation.clone(),
                        crate::QueryWorkStage::Operators,
                    );
                    match value.as_str() {
                        Some(text) => expected.is_match_observed(text, &mut observer)?,
                        None => false,
                    }
                },
                None => false,
            },
            crate::plan::FilterPredicate::BodyRegex(expected) => match body {
                Some(value) => {
                    let mut observer = super::QueryValueObserver::new(
                        service,
                        &mut state.cpu_work_units,
                        state.budget.cpu_work_units(),
                        state.cancellation.clone(),
                        crate::QueryWorkStage::Operators,
                    );
                    match value.as_str() {
                        Some(text) => expected.is_match_observed(text, &mut observer)?,
                        None => false,
                    }
                },
                None => false,
            },
            crate::plan::FilterPredicate::AttributeEquals(query) => {
                let mut observer = super::QueryValueObserver::new(
                    service,
                    &mut state.cpu_work_units,
                    state.budget.cpu_work_units(),
                    state.cancellation.clone(),
                    crate::QueryWorkStage::Operators,
                );
                query
                    .matches_stored_record_observed(record.stored(), &mut observer)
                    .map_err(super::map_observed_failure)?
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
    let plan: &LogicalPlan = &state.plan;
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
    let query_time_selected = selected_columns.contains(&crate::plan::ProjectionColumn::QueryTime);
    let event_time_selected = selected_columns.contains(&crate::plan::ProjectionColumn::EventTime);
    let ingest_time_selected =
        selected_columns.contains(&crate::plan::ProjectionColumn::IngestTime);
    let commit_position_selected =
        selected_columns.contains(&crate::plan::ProjectionColumn::CommitPosition);
    let cancellation = state.cancellation.clone();
    let cpu_limit = state.budget.cpu_work_units();
    let transformed_retained_bytes = transformed_body
        .as_ref()
        .map(transformed_body_retained_bytes)
        .transpose()?
        .map(|bytes| memory.acquire(bytes).map(|()| bytes))
        .transpose()?;
    let (attributes, attribute_retained_bytes) = match project_attributes(
        record.stored(),
        selected_columns,
        service,
        &mut state.cpu_work_units,
        cpu_limit,
        cancellation.clone(),
        memory,
    ) {
        Ok(value) => value,
        Err(failure) => {
            if let Some(bytes) = transformed_retained_bytes {
                memory.release(bytes)?;
            }
            return Err(failure);
        },
    };
    let (body, body_retained_bytes) = if body_selected {
        if let Some(value) = transformed_body {
            (Some(value), transformed_retained_bytes.unwrap_or(0))
        } else {
            let retained = record.body_retained_bytes();
            (record.take_body(), retained)
        }
    } else {
        if let Some(bytes) = transformed_retained_bytes {
            memory.release(bytes)?;
        }
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
            query_time: query_time_selected,
            event_time: event_time_selected,
            ingest_time: ingest_time_selected,
            commit_position: commit_position_selected,
            attributes,
            attribute_retained_bytes,
        },
    )))
}

fn transformed_body_retained_bytes(
    value: &positron_domain::value::ValidatedAttributeValue,
) -> Result<u64, QueryFailure> {
    value
        .retained_heap_bytes()
        .map_err(super::map_domain_value_failure)
        .and_then(|bytes| {
            u64::try_from(bytes)
                .ok()
                .and_then(|bytes| bytes.checked_add(64))
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))
        })
}

fn project_attributes(
    record: &positron_signals::StoredLogRecord,
    columns: &[crate::plan::ProjectionColumn],
    service: &crate::QueryService<'_, '_, '_>,
    cpu_work_units: &mut u64,
    cpu_limit: u64,
    cancellation: crate::QueryCancellation,
    memory: &mut crate::memory::QueryMemory,
) -> Result<(Vec<crate::stream::AttributeProjection>, u64), QueryFailure> {
    const ATTRIBUTE_PROJECTION_SLOT_BYTES: u64 = 64;
    const _: () = assert!(
        std::mem::size_of::<crate::stream::AttributeProjection>()
            <= ATTRIBUTE_PROJECTION_SLOT_BYTES as usize
    );
    let slots = u64::try_from(columns.len())
        .ok()
        .and_then(|count| count.checked_mul(ATTRIBUTE_PROJECTION_SLOT_BYTES))
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::MemoryBytes))?;
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
        let mut observer = super::QueryValueObserver::new(
            service,
            cpu_work_units,
            cpu_limit,
            cancellation.clone(),
            crate::QueryWorkStage::Operators,
        );
        let estimated =
            match record.projected_attribute_retained_bytes_observed(path, &mut observer) {
                Ok(value) => value,
                Err(failure) => {
                    memory.release(retained)?;
                    return Err(map_schema_traversal_failure(failure));
                },
            };
        let bytes = match estimated.map(u64::try_from).transpose() {
            Ok(value) => value.unwrap_or(0),
            Err(_) => {
                memory.release(retained)?;
                return Err(QueryFailure::budget_exhausted(
                    QueryBudgetDimension::MemoryBytes,
                ));
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
                return Err(QueryFailure::budget_exhausted(
                    QueryBudgetDimension::MemoryBytes,
                ));
            },
        };
        let mut observer = super::QueryValueObserver::new(
            service,
            cpu_work_units,
            cpu_limit,
            cancellation.clone(),
            crate::QueryWorkStage::Operators,
        );
        match record.project_attribute_observed(path, &mut observer) {
            Ok(value) => values.push(crate::stream::AttributeProjection::Attribute(value)),
            Err(failure) => {
                memory.release(retained)?;
                return Err(map_schema_traversal_failure(failure));
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
            QueryFailure::new(QueryFailureCode::ResourceExhausted)
        },
        _ => QueryFailure::new(QueryFailureCode::Internal),
    }
}

fn map_schema_traversal_failure(
    failure: positron_signals::SchemaTraversalFailure<QueryFailure>,
) -> QueryFailure {
    match failure {
        positron_signals::SchemaTraversalFailure::Schema(failure) => map_schema_failure(failure),
        positron_signals::SchemaTraversalFailure::Value(failure) => {
            super::map_observed_failure(failure)
        },
    }
}
