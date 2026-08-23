use positron_domain::time::{IngestTimeCandidate, QueryTime};

use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode, QueryRecord, TemporalAxis};

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

impl positron_domain::value::NativeValueObserver for TransformWorkObserver<'_, '_, '_, '_> {
    type Error = QueryFailure;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        crate::transform::TransformObserver::step(self)
    }

    fn observe_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        for _chunk in payload.chunks(positron_domain::value::NATIVE_VALUE_PAYLOAD_CHUNK_BYTES) {
            crate::transform::TransformObserver::step(self)?;
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
    let observed = record.observed_time();
    let ingest_time = record.ingest_time();
    let query_time = QueryTime::for_log(
        &record.event_time(),
        observed.as_ref(),
        IngestTimeCandidate::new(ingest_time.instant()),
    );
    let event_time = record.event_time();
    let temporal_axis = state.plan.temporal_axis();
    let temporal_range = state.plan.temporal_range();
    let Some(ordering_time) = (match temporal_axis {
        TemporalAxis::QueryTime => Some(query_time.instant()),
        TemporalAxis::EventTime => event_time.instant(),
        TemporalAxis::IngestTime => Some(ingest_time.instant()),
    }) else {
        return Ok(None);
    };
    if !temporal_range.contains(ordering_time) {
        return Ok(None);
    }
    let mut transformed_retained_bytes = None;
    let transformed_body = match state.plan.transform() {
        Some(transform) => record
            .body()
            .map(|body| {
                let (value, bytes) = apply_transform(transform, body, service, state, memory)?;
                transformed_retained_bytes = Some(bytes);
                Ok(value)
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
            if let Some(bytes) = transformed_retained_bytes {
                memory.release(bytes)?;
            }
            return Ok(None);
        }
    }
    let selected_columns = state
        .plan
        .aggregate()
        .map(crate::plan::AggregateSpec::group_by)
        .unwrap_or_else(|| state.plan.projection())
        .to_vec();
    let body_selected = selected_columns.contains(&crate::plan::ProjectionColumn::Body);
    let query_time_selected = selected_columns.contains(&crate::plan::ProjectionColumn::QueryTime);
    let event_time_selected = selected_columns.contains(&crate::plan::ProjectionColumn::EventTime);
    let ingest_time_selected =
        selected_columns.contains(&crate::plan::ProjectionColumn::IngestTime);
    let commit_position_selected =
        selected_columns.contains(&crate::plan::ProjectionColumn::CommitPosition);
    let cancellation = state.cancellation.clone();
    let cpu_limit = state.budget.cpu_work_units();
    let (attributes, attribute_retained_bytes) = match project_attributes(
        record.stored(),
        &selected_columns,
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

fn apply_transform(
    transform: crate::transform::BodyTransform,
    body: &positron_domain::value::ValidatedAttributeValue,
    service: &crate::QueryService<'_, '_, '_>,
    state: &mut crate::cursor::CursorState,
    memory: &mut crate::memory::QueryMemory,
) -> Result<(positron_domain::value::ValidatedAttributeValue, u64), QueryFailure> {
    let scratch = transform.scratch_memory_bytes(body)?;
    memory.acquire(scratch)?;
    let transformed = {
        let mut observer = TransformWorkObserver { service, state };
        transform.apply(body, &mut observer)
    };
    let value = match transformed {
        Ok(value) => value,
        Err(failure) => {
            memory.release(scratch)?;
            return Err(failure);
        },
    };
    let retained = {
        let mut observer = TransformWorkObserver { service, state };
        transformed_body_retained_bytes(&value, &mut observer)
    };
    let bytes = match retained {
        Ok(bytes) => bytes,
        Err(failure) => {
            memory.release(scratch)?;
            return Err(failure);
        },
    };
    if bytes >= scratch {
        if let Err(failure) = memory.acquire(bytes - scratch) {
            memory.release(scratch)?;
            return Err(failure);
        }
    } else {
        memory.release(scratch - bytes)?;
    }
    Ok((value, bytes))
}

fn transformed_body_retained_bytes(
    value: &positron_domain::value::ValidatedAttributeValue,
    observer: &mut impl positron_domain::value::NativeValueObserver<Error = QueryFailure>,
) -> Result<u64, QueryFailure> {
    value
        .retained_heap_bytes_observed(observer)
        .map_err(super::map_observed_failure)
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
