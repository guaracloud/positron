use positron_domain::time::{IngestTimeCandidate, QueryTime};

use super::transform::apply_transform;
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode, QueryRecord, TemporalAxis};

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
    let mut transformed = RetainedBytesGuard::new(memory);
    let result = (|| {
        let transformed_body = match state.plan.transform() {
            Some(transform) => record
                .body()
                .map(|body| {
                    let (value, bytes) =
                        apply_transform(transform, body, service, state, transformed.memory())?;
                    transformed.set(bytes);
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
                            &mut state.physical_cpu_work_units,
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
                            &mut state.physical_cpu_work_units,
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
                            &mut state.physical_cpu_work_units,
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
                        &mut state.physical_cpu_work_units,
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
                transformed.release()?;
                return Ok(None);
            }
        }
        let selected_columns = state
            .plan
            .aggregate()
            .map(crate::plan::AggregateSpec::group_by)
            .unwrap_or_else(|| state.plan.projection());
        let body_selected = selected_columns.contains(&crate::plan::ProjectionColumn::Body);
        let query_time_selected =
            selected_columns.contains(&crate::plan::ProjectionColumn::QueryTime);
        let event_time_selected =
            selected_columns.contains(&crate::plan::ProjectionColumn::EventTime);
        let ingest_time_selected =
            selected_columns.contains(&crate::plan::ProjectionColumn::IngestTime);
        let commit_position_selected =
            selected_columns.contains(&crate::plan::ProjectionColumn::CommitPosition);
        let cancellation = state.cancellation.clone();
        let cpu_limit = state.budget.cpu_work_units();
        let (attributes, attribute_retained_bytes) = project_attributes(
            record.stored(),
            selected_columns,
            service,
            &mut state.physical_cpu_work_units,
            cpu_limit,
            cancellation.clone(),
            transformed.memory(),
        )?;
        let (body, body_retained_bytes) = if body_selected {
            if let Some(value) = transformed_body {
                let retained = transformed.disarm();
                (Some(value), retained)
            } else {
                let retained = record.body_retained_bytes();
                (record.take_body(), retained)
            }
        } else {
            transformed.release()?;
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
    })();
    match result {
        Ok(result) => Ok(result),
        Err(failure) => match transformed.release() {
            Ok(()) => Err(failure),
            Err(cleanup) => Err(cleanup),
        },
    }
}

struct RetainedBytesGuard<'a> {
    memory: &'a mut crate::memory::QueryMemory,
    bytes: u64,
}

impl<'a> RetainedBytesGuard<'a> {
    fn new(memory: &'a mut crate::memory::QueryMemory) -> Self {
        Self { memory, bytes: 0 }
    }

    fn memory(&mut self) -> &mut crate::memory::QueryMemory {
        self.memory
    }

    fn set(&mut self, bytes: u64) {
        self.bytes = bytes;
    }

    fn release(&mut self) -> Result<(), QueryFailure> {
        let bytes = std::mem::take(&mut self.bytes);
        if bytes == 0 {
            return Ok(());
        }
        self.memory.release(bytes)
    }

    fn disarm(&mut self) -> u64 {
        std::mem::take(&mut self.bytes)
    }
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

#[cfg(test)]
mod tests {
    use super::{RetainedBytesGuard, map_schema_failure, map_schema_traversal_failure};
    use crate::QueryFailureCode;
    use crate::memory::QueryMemory;
    use positron_signals::{SchemaFailure, SchemaTraversalFailure};

    #[test]
    fn retained_bytes_guard_releases_explicitly_and_disarms_for_transfer() {
        let mut memory = QueryMemory::new(128);
        memory.acquire(32).expect("test admission fits");
        let mut guard = RetainedBytesGuard::new(&mut memory);
        guard.set(32);
        guard.release().expect("explicit release succeeds");
        guard.set(32);
        assert_eq!(guard.disarm(), 32);
        guard.release().expect("disarmed release is a no-op");
    }

    #[test]
    fn retained_bytes_guard_drop_releases_unclaimed_transfer() {
        let mut memory = QueryMemory::new(128);
        memory.acquire(32).expect("test admission fits");
        {
            let mut guard = RetainedBytesGuard::new(&mut memory);
            guard.set(32);
        }
        assert_eq!(memory.release(0), Ok(()));
    }

    #[test]
    fn retained_bytes_cleanup_failure_is_reported_without_drop_panic() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut memory = QueryMemory::new(0);
            {
                let mut guard = RetainedBytesGuard::new(&mut memory);
                guard.set(32);
            }
        }));
        assert!(result.is_ok());

        let mut memory = QueryMemory::new(0);
        let mut guard = RetainedBytesGuard::new(&mut memory);
        guard.set(32);
        assert_eq!(
            guard.release().expect_err("the debit is absent").code(),
            QueryFailureCode::Internal
        );
    }

    #[test]
    fn schema_failures_map_to_stable_query_classes() {
        assert_eq!(
            map_schema_failure(SchemaFailure::AllocationUnavailable).code(),
            QueryFailureCode::ResourceExhausted
        );
        assert_eq!(
            map_schema_failure(SchemaFailure::LimitExceeded).code(),
            QueryFailureCode::ResourceExhausted
        );
        assert_eq!(
            map_schema_failure(SchemaFailure::InvalidValue).code(),
            QueryFailureCode::Internal
        );
        assert_eq!(
            map_schema_traversal_failure(SchemaTraversalFailure::Schema(
                SchemaFailure::InvalidPath,
            ))
            .code(),
            QueryFailureCode::Internal
        );
    }
}
