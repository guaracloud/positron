use crate::{LogicalPlan, QueryFailure, QueryFailureCode, QueryRecord};

#[cfg(test)]
use super::failure::map_domain_value_failure;
use super::vocabulary::{query_time_provenance_tag, source_time_quality_tag};

const DIGEST_STATE_BYTES: u64 = 256;

pub(crate) struct BatchDigestInput<'a, O> {
    pub(crate) prior: [u8; 32],
    pub(crate) sequence: u64,
    pub(crate) plan: &'a LogicalPlan,
    pub(crate) records: &'a [QueryRecord],
    pub(crate) cancellation: &'a crate::QueryCancellation,
    pub(crate) observer: &'a mut O,
}

pub(crate) fn batch_digest(
    protector: &positron_kernel::ControlTokenProtector<'_>,
    input: BatchDigestInput<
        '_,
        impl positron_domain::value::NativeValueObserver<Error = QueryFailure>,
    >,
    memory: &mut crate::memory::QueryMemory,
) -> Result<[u8; 32], QueryFailure> {
    memory.acquire(DIGEST_STATE_BYTES)?;
    let result = batch_digest_with_acquired_state(
        protector,
        input.prior,
        input.sequence,
        input.plan,
        input.records,
        input.cancellation,
        input.observer,
    );
    memory.release(DIGEST_STATE_BYTES)?;
    result
}

pub(crate) fn result_digest(
    protector: &positron_kernel::ControlTokenProtector<'_>,
    plan: &LogicalPlan,
    record: &QueryRecord,
    cancellation: &crate::QueryCancellation,
    observer: &mut impl positron_domain::value::NativeValueObserver<Error = QueryFailure>,
    memory: &mut crate::memory::QueryMemory,
) -> Result<[u8; 32], QueryFailure> {
    batch_digest(
        protector,
        BatchDigestInput {
            prior: [0; 32],
            sequence: 0,
            plan,
            records: std::slice::from_ref(record),
            cancellation,
            observer,
        },
        memory,
    )
}

fn batch_digest_with_acquired_state(
    protector: &positron_kernel::ControlTokenProtector<'_>,
    prior: [u8; 32],
    sequence: u64,
    plan: &LogicalPlan,
    records: &[QueryRecord],
    cancellation: &crate::QueryCancellation,
    observer: &mut impl positron_domain::value::NativeValueObserver<Error = QueryFailure>,
) -> Result<[u8; 32], QueryFailure> {
    check_digest_cancellation(cancellation)?;
    let mut digest = protector
        .query_result_digest()
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    digest.update(&prior);
    digest.update(&sequence.to_be_bytes());
    update_result_contract_digest(&mut digest, plan, cancellation)?;
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
            update_native_value_digest(&mut digest, body, observer)?;
        }
        digest.update(&[u8::from(record.query_time_selected())]);
        if record.query_time_selected() {
            let query_time = record
                .query_time_value()
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            digest.update(&query_time.instant().value().to_be_bytes());
            digest.update(&[query_time_provenance_tag(query_time.provenance())]);
        }
        digest.update(&[u8::from(record.event_time_selected())]);
        if record.event_time_selected() {
            let event_time = record
                .event_time_value()
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            digest.update(&[u8::from(event_time.instant().is_some())]);
            if let Some(event_time) = event_time.instant() {
                digest.update(&event_time.value().to_be_bytes());
            }
            digest.update(&[source_time_quality_tag(event_time.quality())]);
        }
        digest.update(&[u8::from(record.ingest_time_selected())]);
        if record.ingest_time_selected() {
            let ingest_time = record
                .ingest_time_value()
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            digest.update(&ingest_time.instant().value().to_be_bytes());
        }
        digest.update(&[u8::from(record.count().is_some())]);
        if let Some(count) = record.count() {
            digest.update(&count.to_be_bytes());
        }
        for projected in record.attribute_projections() {
            let crate::stream::AttributeProjection::Attribute(value) = projected else {
                continue;
            };
            digest.update(&[u8::from(value.is_some())]);
            if let Some(value) = value {
                update_occurrence_set_digest(&mut digest, value, observer)?;
            }
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
) -> Result<(), QueryFailure> {
    check_digest_cancellation(cancellation)?;
    encode_result_contract(digest, plan, cancellation)
}

fn update_native_value_digest(
    digest: &mut positron_kernel::QueryResultDigest,
    value: &positron_domain::value::ValidatedAttributeValue,
    observer: &mut impl positron_domain::value::NativeValueObserver<Error = QueryFailure>,
) -> Result<(), QueryFailure> {
    value
        .visit_canonical_encoding_observed(observer, &mut |chunk| digest.update(chunk))
        .map_err(super::map_observed_failure)
}

fn update_occurrence_set_digest(
    digest: &mut positron_kernel::QueryResultDigest,
    value: &positron_domain::value::AttributeOccurrenceSet,
    observer: &mut impl positron_domain::value::NativeValueObserver<Error = QueryFailure>,
) -> Result<(), QueryFailure> {
    value
        .visit_canonical_encoding_observed(observer, &mut |chunk| digest.update(chunk))
        .map_err(super::map_observed_failure)
}

fn check_digest_cancellation(cancellation: &crate::QueryCancellation) -> Result<(), QueryFailure> {
    if cancellation.is_cancelled() {
        Err(QueryFailure::new(QueryFailureCode::Cancelled))
    } else {
        Ok(())
    }
}

fn encode_result_contract(
    digest: &mut positron_kernel::QueryResultDigest,
    plan: &LogicalPlan,
    cancellation: &crate::QueryCancellation,
) -> Result<(), QueryFailure> {
    let schema = plan
        .aggregate()
        .map(crate::plan::AggregateSpec::group_by)
        .unwrap_or_else(|| plan.projection());
    digest.update(
        &u64::try_from(schema.len() + usize::from(plan.aggregate().is_some()))
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
            .to_be_bytes(),
    );
    for column in schema {
        update_projection_contract(digest, column, cancellation)?;
    }
    if plan.aggregate().is_some() {
        digest.update(&[
            3,
            result_value_type_tag(crate::ResultValueType::UnsignedInteger),
            0,
        ]);
        digest.update(
            &u64::try_from(schema.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
                .to_be_bytes(),
        );
        for column in schema {
            update_projection_contract(digest, column, cancellation)?;
            digest.update(&[order_direction_tag(crate::plan::OrderDirection::Ascending)]);
        }
    } else {
        digest.update(&3_u64.to_be_bytes());
        digest.update(&[
            match plan.temporal_axis() {
                crate::TemporalAxis::QueryTime => 4,
                crate::TemporalAxis::EventTime => 5,
                crate::TemporalAxis::IngestTime => 7,
            },
            result_value_type_tag(match plan.temporal_axis() {
                crate::TemporalAxis::QueryTime => crate::ResultValueType::QueryTime,
                crate::TemporalAxis::EventTime => crate::ResultValueType::EventTime,
                crate::TemporalAxis::IngestTime => crate::ResultValueType::IngestTime,
            }),
            order_direction_tag(plan.ordering().primary_direction()),
        ]);
        digest.update(&[
            2,
            result_value_type_tag(crate::ResultValueType::CommitPosition),
            order_direction_tag(plan.ordering().commit_direction()),
        ]);
        digest.update(&[
            6,
            result_value_type_tag(crate::ResultValueType::RecordOrdinal),
            order_direction_tag(plan.ordering().commit_direction()),
        ]);
    }
    Ok(())
}

fn update_projection_contract(
    digest: &mut positron_kernel::QueryResultDigest,
    column: &crate::plan::ProjectionColumn,
    cancellation: &crate::QueryCancellation,
) -> Result<(), QueryFailure> {
    digest.update(&[
        projection_column_tag(column),
        result_value_type_tag(crate::stream::column_type(column)),
        u8::from(matches!(
            column,
            crate::plan::ProjectionColumn::Body | crate::plan::ProjectionColumn::Attribute(_)
        )),
    ]);
    if let crate::plan::ProjectionColumn::Attribute(path) = column {
        digest.update(&[match path.namespace() {
            positron_domain::value::AttributeNamespace::Stream => 0,
            positron_domain::value::AttributeNamespace::Resource => 1,
            positron_domain::value::AttributeNamespace::InstrumentationScope => 2,
            positron_domain::value::AttributeNamespace::Record => 3,
        }]);
        digest.update(
            &u64::try_from(path.segments().len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
                .to_be_bytes(),
        );
        for segment in path.segments() {
            check_digest_cancellation(cancellation)?;
            digest.update(
                &u64::try_from(segment.len())
                    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
                    .to_be_bytes(),
            );
            digest.update(segment.as_bytes());
        }
    }
    Ok(())
}

const fn projection_column_tag(column: &crate::plan::ProjectionColumn) -> u8 {
    match column {
        crate::plan::ProjectionColumn::Body => 0,
        crate::plan::ProjectionColumn::QueryTime => 1,
        crate::plan::ProjectionColumn::EventTime => 3,
        crate::plan::ProjectionColumn::IngestTime => 4,
        crate::plan::ProjectionColumn::CommitPosition => 2,
        crate::plan::ProjectionColumn::Attribute(_) => 8,
    }
}

const fn result_value_type_tag(value_type: crate::ResultValueType) -> u8 {
    match value_type {
        crate::ResultValueType::NativeValue => 0,
        crate::ResultValueType::UnixNanoseconds => 1,
        crate::ResultValueType::OptionalUnixNanoseconds => 5,
        crate::ResultValueType::QueryTime => 6,
        crate::ResultValueType::EventTime => 7,
        crate::ResultValueType::IngestTime => 8,
        crate::ResultValueType::CommitPosition => 2,
        crate::ResultValueType::RecordOrdinal => 3,
        crate::ResultValueType::UnsignedInteger => 4,
        crate::ResultValueType::AttributeOccurrenceSet => 9,
    }
}

const fn order_direction_tag(direction: crate::plan::OrderDirection) -> u8 {
    match direction {
        crate::plan::OrderDirection::Ascending => 0,
        crate::plan::OrderDirection::Descending => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        check_digest_cancellation, map_domain_value_failure, query_time_provenance_tag,
        result_value_type_tag, source_time_quality_tag,
    };
    use crate::QueryFailureCode;

    #[test]
    fn typed_digest_vocabulary_and_domain_failures_remain_stable() {
        use positron_domain::time::{QueryTimeProvenance, SourceTimeQuality};
        use positron_domain::value::{CandidateAttributeValue, ValueLimitProfile};

        assert_eq!(
            result_value_type_tag(crate::ResultValueType::UnixNanoseconds),
            1
        );
        assert_eq!(
            result_value_type_tag(crate::ResultValueType::OptionalUnixNanoseconds),
            5
        );
        assert_eq!(query_time_provenance_tag(QueryTimeProvenance::Observed), 1);
        assert_eq!(source_time_quality_tag(SourceTimeQuality::Outlier), 3);
        assert_eq!(source_time_quality_tag(SourceTimeQuality::Contradictory), 4);

        let cancellation = crate::QueryCancellation::new();
        cancellation.cancel();
        assert_eq!(
            check_digest_cancellation(&cancellation)
                .expect_err("cancelled digest work must fail")
                .code(),
            QueryFailureCode::Cancelled
        );

        let domain_failure = CandidateAttributeValue::array(
            (0..1_025)
                .map(|_| CandidateAttributeValue::null())
                .collect(),
        )
        .validate_log_body(ValueLimitProfile::release_1_system_maximum())
        .expect_err("oversized native values must fail domain validation");
        assert_eq!(
            map_domain_value_failure(domain_failure).code(),
            QueryFailureCode::Internal
        );
    }
}
