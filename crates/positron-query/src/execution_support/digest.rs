use crate::{LogicalPlan, QueryFailure, QueryFailureCode, QueryRecord};

use super::failure::map_domain_value_failure;
use super::vocabulary::{query_time_provenance_tag, source_time_quality_tag};

const DIGEST_STATE_BYTES: u64 = 256;
const DIGEST_CONTRACT_BYTES: usize = 128;
const DIGEST_CHUNK_BYTES: usize = 1_024;

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
            crate::TemporalAxis::IngestTime => 7,
        });
        encoding.push(result_value_type_tag(match plan.temporal_axis() {
            crate::TemporalAxis::QueryTime => crate::ResultValueType::QueryTime,
            crate::TemporalAxis::EventTime => crate::ResultValueType::EventTime,
            crate::TemporalAxis::IngestTime => crate::ResultValueType::IngestTime,
        }));
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
        crate::plan::ProjectionColumn::IngestTime => 4,
        crate::plan::ProjectionColumn::CommitPosition => 2,
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
