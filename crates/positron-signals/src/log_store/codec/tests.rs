use super::*;
use crate::log_store::PolicyProvenance;
use crate::log_store::types::LogRecord;
use positron_domain::time::SourceTimeQuality;
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, CandidateAttributeValue,
};
use positron_kernel::{FixedLifecycleClockSource, LifecycleClock};

struct RecordLayout {
    bytes: Vec<u8>,
    stored: StoredLogRecord,
    observed_tag: usize,
    body_tag: usize,
    attribute: usize,
    occurrence_count: usize,
    occurrence_value: usize,
    policy: usize,
}

fn rich_record_layout() -> Result<RecordLayout, LogStoreFailure> {
    let profile = crate::log_store::types::value_profile();
    let record = LogRecord::checked_receiver_candidate(
        profile,
        Some(7),
        Some(8),
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "key".to_owned(),
            vec![CandidateAttributeValue::string("value".to_owned())],
        )],
        PolicyProvenance::new(1, [0x71; 32], vec!["tail-rule".to_owned()])
            .map_err(|_| LogStoreFailure::invalid_input())?,
    )?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(
        positron_domain::time::UnixNanoseconds::new(11),
    ));
    let stored = StoredLogRecord::new(
        record,
        clock
            .assign_ingest_time()
            .map_err(|_| LogStoreFailure::resource_exhausted())?,
    );
    let limits = CodecLimits::release_1()?;
    let mut bytes = Vec::new();
    encode_record(&mut bytes, &stored, limits.nesting_depth)?;

    let event_len = if stored.event_time().instant().is_some() {
        9
    } else {
        1
    };
    let observed_len = if stored.observed_time().is_some() {
        10
    } else {
        1
    };
    let metadata_len = metadata::encoded_length(stored.metadata())?;
    let body_tag = event_len + observed_len + metadata_len + 8;
    let body_len = stored
        .body()
        .map(|body| value::encoded_length(body, limits.nesting_depth))
        .transpose()?
        .unwrap_or(0);
    let attribute_count = body_tag + 1 + body_len;
    let attribute = attribute_count + 2;
    let occurrence_count = attribute + 1 + 1 + 4 + 3;
    let occurrence_value = occurrence_count + 2;
    let policy = occurrence_value
        + value::encoded_length(
            stored
                .attributes()
                .first()
                .ok_or_else(LogStoreFailure::malformed_block)?
                .occurrences()
                .occurrence(0)
                .ok_or_else(LogStoreFailure::malformed_block)?,
            limits.nesting_depth,
        )?;
    Ok(RecordLayout {
        bytes,
        stored,
        observed_tag: event_len,
        body_tag,
        attribute,
        occurrence_count,
        occurrence_value,
        policy,
    })
}

fn rejects(bytes: Vec<u8>) -> Result<(), LogStoreFailure> {
    let limits = CodecLimits::release_1()?;
    let mut input = Input::new(&bytes);
    record::validate_structure(&mut input, limits, METADATA_VERSION).map(|_| ())
}

#[test]
fn block_header_rejects_unknown_version_and_empty_blocks() -> Result<(), LogStoreFailure> {
    let tenant = TenantId::from_bytes([0x41; 16]).expect("tenant");
    let mut bytes = MAGIC.to_vec();
    put_u16(&mut bytes, VERSION + 1);
    assert!(decode_block_header_with(tenant, Input::new(&bytes)).is_err());
    assert!(encode_block(tenant, &[], 0).is_err());
    let layout = rich_record_layout()?;
    assert!(encode_block(tenant, &[layout.stored], 0).is_err());
    Ok(())
}

#[test]
fn structural_tail_validation_accepts_v2_and_legacy_records() -> Result<(), LogStoreFailure> {
    let layout = rich_record_layout()?;
    let limits = CodecLimits::release_1()?;
    let mut input = Input::new(&layout.bytes);
    record::validate_structure(&mut input, limits, METADATA_VERSION)?;
    assert!(input.is_empty());

    let mut legacy = Vec::new();
    legacy.push(2);
    legacy.push(0);
    legacy.extend_from_slice(&0_i64.to_be_bytes());
    legacy.push(0);
    legacy.extend_from_slice(&0_u16.to_be_bytes());
    legacy.extend_from_slice(&1_u64.to_be_bytes());
    legacy.extend_from_slice(&[0x71; 32]);
    legacy.extend_from_slice(&0_u16.to_be_bytes());
    let mut legacy_input = Input::new(&legacy);
    record::validate_structure(&mut legacy_input, limits, LEGACY_VERSION)?;
    assert!(legacy_input.is_empty());
    Ok(())
}

#[test]
fn structural_tail_validation_rejects_each_record_boundary() -> Result<(), LogStoreFailure> {
    let layout = rich_record_layout()?;
    let cases = [
        (0, vec![9]),
        (layout.observed_tag, vec![9]),
        (layout.body_tag, vec![9]),
        (layout.body_tag + 1, vec![9]),
        (layout.attribute, vec![9]),
        (layout.attribute + 1, vec![9]),
        (layout.attribute + 2, vec![0, 0, 0, 0]),
        (layout.occurrence_count, vec![0, 0]),
        (layout.occurrence_value, vec![9]),
        (layout.policy + 40, vec![0, 65]),
    ];
    for (offset, replacement) in cases {
        let mut bytes = layout.bytes.clone();
        let target = bytes
            .get_mut(offset..offset + replacement.len())
            .ok_or_else(LogStoreFailure::malformed_block)?;
        target.copy_from_slice(&replacement);
        assert!(rejects(bytes).is_err(), "offset {offset} must reject");
    }

    let mut metadata = layout.bytes.clone();
    let event_name_length = metadata
        .get_mut(10..14)
        .ok_or_else(LogStoreFailure::malformed_block)?;
    event_name_length.copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(rejects(metadata).is_err());
    Ok(())
}

#[test]
fn structural_tail_validation_rejects_truncation_and_trailing_bytes() -> Result<(), LogStoreFailure>
{
    let layout = rich_record_layout()?;
    let truncated = layout
        .bytes
        .get(..layout.bytes.len().saturating_sub(1))
        .ok_or_else(LogStoreFailure::malformed_block)?
        .to_vec();
    assert!(rejects(truncated).is_err());

    let mut trailing = layout.bytes.clone();
    trailing.push(0);
    let limits = CodecLimits::release_1()?;
    let mut input = Input::new(&trailing);
    record::validate_structure(&mut input, limits, METADATA_VERSION)?;
    assert!(!input.is_empty());
    Ok(())
}

#[test]
fn structural_tags_accept_the_full_time_quality_contract() -> Result<(), LogStoreFailure> {
    assert_eq!(record::decode_quality(5)?, SourceTimeQuality::Contradictory);
    assert_eq!(record::decode_quality(3)?, SourceTimeQuality::Zero);
    assert_eq!(quality_tag(SourceTimeQuality::Zero), 3);
    assert_eq!(quality_tag(SourceTimeQuality::Contradictory), 5);
    assert_eq!(
        record::decode_namespace(4, METADATA_VERSION)?,
        AttributeNamespace::Stream
    );
    Ok(())
}

#[test]
fn semantic_record_decode_rejects_empty_keys_and_invalid_values() -> Result<(), LogStoreFailure> {
    let layout = rich_record_layout()?;
    let limits = CodecLimits::release_1()?;

    let mut empty_key = layout.bytes.clone();
    let key_length = empty_key
        .get_mut(layout.attribute + 2..layout.attribute + 6)
        .ok_or_else(LogStoreFailure::malformed_block)?;
    key_length.copy_from_slice(&0_u32.to_be_bytes());
    assert!(record::decode(&mut Input::new(&empty_key), limits, METADATA_VERSION).is_err());

    let mut invalid_value = layout.bytes;
    *invalid_value
        .get_mut(layout.occurrence_value)
        .ok_or_else(LogStoreFailure::malformed_block)? = 9;
    assert!(record::decode(&mut Input::new(&invalid_value), limits, METADATA_VERSION).is_err());
    Ok(())
}
