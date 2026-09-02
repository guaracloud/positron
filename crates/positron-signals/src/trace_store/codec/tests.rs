use super::{
    BlockDecode, Input, MAX_BLOCK_BYTES, decode_kind, decode_namespace, decode_observation,
    decode_quality, decode_sampling, decoded_memory_bound, encode_block, kind_tag, namespace_index,
    namespace_tag, preflight_policy, put_slice, quality_tag, sampling_tag,
};
use crate::trace_store::{SamplingDecision, SpanKind, SpanObservation, StoredSpanObservation};
use crate::{ScanCancellation, ScanObservationFailureCode, ScanObserver};
use positron_domain::identity::TenantId;
use positron_domain::time::{EventTime, SourceTimeQuality};
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, CandidateAttributeValue, ValueLimitProfile,
};
use positron_kernel::{FixedLifecycleClockSource, LifecycleClock};

#[test]
fn codec_tags_round_trip_known_native_values() {
    for kind in [
        SpanKind::Unspecified,
        SpanKind::Internal,
        SpanKind::Server,
        SpanKind::Client,
        SpanKind::Producer,
        SpanKind::Consumer,
    ] {
        assert_eq!(decode_kind(kind_tag(kind)).expect("kind"), kind);
    }
    for sampling in [
        SamplingDecision::Unknown,
        SamplingDecision::NotSampled,
        SamplingDecision::Sampled,
    ] {
        assert_eq!(
            decode_sampling(sampling_tag(sampling)).expect("sampling"),
            sampling
        );
    }
    for quality in [
        SourceTimeQuality::Usable,
        SourceTimeQuality::Missing,
        SourceTimeQuality::Zero,
        SourceTimeQuality::Outlier,
        SourceTimeQuality::Contradictory,
    ] {
        assert_eq!(
            decode_quality(quality_tag(quality)).expect("quality"),
            quality
        );
    }
    for namespace in [
        AttributeNamespace::Resource,
        AttributeNamespace::InstrumentationScope,
        AttributeNamespace::Record,
    ] {
        assert_eq!(
            decode_namespace(namespace_tag(namespace).expect("namespace")).expect("namespace"),
            namespace
        );
    }
    assert!(namespace_tag(AttributeNamespace::Stream).is_err());
    assert!(decode_namespace(4).is_err());
}

#[test]
fn encoder_rejects_empty_and_overlarge_blocks_before_allocation() {
    let tenant = TenantId::from_bytes([0x41; 16]).expect("tenant");
    let empty = encode_block(tenant, &[]).expect_err("empty blocks are not native blocks");
    assert_eq!(empty.code(), crate::TraceStoreFailureCode::LimitExceeded);
    let observation = SpanObservation::checked_native(
        [0x71; 16],
        [0x72; 8],
        None,
        "encoded".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x70; 32], Vec::new())
            .expect("policy provenance"),
    )
    .expect("observation");
    let stored = StoredSpanObservation::new(
        observation,
        LifecycleClock::new(FixedLifecycleClockSource::new(
            positron_domain::time::UnixNanoseconds::new(1),
        ))
        .assign_ingest_time()
        .expect("ingest time"),
    );
    let records = vec![stored; super::MAX_RECORDS + 1];
    let overlarge =
        encode_block(tenant, &records).expect_err("overlarge blocks are rejected before encoding");
    assert_eq!(
        overlarge.code(),
        crate::TraceStoreFailureCode::LimitExceeded
    );
}

struct NeverCancelled;

impl ScanCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct NeverObserved;

impl ScanObserver for NeverObserved {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

struct DecodedRecordsExhausted;

impl ScanObserver for DecodedRecordsExhausted {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }

    fn observe_decoded_records(&self, _records: u64) -> Result<(), ScanObservationFailureCode> {
        Err(ScanObservationFailureCode::DecodedRecordsExhausted)
    }
}

struct AlwaysCancelled;

impl ScanCancellation for AlwaysCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

#[test]
fn decoder_defensive_paths_remain_typed_after_admission_preflight() {
    let tenant = TenantId::from_bytes([0x51; 16]).expect("tenant");
    let attribute = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "key".to_owned(),
        vec![CandidateAttributeValue::boolean(true)],
    )
    .validate(ValueLimitProfile::release_1_system_maximum())
    .expect("attribute");
    let observation = SpanObservation::checked_native(
        [0x61; 16],
        [0x62; 8],
        None,
        "valid".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        vec![attribute],
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [1; 32], Vec::new()).expect("policy provenance"),
    )
    .expect("observation");
    let stored = StoredSpanObservation::new(
        observation,
        LifecycleClock::new(FixedLifecycleClockSource::new(
            positron_domain::time::UnixNanoseconds::new(1),
        ))
        .assign_ingest_time()
        .expect("ingest time"),
    );
    let valid = encode_block(tenant, &[stored]).expect("encoded block");
    let observer = NeverObserved;
    let mut wrong_magic = valid.clone();
    wrong_magic[0] = 0;
    assert_eq!(
        BlockDecode::observed(tenant, &wrong_magic, &NeverCancelled, &observer)
            .err()
            .expect("wrong magic")
            .code(),
        crate::TraceStoreFailureCode::MalformedBlock
    );
    let mut wrong_version = valid.clone();
    wrong_version[9] = 2;
    assert_eq!(
        BlockDecode::observed(tenant, &wrong_version, &NeverCancelled, &observer)
            .err()
            .expect("wrong version")
            .code(),
        crate::TraceStoreFailureCode::MalformedBlock
    );
    let mut wrong_tenant = valid.clone();
    wrong_tenant[10] ^= 1;
    assert_eq!(
        BlockDecode::observed(tenant, &wrong_tenant, &NeverCancelled, &observer)
            .err()
            .expect("wrong tenant")
            .code(),
        crate::TraceStoreFailureCode::PhysicalScopeMismatch
    );
    let mut zero_records = valid.clone();
    zero_records[26..28].copy_from_slice(&0_u16.to_be_bytes());
    assert_eq!(
        BlockDecode::observed(tenant, &zero_records, &NeverCancelled, &observer)
            .err()
            .expect("zero records")
            .code(),
        crate::TraceStoreFailureCode::MalformedBlock
    );

    let record = &valid[28..];
    for (offset, value) in [(24, 9_u8), (50, 9_u8), (51, 9_u8)] {
        let mut malformed = record.to_vec();
        malformed[offset] = value;
        let failure = decode_observation(&mut Input::cancelable(&malformed, &NeverCancelled))
            .expect_err("defensive record shape rejection");
        assert_eq!(failure.code(), crate::TraceStoreFailureCode::MalformedBlock);
    }
    let mut zero_occurrences = record.to_vec();
    zero_occurrences[48..50].copy_from_slice(&0_u16.to_be_bytes());
    let failure = decode_observation(&mut Input::cancelable(&zero_occurrences, &NeverCancelled))
        .expect_err("empty occurrence set");
    assert_eq!(failure.code(), crate::TraceStoreFailureCode::MalformedBlock);

    let failure = Input::cancelable(&[0], &AlwaysCancelled)
        .u8()
        .expect_err("cancellation must be observed by raw input");
    assert_eq!(failure.code(), crate::TraceStoreFailureCode::Cancelled);
    let failure = super::check_cancel(&AlwaysCancelled)
        .expect_err("cancellation must be observed before decoder work");
    assert_eq!(failure.code(), crate::TraceStoreFailureCode::Cancelled);
    let failure = Input::observed(&[], &NeverCancelled, &DecodedRecordsExhausted)
        .observe_decoded_record()
        .expect_err("decoded record observer failures must remain typed");
    assert_eq!(failure.code(), crate::TraceStoreFailureCode::LimitExceeded);
    Input::observed(&[], &NeverCancelled, &DecodedRecordsExhausted)
        .observe_component()
        .expect("work observer accepts the component");
    assert_eq!(
        namespace_index(AttributeNamespace::Resource).expect("namespace"),
        0
    );
    assert_eq!(
        namespace_index(AttributeNamespace::InstrumentationScope).expect("namespace"),
        1
    );
    assert_eq!(
        namespace_index(AttributeNamespace::Record).expect("namespace"),
        2
    );
    assert!(namespace_index(AttributeNamespace::Stream).is_err());
    let mut empty_rule = Vec::new();
    empty_rule.extend_from_slice(&1_u64.to_be_bytes());
    empty_rule.extend_from_slice(&[1; 32]);
    empty_rule.extend_from_slice(&1_u16.to_be_bytes());
    empty_rule.extend_from_slice(&0_u32.to_be_bytes());
    let failure = preflight_policy(&mut Input::cancelable(&empty_rule, &NeverCancelled), &mut 0)
        .expect_err("empty policy rule must be malformed");
    assert_eq!(failure.code(), crate::TraceStoreFailureCode::MalformedBlock);
    let mut full = vec![0_u8; MAX_BLOCK_BYTES];
    let failure = put_slice(&mut full, &[0]).expect_err("encoded block bound must be enforced");
    assert_eq!(failure.code(), crate::TraceStoreFailureCode::LimitExceeded);
}

#[test]
fn admission_preflight_rejects_oversized_native_bytes_and_decoded_payloads() {
    let tenant = TenantId::from_bytes([0x51; 16]).expect("tenant");
    let profile = ValueLimitProfile::release_1_system_maximum();
    let bytes_attribute = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "payload".to_owned(),
        vec![CandidateAttributeValue::bytes(vec![1, 2, 3])],
    )
    .validate(profile)
    .expect("bytes attribute");
    let observation = SpanObservation::checked_native(
        [0x61; 16],
        [0x62; 8],
        None,
        "bytes".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        vec![bytes_attribute],
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [1; 32], Vec::new()).expect("policy provenance"),
    )
    .expect("native observation");
    let stored = StoredSpanObservation::new(
        observation,
        LifecycleClock::new(FixedLifecycleClockSource::new(
            positron_domain::time::UnixNanoseconds::new(1),
        ))
        .assign_ingest_time()
        .expect("ingest time"),
    );
    let mut oversized_bytes = encode_block(tenant, &[stored]).expect("encoded block");
    oversized_bytes[83..87].copy_from_slice(&65_537_u32.to_be_bytes());
    let failure = decoded_memory_bound(tenant, &oversized_bytes, &NeverCancelled, &NeverObserved)
        .expect_err("native bytes beyond profile must be rejected pre-decode");
    assert_eq!(failure.code(), crate::TraceStoreFailureCode::MalformedBlock);

    let mut oversized_decoded = Vec::new();
    oversized_decoded.extend_from_slice(b"PTRCBL01");
    oversized_decoded.extend_from_slice(&1_u16.to_be_bytes());
    oversized_decoded.extend_from_slice(&tenant.to_bytes());
    oversized_decoded.extend_from_slice(&1_u16.to_be_bytes());
    oversized_decoded.extend_from_slice(&[0x71; 16]);
    oversized_decoded.extend_from_slice(&[0x72; 8]);
    oversized_decoded.push(0);
    oversized_decoded.push(0);
    oversized_decoded.push(0);
    oversized_decoded.push(2);
    oversized_decoded.push(2);
    oversized_decoded.extend_from_slice(&1_u32.to_be_bytes());
    oversized_decoded.push(b'x');
    oversized_decoded.extend_from_slice(&1_u16.to_be_bytes());
    oversized_decoded.push(1);
    oversized_decoded.extend_from_slice(&1_u32.to_be_bytes());
    oversized_decoded.push(b'k');
    oversized_decoded.extend_from_slice(&17_u16.to_be_bytes());
    for _ in 0..17 {
        oversized_decoded.push(4);
        oversized_decoded.extend_from_slice(&65_536_u32.to_be_bytes());
        oversized_decoded.extend(std::iter::repeat_n(b'x', 65_536));
    }
    oversized_decoded.extend_from_slice(&1_u64.to_be_bytes());
    oversized_decoded.extend_from_slice(&[1; 32]);
    oversized_decoded.extend_from_slice(&0_u16.to_be_bytes());
    oversized_decoded.extend_from_slice(&1_i64.to_be_bytes());
    let failure = decoded_memory_bound(tenant, &oversized_decoded, &NeverCancelled, &NeverObserved)
        .expect_err("decoded payload growth must be rejected before allocation");
    assert_eq!(failure.code(), crate::TraceStoreFailureCode::MalformedBlock);
}
