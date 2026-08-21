use crate::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, AttributeValueKind, ByteLimit,
    CandidateAttributeValue, CandidateKeyValue, CollectionLimit, DynamicValueLimits,
    NativeValueObserver, NestingLimit, ObservedValueFailure, RecordLimits, RequestLimits,
    ValueLimitProfile, ValueLimitProfileCandidate, ValueLimitSet,
};

mod validation;

fn profile() -> ValueLimitProfile {
    profile_with_value_and_body_bytes(64, 64)
}

fn profile_with_value_and_body_bytes(
    individual_value_bytes: u32,
    log_body_bytes: u32,
) -> ValueLimitProfile {
    let bytes = ByteLimit::new(64).expect("fixture byte limit is nonzero");
    let entries = CollectionLimit::new(8).expect("fixture collection limit is nonzero");
    let request = RequestLimits::new(bytes, bytes, entries, entries);
    let record = RecordLimits::new(
        bytes,
        bytes,
        ByteLimit::new(log_body_bytes).expect("fixture body limit is nonzero"),
    );
    let dynamic = DynamicValueLimits::new(
        ByteLimit::new(individual_value_bytes).expect("fixture value limit is nonzero"),
        entries,
        bytes,
        NestingLimit::new(4).expect("fixture nesting limit is nonzero"),
        entries,
        entries,
    );
    ValueLimitProfileCandidate::new(ValueLimitSet::new(request, record, dynamic), None)
        .validate()
        .expect("fixture tenant limits do not raise system ceilings")
}
