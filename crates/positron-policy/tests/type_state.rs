use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};

#[test]
fn only_policy_evaluation_produces_a_durable_record_with_provenance() {
    let candidate = NativeLogCandidate::new(
        Some(42),
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![NativeLogAttribute::new(
            AttributeNamespace::Record,
            "key".to_owned(),
            vec![CandidateAttributeValue::string("value".to_owned())],
        )],
        LogMetadata::empty(),
    );
    let policy = IngestPolicy::preserving(7).expect("canonical preserving policy");
    let PolicyEvaluation::Accepted(record) = policy
        .evaluate(candidate, PolicyReceiver::OtlpGrpc)
        .expect("bounded evaluation")
    else {
        panic!("preserving policy rejected the record");
    };

    assert_eq!(record.policy_provenance().generation(), 7);
    assert_eq!(record.policy_provenance().applied_rules(), &[] as &[String]);
    assert_ne!(record.policy_provenance().digest(), [0; 32]);
}
