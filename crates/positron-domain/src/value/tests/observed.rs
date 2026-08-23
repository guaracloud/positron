use crate::value::{
    CandidateAttributeValue, CandidateKeyValue, NativeValueObserver, ObservedValueFailure,
    ValueLimitProfile,
};

#[derive(Default)]
struct CountingObserver {
    fail_at_structure: Option<usize>,
    structures: usize,
    payloads: usize,
}

impl NativeValueObserver for CountingObserver {
    type Error = &'static str;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        self.structures = self.structures.saturating_add(1);
        if self.fail_at_structure == Some(self.structures) {
            return Err("cancelled traversal");
        }
        Ok(())
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
        self.payloads = self.payloads.saturating_add(1);
        Ok(())
    }
}

#[test]
fn observed_log_body_validation_reports_recursive_work_and_cancellation() {
    let candidate = CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
        "nested".to_owned(),
        CandidateAttributeValue::array(vec![CandidateAttributeValue::string("payload".to_owned())]),
    )]);
    let mut observer = CountingObserver {
        fail_at_structure: Some(2),
        ..CountingObserver::default()
    };
    assert_eq!(
        candidate.validate_log_body_observed(
            ValueLimitProfile::release_1_system_maximum(),
            &mut observer,
        ),
        Err(ObservedValueFailure::Observer("cancelled traversal"))
    );
}

#[test]
fn observed_log_body_validation_returns_profile_transfer_facts_from_one_traversal() {
    let candidate = CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
        "nested".to_owned(),
        CandidateAttributeValue::array(vec![
            CandidateAttributeValue::string("x".to_owned()),
            CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                "leaf".to_owned(),
                CandidateAttributeValue::string("yz".to_owned()),
            )]),
        ]),
    )]);
    let mut observer = CountingObserver::default();
    let facts = candidate
        .validate_log_body_observed_with_facts(
            ValueLimitProfile::release_1_system_maximum(),
            &mut observer,
        )
        .expect("nested profile transfer is bounded");

    assert_eq!(facts.value_size_bytes(), 3);
    assert_eq!(facts.retained_heap_bytes(), 333);
    assert_eq!(
        facts.value().kind(),
        crate::value::AttributeValueKind::KeyValueList
    );
    assert_eq!(observer.structures, 7);
    assert_eq!(observer.payloads, 4);
}
