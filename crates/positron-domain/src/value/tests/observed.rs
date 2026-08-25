use crate::value::{
    CandidateAttributeValue, CandidateKeyValue, NativeValueObserver, ObservedValueFailure,
    ValueLimitProfile,
};

#[derive(Default)]
struct CountingObserver {
    fail_at_structure: Option<usize>,
    fail_at_allocation: Option<usize>,
    allocation_limit: Option<usize>,
    structures: usize,
    payloads: usize,
    allocation_calls: usize,
    allocations: Vec<usize>,
    releases: Vec<usize>,
    live_bytes: usize,
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

    fn observe_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.allocation_calls = self.allocation_calls.saturating_add(1);
        if self.fail_at_allocation == Some(self.allocation_calls) {
            return Err("allocation admission failed");
        }
        let next = self.live_bytes.saturating_add(bytes);
        if self.allocation_limit.is_some_and(|limit| next > limit) {
            return Err("allocation budget exhausted");
        }
        self.live_bytes = next;
        self.allocations.push(bytes);
        Ok(())
    }

    fn release_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.live_bytes = self.live_bytes.saturating_sub(bytes);
        self.releases.push(bytes);
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
    assert_eq!(observer.allocations, vec![96, 128, 96]);
    assert_eq!(observer.live_bytes, 320);
}

#[test]
fn observed_validation_reports_string_capacity_not_only_length() {
    let mut text = String::with_capacity(128);
    text.push('7');
    let retained_capacity = text.capacity();
    let candidate = CandidateAttributeValue::string(text);
    let mut observer = CountingObserver::default();
    let facts = candidate
        .validate_log_body_observed_with_facts(
            ValueLimitProfile::release_1_system_maximum(),
            &mut observer,
        )
        .expect("bounded scalar string validates");

    assert_eq!(facts.value_size_bytes(), 1);
    assert_eq!(facts.retained_heap_bytes(), retained_capacity);
}

#[test]
fn observed_validation_releases_output_capacity_on_cancellation() {
    let candidate = CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
        "nested".to_owned(),
        CandidateAttributeValue::array(vec![CandidateAttributeValue::string("payload".to_owned())]),
    )]);
    let mut observer = CountingObserver {
        fail_at_structure: Some(4),
        ..CountingObserver::default()
    };
    assert_eq!(
        candidate.validate_log_body_observed(
            ValueLimitProfile::release_1_system_maximum(),
            &mut observer,
        ),
        Err(ObservedValueFailure::Observer("cancelled traversal"))
    );
    assert_eq!(observer.allocations, vec![96, 64]);
    assert_eq!(observer.releases, vec![64, 96]);
    assert_eq!(observer.live_bytes, 0);
}

#[test]
fn observed_validation_charges_candidate_and_output_at_exact_boundary() {
    let candidate = CandidateAttributeValue::array(vec![CandidateAttributeValue::null()]);
    let mut under = CountingObserver {
        allocation_limit: Some(159),
        ..CountingObserver::default()
    };
    under
        .observe_allocation(96)
        .expect("the parser candidate fits below the boundary");
    assert_eq!(
        candidate
            .validate_log_body_observed(ValueLimitProfile::release_1_system_maximum(), &mut under,),
        Err(ObservedValueFailure::Observer(
            "allocation budget exhausted"
        ))
    );
    assert_eq!(under.live_bytes, 96);
    under
        .release_allocation(96)
        .expect("candidate cleanup is balanced");
    assert_eq!(under.live_bytes, 0);

    let candidate = CandidateAttributeValue::array(vec![CandidateAttributeValue::null()]);
    let mut exact = CountingObserver {
        allocation_limit: Some(160),
        ..CountingObserver::default()
    };
    exact
        .observe_allocation(96)
        .expect("the parser candidate fits at the boundary");
    let facts = candidate
        .validate_log_body_observed_with_facts(
            ValueLimitProfile::release_1_system_maximum(),
            &mut exact,
        )
        .expect("candidate and canonical output fit exactly");
    assert_eq!(facts.retained_heap_bytes(), 64);
    assert_eq!(exact.live_bytes, 160);
    exact
        .release_allocation(64)
        .expect("canonical output cleanup is balanced");
    exact
        .release_allocation(96)
        .expect("candidate cleanup is balanced");
    assert_eq!(exact.live_bytes, 0);
}

#[test]
fn observed_validation_propagates_allocation_admission_failure() {
    let candidate = CandidateAttributeValue::array(vec![CandidateAttributeValue::null()]);
    let mut observer = CountingObserver {
        fail_at_allocation: Some(1),
        ..CountingObserver::default()
    };
    assert_eq!(
        candidate.validate_log_body_observed(
            ValueLimitProfile::release_1_system_maximum(),
            &mut observer,
        ),
        Err(ObservedValueFailure::Observer(
            "allocation admission failed"
        ))
    );
    assert!(observer.allocations.is_empty());
    assert!(observer.releases.is_empty());
    assert_eq!(observer.live_bytes, 0);
}

#[test]
fn observed_validation_releases_capacity_when_collection_value_limit_is_exceeded() {
    let candidate = CandidateAttributeValue::array(vec![
        CandidateAttributeValue::string("a".to_owned()),
        CandidateAttributeValue::string("b".to_owned()),
    ]);
    let mut observer = CountingObserver::default();
    assert!(
        candidate
            .validate_log_body_observed(
                super::profile_with_value_and_body_bytes(64, 1),
                &mut observer
            )
            .is_err()
    );
    assert_eq!(observer.allocations, vec![128]);
    assert_eq!(observer.releases, vec![128]);
    assert_eq!(observer.live_bytes, 0);
}

#[test]
fn observed_validation_reconciles_capacity_failures_without_leaking_admission() {
    let mut overflow = CountingObserver::default();
    overflow
        .observe_allocation(2)
        .expect("the synthetic admitted capacity fits");
    assert!(
        super::super::reconcile_output_capacity(
            &Vec::<u8>::with_capacity(2),
            usize::MAX,
            2,
            &mut overflow,
        )
        .is_err()
    );
    assert_eq!(overflow.releases, vec![2]);
    assert_eq!(overflow.live_bytes, 0);

    let mut additional_failure = CountingObserver {
        fail_at_allocation: Some(1),
        ..CountingObserver::default()
    };
    assert!(
        super::super::reconcile_output_capacity(
            &Vec::<u8>::with_capacity(1),
            1,
            0,
            &mut additional_failure,
        )
        .is_err()
    );
    assert_eq!(additional_failure.releases, vec![0]);
    assert_eq!(additional_failure.live_bytes, 0);
}
