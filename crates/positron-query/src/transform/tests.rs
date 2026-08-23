use std::cell::Cell;

use super::*;

struct Unobserved;

#[derive(Default)]
struct MemoryProbe {
    reserved: u64,
    released: u64,
}

impl TransformObserver for MemoryProbe {
    fn step(&mut self) -> Result<(), QueryFailure> {
        Ok(())
    }

    fn reserve_memory(&mut self, bytes: u64) -> Result<(), QueryFailure> {
        self.reserved = self
            .reserved
            .checked_add(bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        Ok(())
    }

    fn release_memory(&mut self, bytes: u64) -> Result<(), QueryFailure> {
        self.released = self
            .released
            .checked_add(bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        Ok(())
    }
}

impl TransformObserver for Unobserved {
    fn step(&mut self) -> Result<(), QueryFailure> {
        Ok(())
    }
}

#[test]
fn direct_transforms_use_default_memory_hooks_and_return_transfer_facts() {
    let source = CandidateAttributeValue::string("{\"field\":\"value\"}".to_owned())
        .validate_log_body(ValueLimitProfile::release_1_system_maximum())
        .expect("bounded JSON source");
    let mut observer = Unobserved;
    let facts = BodyTransform::Json
        .apply_with_facts(&source, &mut observer)
        .expect("JSON transform succeeds");
    assert_eq!(facts.value_size_bytes(), 5);
    assert_eq!(
        facts.value().kind(),
        positron_domain::value::AttributeValueKind::KeyValueList
    );

    observer
        .reserve_memory(4)
        .expect("default memory admission");
    observer.release_memory(4).expect("default memory release");
    let cast = BodyTransform::Cast(CastTarget::String)
        .apply_with_facts(
            &CandidateAttributeValue::signed_integer(7)
                .validate_attribute(ValueLimitProfile::release_1_system_maximum())
                .expect("bounded integer"),
            &mut observer,
        )
        .expect("scalar cast succeeds");
    assert_eq!(cast.value().as_str(), Some("7"));
}

#[test]
fn json_validation_admits_output_capacity_while_parser_candidates_are_live() {
    let source = CandidateAttributeValue::string("{\"a\":[1,2]}".to_owned())
        .validate_log_body(ValueLimitProfile::release_1_system_maximum())
        .expect("bounded JSON source");
    let mut observer = MemoryProbe::default();
    BodyTransform::Json
        .apply_with_facts(&source, &mut observer)
        .expect("JSON transform succeeds");

    // Three parser entries (288 bytes), one key capacity (8 bytes), and the
    // canonical root/array output slots (96 + 2 * 64 bytes) are simultaneous.
    assert_eq!(observer.reserved, 520);
    assert_eq!(observer.released, 7);
}

#[test]
fn parser_reservations_cover_actual_string_capacity() {
    let source = CandidateAttributeValue::string(r#""123456789""#.to_owned())
        .validate_log_body(ValueLimitProfile::release_1_system_maximum())
        .expect("bounded JSON source");
    let mut observer = MemoryProbe::default();
    let facts = BodyTransform::Json
        .apply_with_facts(&source, &mut observer)
        .expect("JSON scalar transform succeeds");

    assert!(observer.reserved >= facts.retained_heap_bytes() as u64);
}

#[test]
fn capacity_helpers_fail_closed_and_reconcile_formatter_failures() {
    let mut observer = MemoryProbe::default();
    let mut text = String::new();
    reserve_string_capacity(&mut text, 0, &mut observer).expect("zero growth is a no-op");
    assert_eq!(
        reserve_string_capacity(&mut text, usize::MAX, &mut observer),
        Err(QueryFailure::new(QueryFailureCode::ResourceExhausted))
    );
    assert_eq!(
        reserve_string_capacity(&mut text, 1_usize << 62, &mut observer),
        Err(QueryFailure::new(QueryFailureCode::ResourceExhausted))
    );

    let mut entries = Vec::<u8>::new();
    reserve_vec_capacity(&mut entries, 0, 1, &mut observer).expect("zero growth is a no-op");
    assert_eq!(
        reserve_vec_capacity(&mut entries, usize::MAX, 1, &mut observer),
        Err(QueryFailure::new(QueryFailureCode::ResourceExhausted))
    );
    assert_eq!(
        reserve_vec_capacity(&mut entries, 1_usize << 62, 1, &mut observer),
        Err(QueryFailure::new(QueryFailureCode::ResourceExhausted))
    );
    assert_eq!(
        reserve_vec_capacity(&mut entries, 2, u64::MAX, &mut observer),
        Err(QueryFailure::new(QueryFailureCode::ResourceExhausted))
    );

    let first_pass = Cell::new(true);
    let result = capacity::format_scalar(
        |output| {
            if first_pass.replace(false) {
                output.write_str("7")
            } else {
                output.write_str("77")
            }
        },
        &mut observer,
    );
    assert_eq!(result, Err(QueryFailure::new(QueryFailureCode::Internal)));
    assert!(observer.released > 0);

    let mut sizing_error = MemoryProbe::default();
    let result = capacity::format_scalar(|_| Err(std::fmt::Error), &mut sizing_error);
    assert_eq!(result, Err(QueryFailure::new(QueryFailureCode::Internal)));
}

#[test]
fn observed_transform_failures_keep_stable_domain_and_observer_classes() {
    assert_eq!(
        map_domain_failure_code(positron_domain::outcome::DomainFailureCode::ValueLimitExceeded)
            .code(),
        QueryFailureCode::UnsupportedQuery
    );
    assert_eq!(
        map_domain_failure_code(positron_domain::outcome::DomainFailureCode::AllocationUnavailable)
            .code(),
        QueryFailureCode::ResourceExhausted
    );

    let domain_failure = CandidateAttributeValue::key_value_list(vec![
        positron_domain::value::CandidateKeyValue::new(
            String::new(),
            CandidateAttributeValue::null(),
        ),
    ])
    .validate_attribute(ValueLimitProfile::release_1_system_maximum())
    .expect_err("empty key is a domain value-limit failure");
    let mapped = map_observed_failure(positron_domain::value::ObservedValueFailure::Domain(
        domain_failure,
    ));
    assert_eq!(mapped.code(), QueryFailureCode::UnsupportedQuery);

    let cancelled = map_observed_failure(positron_domain::value::ObservedValueFailure::Observer(
        QueryFailure::new(QueryFailureCode::Cancelled),
    ));
    assert_eq!(cancelled.code(), QueryFailureCode::Cancelled);
}
