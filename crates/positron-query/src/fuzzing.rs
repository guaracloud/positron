use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode};

pub(super) fn fuzz_query_transforms(data: &[u8]) {
    if data.len() > crate::transform::MAX_TRANSFORM_INPUT_BYTES {
        return;
    }
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    struct Unobserved;
    impl crate::transform::TransformObserver for Unobserved {
        fn step(&mut self) -> Result<(), QueryFailure> {
            Ok(())
        }
    }
    let profile = positron_domain::value::ValueLimitProfile::release_1_system_maximum();
    let mut bits = [0_u8; 8];
    for (index, byte) in data.iter().take(bits.len()).enumerate() {
        if let Some(slot) = bits.get_mut(index) {
            *slot = *byte;
        }
    }
    let candidates = [
        positron_domain::value::CandidateAttributeValue::string(source.to_owned()),
        positron_domain::value::CandidateAttributeValue::null(),
        positron_domain::value::CandidateAttributeValue::boolean(data.len() % 2 == 0),
        positron_domain::value::CandidateAttributeValue::signed_integer(i64::from_le_bytes(bits)),
        positron_domain::value::CandidateAttributeValue::floating_point_bits(u64::from_le_bytes(
            bits,
        )),
    ];
    struct Limited {
        remaining: u16,
    }
    impl crate::transform::TransformObserver for Limited {
        fn step(&mut self) -> Result<(), QueryFailure> {
            if self.remaining == 0 {
                return Err(QueryFailure::budget_exhausted(
                    QueryBudgetDimension::CpuWorkUnits,
                ));
            }
            self.remaining -= 1;
            Ok(())
        }
    }
    let transforms = [
        crate::transform::BodyTransform::Json,
        crate::transform::BodyTransform::Logfmt,
        crate::transform::BodyTransform::Cast(crate::transform::CastTarget::String),
        crate::transform::BodyTransform::Cast(crate::transform::CastTarget::Integer),
        crate::transform::BodyTransform::Cast(crate::transform::CastTarget::Float),
        crate::transform::BodyTransform::Cast(crate::transform::CastTarget::Boolean),
    ];
    for candidate in candidates {
        let Ok(value) = candidate.validate_log_body(profile) else {
            continue;
        };
        for transform in transforms {
            let mut observer = Unobserved;
            let outcome = transform.apply(&value, &mut observer);
            if let Ok(output) = &outcome {
                let mut repeat_observer = Unobserved;
                assert_eq!(
                    outcome,
                    transform.apply(&value, &mut repeat_observer),
                    "transform outcome must be deterministic"
                );
                match transform {
                    crate::transform::BodyTransform::Cast(crate::transform::CastTarget::String) => {
                        assert!(output.as_str().is_some());
                    },
                    crate::transform::BodyTransform::Cast(
                        crate::transform::CastTarget::Integer,
                    ) => {
                        assert!(output.as_signed_integer().is_some());
                    },
                    crate::transform::BodyTransform::Cast(crate::transform::CastTarget::Float) => {
                        assert!(output.as_floating_point_bits().is_some());
                    },
                    crate::transform::BodyTransform::Cast(
                        crate::transform::CastTarget::Boolean,
                    ) => {
                        assert!(output.as_boolean().is_some());
                    },
                    crate::transform::BodyTransform::Json
                    | crate::transform::BodyTransform::Logfmt => {},
                }
            }
            let mut limited = Limited { remaining: 0 };
            if let Err(failure) = transform.apply(&value, &mut limited) {
                assert!(
                    matches!(
                        failure.code(),
                        QueryFailureCode::BudgetExhausted
                            | QueryFailureCode::UnsupportedQuery
                            | QueryFailureCode::ResourceExhausted
                            | QueryFailureCode::Cancelled
                    ),
                    "observed transform failures must retain stable budget vocabulary"
                );
            }
        }
    }
}

pub(super) fn fuzz_query_search_matcher(data: &[u8]) {
    if data.is_empty() || data.len() > 4_096 {
        return;
    }
    let pattern_len = usize::from(data[0]).min(data.len().saturating_sub(1));
    let (pattern, body) = data[1..].split_at(pattern_len);
    let Ok(pattern) = std::str::from_utf8(pattern) else {
        return;
    };
    let Ok(body) = std::str::from_utf8(body) else {
        return;
    };
    let Ok(mut regex) = crate::search::BoundedRegex::from_source(pattern.to_owned()) else {
        return;
    };
    if regex.compile().is_err() {
        return;
    }
    let mut observer = crate::search::UnobservedSearch;
    let _ = regex.is_match_observed(body, &mut observer);
    let Ok(mut substring) = crate::search::BoundedSubstring::from_source(pattern.to_owned()) else {
        return;
    };
    if substring.compile().is_err() {
        return;
    }
    let _ = substring.is_match_observed(body, &mut observer);
    let literals = regex
        .pruning_literals()
        .iter()
        .map(|literal| literal.to_vec())
        .collect::<Vec<_>>();
    positron_signals::fuzz_text_search_pruning(body, &literals);
}
