use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode};

pub(super) fn fuzz_query_transforms(data: &[u8]) {
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
    if data.len() > crate::transform::MAX_TRANSFORM_INPUT_BYTES {
        let candidate = positron_domain::value::CandidateAttributeValue::string(source.to_owned());
        let value = match candidate.validate_log_body(profile) {
            Ok(value) => value,
            Err(failure) => {
                assert_eq!(
                    failure.code(),
                    positron_domain::outcome::DomainFailureCode::ValueLimitExceeded
                );
                return;
            },
        };
        for transform in [
            crate::transform::BodyTransform::Json,
            crate::transform::BodyTransform::Logfmt,
            crate::transform::BodyTransform::Cast(crate::transform::CastTarget::String),
            crate::transform::BodyTransform::Cast(crate::transform::CastTarget::Integer),
            crate::transform::BodyTransform::Cast(crate::transform::CastTarget::Float),
            crate::transform::BodyTransform::Cast(crate::transform::CastTarget::Boolean),
        ] {
            let mut observer = Unobserved;
            let result = transform.apply_with_facts(&value, &mut observer);
            assert!(matches!(
                result,
                Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
            ));
        }
        return;
    }
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
