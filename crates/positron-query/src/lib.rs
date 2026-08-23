//! Native bounded query planning and execution.

#![forbid(unsafe_code)]

mod attribute_syntax;
mod budget;
mod cancellation;
mod cursor;
mod execution;
mod execution_state;
mod execution_support;
mod failure;
mod memory;
mod native_literal;
mod operators;
mod plan;
mod query_service;
mod runtime;
mod search;
mod service;
mod sql;
mod sql_lexer;
mod sql_selection;
mod stream;
mod stream_lifecycle;
mod transform;

pub use budget::{QueryBudget, QueryBudgetDimension};
pub use cancellation::QueryCancellation;
pub use cursor::QueryCursor;
pub use failure::{QueryFailure, QueryFailureCode};
pub use plan::{LogicalPlan, OrderDirection, PlannedQuery, TemporalAxis, TemporalRange};
pub use query_service::QueryService;
pub use runtime::{
    QueryClock, QueryClockFailure, QueryWorkFailure, QueryWorkMeter, QueryWorkStage,
};
pub use stream::{
    QueryBatch, QueryEvent, QueryHeader, QueryIncomplete, QueryRecord, QueryStats, QueryTerminal,
    ResultLease, ResultOrdering, ResultSchema, ResultSnapshot, ResultValueType,
};
pub use stream_lifecycle::QueryStream;

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_inputs(data: &[u8]) {
    if data.len() > 4_096 {
        return;
    }
    if let Ok(source) = std::str::from_utf8(data) {
        let _ = service::parse_pipeline(source);
        let _ = service::parse_sql(source);
    }
    let _ = QueryCursor::from_bytes(data);
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_sql(data: &[u8]) {
    const MAX_RAW_BYTES: usize = 4_096;
    const MAX_PARITY_LITERAL_BYTES: usize = 512;
    let raw = bounded_lossy_query(data, MAX_RAW_BYTES);
    let first = service::parse_sql(&raw);
    let second = service::parse_sql(&raw);
    assert_eq!(query_classification(&first), query_classification(&second));
    if let (Ok(first), Ok(second)) = (&first, &second) {
        assert_eq!(first, second, "SQL plans must be deterministic");
    }

    let literal = bounded_lossy_query(data, MAX_PARITY_LITERAL_BYTES);
    let Some(literal) = escaped_query_literal(&literal) else {
        return;
    };
    let Some((sql, pipeline)) = parity_queries(&literal) else {
        return;
    };
    let sql_result = service::parse_sql(&sql);
    let pipeline_result = service::parse_pipeline(&pipeline);
    assert_eq!(
        query_classification(&sql_result),
        query_classification(&pipeline_result),
        "equivalent bounded frontends must classify identically"
    );
    if let (Ok(sql), Ok(pipeline)) = (&sql_result, &pipeline_result) {
        assert_eq!(sql, pipeline, "equivalent frontends must share one plan");
    }
}

#[cfg(fuzzing)]
fn bounded_lossy_query(data: &[u8], maximum_bytes: usize) -> String {
    let bounded = data.get(..data.len().min(maximum_bytes)).unwrap_or(data);
    let lossy = String::from_utf8_lossy(bounded);
    let mut output = String::new();
    if output
        .try_reserve_exact(lossy.len().min(maximum_bytes))
        .is_err()
    {
        return String::new();
    }
    for character in lossy.chars() {
        let Some(next_length) = output.len().checked_add(character.len_utf8()) else {
            break;
        };
        if next_length > maximum_bytes {
            break;
        }
        output.push(character);
    }
    output
}

#[cfg(fuzzing)]
fn escaped_query_literal(value: &str) -> Option<String> {
    let required = value.bytes().try_fold(0_usize, |length, byte| {
        length.checked_add(usize::from(matches!(byte, b'"' | b'\\' | b'|')))
    })?;
    let required = value.len().checked_add(required)?;
    let mut escaped = String::new();
    escaped.try_reserve_exact(required).ok()?;
    for character in value.chars() {
        if matches!(character, '"' | '\\' | '|') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    Some(escaped)
}

#[cfg(fuzzing)]
fn parity_queries(literal: &str) -> Option<(String, String)> {
    let sql_prefix =
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body = \"";
    let sql_suffix = "\" ORDER BY query_time, commit_position LIMIT 1";
    let pipeline_prefix = "pipeline:v1 logs | range query_time -100 100 | filter body == \"";
    let pipeline_suffix = "\" | limit 1";
    let mut sql = String::new();
    sql.try_reserve_exact(
        sql_prefix
            .len()
            .checked_add(literal.len())?
            .checked_add(sql_suffix.len())?,
    )
    .ok()?;
    sql.push_str(sql_prefix);
    sql.push_str(literal);
    sql.push_str(sql_suffix);
    let mut pipeline = String::new();
    pipeline
        .try_reserve_exact(
            pipeline_prefix
                .len()
                .checked_add(literal.len())?
                .checked_add(pipeline_suffix.len())?,
        )
        .ok()?;
    pipeline.push_str(pipeline_prefix);
    pipeline.push_str(literal);
    pipeline.push_str(pipeline_suffix);
    Some((sql, pipeline))
}

#[cfg(fuzzing)]
fn query_classification(
    result: &Result<LogicalPlan, QueryFailure>,
) -> (Option<QueryFailureCode>, Option<QueryBudgetDimension>) {
    match result {
        Ok(_) => (None, None),
        Err(failure) => (Some(failure.code()), failure.limiting_budget()),
    }
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_search_matcher(data: &[u8]) {
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
    let Ok(mut regex) = search::BoundedRegex::from_source(pattern.to_owned()) else {
        return;
    };
    if regex.compile().is_err() {
        return;
    }
    let mut observer = search::UnobservedSearch;
    let _ = regex.is_match_observed(body, &mut observer);
    let Ok(mut substring) = search::BoundedSubstring::from_source(pattern.to_owned()) else {
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

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_transforms(data: &[u8]) {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    struct Unobserved;
    impl transform::TransformObserver for Unobserved {
        fn step(&mut self) -> Result<(), QueryFailure> {
            Ok(())
        }
    }
    let profile = positron_domain::value::ValueLimitProfile::release_1_system_maximum();
    if data.len() > transform::MAX_TRANSFORM_INPUT_BYTES {
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
            transform::BodyTransform::Json,
            transform::BodyTransform::Logfmt,
            transform::BodyTransform::Cast(transform::CastTarget::String),
            transform::BodyTransform::Cast(transform::CastTarget::Integer),
            transform::BodyTransform::Cast(transform::CastTarget::Float),
            transform::BodyTransform::Cast(transform::CastTarget::Boolean),
        ] {
            let mut observer = Unobserved;
            let result = transform.apply_with_facts(&value, &mut observer);
            assert!(matches!(
                result,
                Err(failure)
                    if failure.code() == QueryFailureCode::UnsupportedQuery
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
    impl transform::TransformObserver for Limited {
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
        transform::BodyTransform::Json,
        transform::BodyTransform::Logfmt,
        transform::BodyTransform::Cast(transform::CastTarget::String),
        transform::BodyTransform::Cast(transform::CastTarget::Integer),
        transform::BodyTransform::Cast(transform::CastTarget::Float),
        transform::BodyTransform::Cast(transform::CastTarget::Boolean),
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
                    transform::BodyTransform::Cast(transform::CastTarget::String) => {
                        assert!(output.as_str().is_some());
                    },
                    transform::BodyTransform::Cast(transform::CastTarget::Integer) => {
                        assert!(output.as_signed_integer().is_some());
                    },
                    transform::BodyTransform::Cast(transform::CastTarget::Float) => {
                        assert!(output.as_floating_point_bits().is_some());
                    },
                    transform::BodyTransform::Cast(transform::CastTarget::Boolean) => {
                        assert!(output.as_boolean().is_some());
                    },
                    transform::BodyTransform::Json | transform::BodyTransform::Logfmt => {},
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
