use std::error::Error;

use positron_domain::value::CandidateAttributeValue;
use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryRecord, QueryTerminal};

use super::terminal_and_bounds::QueryFixture;

fn first_record(events: &[QueryEvent]) -> Result<&QueryRecord, Box<dyn Error>> {
    events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().first(),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or_else(|| "query result record missing".into())
}

fn records(events: &[QueryEvent]) -> Vec<&QueryRecord> {
    events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records().iter()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .collect()
}

fn execute(fixture: &QueryFixture, source: &str) -> Result<Vec<QueryEvent>, Box<dyn Error>> {
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    Ok(service.execute(query)?.collect())
}

fn assert_unsupported(events: &[QueryEvent]) {
    assert!(
        matches!(
            events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::UnsupportedQuery
        ),
        "unexpected terminal: {:?}",
        events.last()
    );
}

#[test]
fn casts_cover_all_native_scalar_sources_and_exact_float_bits() -> Result<(), Box<dyn Error>> {
    let strings = QueryFixture::new("query-cast-all-string")?;
    strings.kernel.append_log_bodies(
        vec![
            Some(CandidateAttributeValue::null()),
            Some(CandidateAttributeValue::boolean(true)),
            Some(CandidateAttributeValue::signed_integer(-7)),
            Some(CandidateAttributeValue::floating_point_bits(
                1.5_f64.to_bits(),
            )),
            Some(CandidateAttributeValue::string("42".to_owned())),
        ],
        20,
        1,
    )?;
    let events = execute(
        &strings,
        "pipeline:v1 logs | range query_time -100 100 | cast body as string | limit 5",
    )?;
    let values = records(&events)
        .into_iter()
        .map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(
        values,
        vec![
            Some("null"),
            Some("true"),
            Some("-7"),
            Some("1.5"),
            Some("42")
        ]
    );

    let integers = QueryFixture::new("query-cast-all-integer")?;
    integers.kernel.append_log_bodies(
        vec![
            Some(CandidateAttributeValue::string("42".to_owned())),
            Some(CandidateAttributeValue::floating_point_bits(
                7.0_f64.to_bits(),
            )),
            Some(CandidateAttributeValue::boolean(true)),
        ],
        20,
        1,
    )?;
    let events = execute(
        &integers,
        "pipeline:v1 logs | range query_time -100 100 | cast body as int | limit 3",
    )?;
    let values = records(&events)
        .into_iter()
        .filter_map(|record| {
            record
                .body_value()
                .and_then(|value| value.as_signed_integer())
        })
        .collect::<Vec<_>>();
    assert_eq!(values, vec![42, 7, 1]);

    let floats = QueryFixture::new("query-cast-all-float")?;
    floats.kernel.append_log_bodies(
        vec![
            Some(CandidateAttributeValue::signed_integer(-3)),
            Some(CandidateAttributeValue::string("1.25".to_owned())),
            Some(CandidateAttributeValue::floating_point_bits(
                3.5_f64.to_bits(),
            )),
        ],
        20,
        1,
    )?;
    let events = execute(
        &floats,
        "pipeline:v1 logs | range query_time -100 100 | cast body as float | limit 3",
    )?;
    let values = records(&events)
        .into_iter()
        .filter_map(|record| {
            record
                .body_value()
                .and_then(|value| value.as_floating_point_bits())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        values,
        vec![(-3.0_f64).to_bits(), 1.25_f64.to_bits(), 3.5_f64.to_bits()]
    );

    let booleans = QueryFixture::new("query-cast-all-bool")?;
    booleans.kernel.append_log_bodies(
        vec![
            Some(CandidateAttributeValue::string("true".to_owned())),
            Some(CandidateAttributeValue::signed_integer(0)),
            Some(CandidateAttributeValue::signed_integer(1)),
            Some(CandidateAttributeValue::boolean(false)),
        ],
        20,
        1,
    )?;
    let events = execute(
        &booleans,
        "pipeline:v1 logs | range query_time -100 100 | cast body as bool | limit 4",
    )?;
    let values = records(&events)
        .into_iter()
        .filter_map(|record| record.body_value().and_then(|value| value.as_boolean()))
        .collect::<Vec<_>>();
    assert_eq!(values, vec![true, false, true, false]);

    let unsupported_sources = QueryFixture::new("query-cast-unsupported-sources")?;
    unsupported_sources.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::bytes(vec![1, 2]))],
        20,
        1,
    )?;
    assert_unsupported(&execute(
        &unsupported_sources,
        "pipeline:v1 logs | range query_time -100 100 | cast body as string | limit 1",
    )?);

    let unsupported_integer = QueryFixture::new("query-cast-out-of-range-integer")?;
    unsupported_integer.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::floating_point_bits(
            1e100_f64.to_bits(),
        ))],
        20,
        1,
    )?;
    assert_unsupported(&execute(
        &unsupported_integer,
        "pipeline:v1 logs | range query_time -100 100 | cast body as int | limit 1",
    )?);

    let fractional_integer = QueryFixture::new("query-cast-fractional-integer")?;
    fractional_integer.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::floating_point_bits(
            1.5_f64.to_bits(),
        ))],
        20,
        1,
    )?;
    assert_unsupported(&execute(
        &fractional_integer,
        "pipeline:v1 logs | range query_time -100 100 | cast body as int | limit 1",
    )?);

    let unsupported_float = QueryFixture::new("query-cast-null-float")?;
    unsupported_float.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::null())],
        20,
        1,
    )?;
    assert_unsupported(&execute(
        &unsupported_float,
        "pipeline:v1 logs | range query_time -100 100 | cast body as float | limit 1",
    )?);

    let unsupported_boolean = QueryFixture::new("query-cast-invalid-bool")?;
    unsupported_boolean.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::signed_integer(2))],
        20,
        1,
    )?;
    assert_unsupported(&execute(
        &unsupported_boolean,
        "pipeline:v1 logs | range query_time -100 100 | cast body as bool | limit 1",
    )?);

    let null_boolean = QueryFixture::new("query-cast-null-bool")?;
    null_boolean
        .kernel
        .append_log_bodies(vec![Some(CandidateAttributeValue::null())], 20, 1)?;
    assert_unsupported(&execute(
        &null_boolean,
        "pipeline:v1 logs | range query_time -100 100 | cast body as bool | limit 1",
    )?);

    let false_text = QueryFixture::new("query-cast-false-text")?;
    false_text.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::string("false".to_owned()))],
        20,
        1,
    )?;
    let events = execute(
        &false_text,
        "pipeline:v1 logs | range query_time -100 100 | cast body as bool | limit 1",
    )?;
    assert_eq!(
        first_record(&events)?
            .body_value()
            .and_then(|value| value.as_boolean()),
        Some(false)
    );

    let invalid_text = QueryFixture::new("query-cast-invalid-bool-text")?;
    invalid_text.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::string("maybe".to_owned()))],
        20,
        1,
    )?;
    assert_unsupported(&execute(
        &invalid_text,
        "pipeline:v1 logs | range query_time -100 100 | cast body as bool | limit 1",
    )?);

    let non_finite = QueryFixture::new("query-cast-nan-float")?;
    non_finite.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::string("NaN".to_owned()))],
        20,
        1,
    )?;
    assert_unsupported(&execute(
        &non_finite,
        "pipeline:v1 logs | range query_time -100 100 | cast body as float | limit 1",
    )?);

    let non_finite_string = QueryFixture::new("query-cast-nan-string")?;
    non_finite_string.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::floating_point_bits(
            f64::NAN.to_bits(),
        ))],
        20,
        1,
    )?;
    assert_unsupported(&execute(
        &non_finite_string,
        "pipeline:v1 logs | range query_time -100 100 | cast body as string | limit 1",
    )?);

    let oversized = QueryFixture::new("query-cast-input-limit")?;
    oversized.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::string("x".repeat(65_537)))],
        20,
        1,
    )?;
    assert_unsupported(&execute(
        &oversized,
        "pipeline:v1 logs | range query_time -100 100 | cast body as string | limit 1",
    )?);
    Ok(())
}
