use std::error::Error;

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
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::UnsupportedQuery
    ));
}

#[test]
fn logfmt_typed_quoted_duplicate_and_limit_contract_is_public() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-logfmt-edge-values")?;
    fixture.kernel.append_log(
        "null_value=null true_value=true false_value=false int=-7 float=1.5 text=hello empty= message=\"quote\\\" slash\\\\ line\\nreturn\\rtab\\t\" dup=one dup=\"two words\" unicode=olá   ",
        20,
        1,
    )?;
    let events = execute(
        &fixture,
        "pipeline:v1 logs | range query_time -100 100 | logfmt | limit 1",
    )?;
    let body = first_record(&events)?.body_value().ok_or("body missing")?;
    assert_eq!(body.key_value_list_len(), Some(11));
    assert!(
        body.key_value_entry(0)
            .is_some_and(|entry| entry.value().is_null())
    );
    assert_eq!(
        body.key_value_entry(1)
            .and_then(|entry| entry.value().as_boolean()),
        Some(true)
    );
    assert_eq!(
        body.key_value_entry(2)
            .and_then(|entry| entry.value().as_boolean()),
        Some(false)
    );
    assert_eq!(
        body.key_value_entry(3)
            .and_then(|entry| entry.value().as_signed_integer()),
        Some(-7)
    );
    assert_eq!(
        body.key_value_entry(4)
            .and_then(|entry| entry.value().as_floating_point_bits()),
        Some(1.5_f64.to_bits())
    );
    assert_eq!(
        body.key_value_entry(5)
            .and_then(|entry| entry.value().as_str()),
        Some("hello")
    );
    assert_eq!(
        body.key_value_entry(6)
            .and_then(|entry| entry.value().as_str()),
        Some("")
    );
    assert_eq!(
        body.key_value_entry(7)
            .and_then(|entry| entry.value().as_str()),
        Some("quote\" slash\\ line\nreturn\rtab\t")
    );
    assert_eq!(
        body.key_value_entry(8).map(|entry| entry.key()),
        Some("dup")
    );
    assert_eq!(
        body.key_value_entry(9).map(|entry| entry.key()),
        Some("dup")
    );
    assert_eq!(
        body.key_value_entry(10)
            .and_then(|entry| entry.value().as_str()),
        Some("olá")
    );
    Ok(())
}

#[test]
fn logfmt_malformed_and_input_limits_are_stable() -> Result<(), Box<dyn Error>> {
    for (index, source) in [
        "=value",
        "missing_equals",
        "key=\"unterminated",
        "key=\"bad\\q\"",
        "key=\"\u{0001}\"",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = QueryFixture::new(&format!("query-logfmt-malformed-{index}"))?;
        fixture.kernel.append_log(source, 20, 1)?;
        assert_unsupported(&execute(
            &fixture,
            "pipeline:v1 logs | range query_time -100 100 | logfmt | limit 1",
        )?);
    }
    let entries = (0..1_025)
        .map(|index| format!("k{index}=0"))
        .collect::<Vec<_>>()
        .join(" ");
    let fixture = QueryFixture::new("query-logfmt-entry-limit")?;
    fixture.kernel.append_log(&entries, 20, 1)?;
    assert_unsupported(&execute(
        &fixture,
        "pipeline:v1 logs | range query_time -100 100 | logfmt | limit 1",
    )?);

    let fixture = QueryFixture::new("query-logfmt-input-limit")?;
    fixture
        .kernel
        .append_log(&format!("value={}", "x".repeat(65_537)), 20, 1)?;
    assert_unsupported(&execute(
        &fixture,
        "pipeline:v1 logs | range query_time -100 100 | logfmt | limit 1",
    )?);
    Ok(())
}
