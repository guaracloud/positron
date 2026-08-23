use std::error::Error;

use positron_domain::value::{AttributeValueKind, CandidateAttributeValue};
use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryTerminal};

use super::support::zero_work_service;
use super::terminal_and_bounds::QueryFixture;

fn first_record(events: &[QueryEvent]) -> Result<&positron_query::QueryRecord, Box<dyn Error>> {
    events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().first(),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or_else(|| "query result record missing".into())
}

#[test]
fn json_query_transform_decodes_bounded_native_object_without_mutating_source()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-json-transform")?;
    fixture
        .kernel
        .append_log(r#"{"service":"api","count":7,"ok":true}"#, 20, 1)?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let record = first_record(&events)?;
    let body = record.body_value().ok_or("transformed body missing")?;
    assert_eq!(body.kind(), AttributeValueKind::KeyValueList);
    assert_eq!(body.key_value_list_len(), Some(3));
    assert_eq!(
        body.key_value_entry(1).map(|entry| entry.key()),
        Some("count")
    );
    assert_eq!(
        body.key_value_entry(1)
            .and_then(|entry| entry.value().as_signed_integer()),
        Some(7)
    );
    assert_eq!(
        body.key_value_entry(2)
            .and_then(|entry| entry.value().as_boolean()),
        Some(true)
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn json_transform_can_expand_a_source_body_within_the_memory_budget() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("query-json-transform-expansion")?;
    let source = format!(
        "[{}]",
        (0..1_024).map(|_| "0").collect::<Vec<_>>().join(",")
    );
    fixture.kernel.append_log(&source, 20, 1)?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert_eq!(
        first_record(&events)?
            .body_value()
            .and_then(|body| body.array_len()),
        Some(1_024)
    );
    Ok(())
}

#[test]
fn parser_scratch_and_retained_output_have_exact_memory_boundaries() -> Result<(), Box<dyn Error>> {
    let json_fixture = QueryFixture::new("query-json-transform-memory-boundary")?;
    let json_source = format!(
        "{{{}}}",
        (0..100)
            .map(|index| format!(r#""k{index}":"{}""#, "value".repeat(8)))
            .collect::<Vec<_>>()
            .join(",")
    );
    json_fixture.kernel.append_log(&json_source, 20, 1)?;
    let json_service = zero_work_service(
        json_fixture.kernel.authority.governor(),
        json_fixture.kernel.ledger()?,
        16,
    );
    let json_query = |memory| {
        let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, memory, 60)
            .and_then(|budget| budget.with_cpu_work_units(1_024))?;
        json_service.plan_pipeline(
            json_fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
            budget,
        )
    };
    let json_events = json_service
        .execute(json_query(1_048_576)?)?
        .collect::<Vec<_>>();
    let json_peak = json_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Complete(stats)) => Some(stats.memory_peak_bytes()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("JSON boundary query did not complete")?;
    let json_under = json_service
        .execute(json_query(
            json_peak.checked_sub(1).ok_or("JSON peak was zero")?,
        )?)?
        .collect::<Vec<_>>();
    assert!(matches!(
        json_under.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::MemoryBytes)
    ));

    let logfmt_fixture = QueryFixture::new("query-logfmt-transform-memory-boundary")?;
    let logfmt_source = (0..1_024)
        .map(|index| format!("k{index}=\"{}\"", "value".repeat(8)))
        .collect::<Vec<_>>()
        .join(" ");
    logfmt_fixture.kernel.append_log(&logfmt_source, 20, 1)?;
    let logfmt_service = zero_work_service(
        logfmt_fixture.kernel.authority.governor(),
        logfmt_fixture.kernel.ledger()?,
        16,
    );
    let logfmt_query = |memory| {
        let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, memory, 60)
            .and_then(|budget| budget.with_cpu_work_units(1_024))?;
        logfmt_service.plan_pipeline(
            logfmt_fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | logfmt | limit 1",
            budget,
        )
    };
    let logfmt_events = logfmt_service
        .execute(logfmt_query(1_048_576)?)?
        .collect::<Vec<_>>();
    let logfmt_peak = logfmt_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Complete(stats)) => Some(stats.memory_peak_bytes()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("logfmt boundary query did not complete")?;
    let logfmt_under = logfmt_service
        .execute(logfmt_query(
            logfmt_peak.checked_sub(1).ok_or("logfmt peak was zero")?,
        )?)?
        .collect::<Vec<_>>();
    assert!(matches!(
        logfmt_under.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::MemoryBytes)
    ));
    Ok(())
}

#[test]
fn logfmt_query_transform_decodes_quoted_and_typed_fields() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-logfmt-transform")?;
    fixture
        .kernel
        .append_log(r#"service=api count=7 ok=true msg="hello world""#, 20, 1)?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | logfmt | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let body = first_record(&events)?
        .body_value()
        .ok_or("transformed body missing")?;
    assert_eq!(body.kind(), AttributeValueKind::KeyValueList);
    assert_eq!(body.key_value_list_len(), Some(4));
    assert_eq!(
        body.key_value_entry(1)
            .and_then(|entry| entry.value().as_signed_integer()),
        Some(7)
    );
    assert_eq!(
        body.key_value_entry(2)
            .and_then(|entry| entry.value().as_boolean()),
        Some(true)
    );
    assert_eq!(
        body.key_value_entry(3)
            .and_then(|entry| entry.value().as_str()),
        Some("hello world")
    );
    Ok(())
}

#[test]
fn transforms_preserve_unicode_and_allow_trailing_logfmt_whitespace() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("query-transform-unicode-json")?;
    fixture
        .kernel
        .append_log(r#"{"message":"olá 世界"}"#, 20, 1)?;
    fixture
        .kernel
        .append_log("[null,true,false,-1,1.5,1e2]", 21, 2)?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let json = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let json_events = service.execute(json)?.collect::<Vec<_>>();
    assert_eq!(
        first_record(&json_events)?
            .body_value()
            .and_then(|value| value.key_value_entry(0))
            .and_then(|entry| entry.value().as_str()),
        Some("olá 世界")
    );
    let array = json_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().get(1),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("json array record missing")?
        .body_value()
        .ok_or("json array body missing")?;
    assert_eq!(array.array_len(), Some(6));
    assert!(array.array_entry(0).is_some_and(|value| value.is_null()));
    assert_eq!(
        array.array_entry(1).and_then(|value| value.as_boolean()),
        Some(true)
    );
    assert_eq!(
        array
            .array_entry(3)
            .and_then(|value| value.as_signed_integer()),
        Some(-1)
    );
    assert_eq!(
        array
            .array_entry(4)
            .and_then(|value| value.as_floating_point_bits()),
        Some(1.5_f64.to_bits())
    );
    let logfmt_fixture = QueryFixture::new("query-transform-unicode-logfmt")?;
    logfmt_fixture.kernel.append_log("message=olá ", 20, 1)?;
    let logfmt_service = zero_work_service(
        logfmt_fixture.kernel.authority.governor(),
        logfmt_fixture.kernel.ledger()?,
        16,
    );
    let logfmt = logfmt_service.plan_pipeline(
        logfmt_fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | logfmt | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let logfmt_events = logfmt_service.execute(logfmt)?.collect::<Vec<_>>();
    let body = logfmt_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().first(),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("logfmt record missing")?
        .body_value()
        .ok_or("logfmt body missing")?;
    assert_eq!(
        body.key_value_entry(0)
            .and_then(|entry| entry.value().as_str()),
        Some("olá")
    );
    Ok(())
}

#[test]
fn explicit_cast_changes_only_the_query_value_and_reports_cast_failure()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-cast-transform")?;
    fixture.kernel.append_log_bodies(
        vec![
            Some(CandidateAttributeValue::signed_integer(42)),
            Some(CandidateAttributeValue::string("not-an-int".to_owned())),
        ],
        20,
        1,
    )?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | cast body as string | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert_eq!(first_record(&events)?.body_text(), Some("42"));
    let invalid = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | cast body as int | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let invalid_events = service.execute(invalid)?.collect::<Vec<_>>();
    assert!(matches!(
        invalid_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::UnsupportedQuery
    ));
    Ok(())
}
