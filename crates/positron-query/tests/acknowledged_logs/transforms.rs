use std::error::Error;
use std::sync::Arc;

use positron_domain::value::{AttributeValueKind, CandidateAttributeValue};
use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryTerminal};

use super::support::{
    CancellingOperatorCallMeter, TestClock, stage_work_service, zero_work_service,
};
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

#[test]
fn malformed_and_over_limit_transforms_fail_closed_with_stable_query_errors()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-transform-bounds")?;
    let mut nested = String::new();
    for _ in 0..34 {
        nested.push('[');
    }
    nested.push('0');
    for _ in 0..34 {
        nested.push(']');
    }
    fixture.kernel.append_log(&nested, 20, 1)?;
    fixture.kernel.append_log("{malformed", 21, 2)?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    for source in [
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | logfmt | limit 1",
    ] {
        let query = service.plan_pipeline(
            fixture.context,
            source,
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
        )?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        assert!(matches!(
            events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::UnsupportedQuery
        ));
    }
    let oversized = "x".repeat(65_537);
    let oversized_fixture = QueryFixture::new("query-transform-size")?;
    oversized_fixture.kernel.append_log(&oversized, 20, 1)?;
    let oversized_service = zero_work_service(
        oversized_fixture.kernel.authority.governor(),
        oversized_fixture.kernel.ledger()?,
        16,
    );
    let query = oversized_service.plan_pipeline(
        oversized_fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = oversized_service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::UnsupportedQuery
    ));
    let entries_fixture = QueryFixture::new("query-transform-entry-bound")?;
    let mut logfmt = String::new();
    for index in 0..1_025 {
        if index > 0 {
            logfmt.push(' ');
        }
        logfmt.push_str("k=");
        logfmt.push_str(&index.to_string());
    }
    entries_fixture.kernel.append_log(&logfmt, 20, 1)?;
    let entries_service = zero_work_service(
        entries_fixture.kernel.authority.governor(),
        entries_fixture.kernel.ledger()?,
        16,
    );
    let query = entries_service.plan_pipeline(
        entries_fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | logfmt | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = entries_service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::UnsupportedQuery
    ));
    Ok(())
}

#[test]
fn transform_work_is_cumulative_and_cancellation_is_prompt() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-transform-work")?;
    fixture
        .kernel
        .append_log(&format!("{{\"value\":{}}}", "7".repeat(128)), 20, 1)?;
    let service = stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let budget =
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(8)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        budget,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
    ));

    let cancelling = QueryFixture::new("query-transform-cancel")?;
    cancelling
        .kernel
        .append_log(&format!("{{\"value\":{}}}", "7".repeat(128)), 20, 1)?;
    let meter = CancellingOperatorCallMeter::shared(3);
    let service = positron_query::QueryService::with_runtime(
        cancelling.kernel.authority.governor(),
        cancelling.kernel.ledger()?,
        16,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let query = service.plan_pipeline(
        cancelling.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    meter.bind(query.cancellation())?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
    ));
    Ok(())
}

#[test]
fn transforms_read_active_sealed_and_reopened_records_without_source_mutation()
-> Result<(), Box<dyn Error>> {
    let mut fixture = QueryFixture::new("query-transform-lifecycle")?;
    fixture.kernel.append_log(r#"{"state":"active"}"#, 20, 1)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert_eq!(
        first_record(&events)?
            .body_value()
            .and_then(|value| value.key_value_entry(0))
            .and_then(|entry| entry.value().as_str()),
        Some("active")
    );
    drop(service);
    fixture.kernel.seal_and_reopen()?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert_eq!(
        first_record(&events)?
            .body_value()
            .and_then(|value| value.key_value_entry(0))
            .and_then(|entry| entry.value().as_str()),
        Some("active")
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert_eq!(
        first_record(&events)?.body_text(),
        Some(r#"{"state":"active"}"#)
    );
    Ok(())
}
