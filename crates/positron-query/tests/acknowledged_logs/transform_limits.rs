use std::error::Error;
use std::sync::Arc;

use positron_domain::value::CandidateAttributeValue;
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

fn assert_unsupported(events: &[QueryEvent]) {
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::UnsupportedQuery
    ));
}

#[test]
fn text_predicates_skip_missing_and_non_text_bodies() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-text-predicate-body-kinds")?;
    fixture.kernel.append_log_bodies(
        vec![None, Some(CandidateAttributeValue::signed_integer(7))],
        20,
        1,
    )?;
    let service = fixture.service(16)?;
    for predicate in [
        r#"search body contains "seven""#,
        r#"search body =~ "seven""#,
    ] {
        let query = service.plan_pipeline(
            fixture.context,
            &format!("pipeline:v1 logs | range query_time -100 100 | {predicate} | limit 2"),
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
        )?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, QueryEvent::Batch(_)))
        );
        assert!(matches!(
            events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
        ));
    }
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
        assert_unsupported(&service.execute(query)?.collect::<Vec<_>>());
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
    assert_unsupported(&oversized_service.execute(query)?.collect::<Vec<_>>());

    let entries_fixture = QueryFixture::new("query-transform-entry-bound")?;
    let entries = (0..1_025)
        .map(|index| format!("k={index}"))
        .collect::<Vec<_>>()
        .join(" ");
    entries_fixture.kernel.append_log(&entries, 20, 1)?;
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
    assert_unsupported(&entries_service.execute(query)?.collect::<Vec<_>>());
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

#[test]
fn transformed_text_predicates_use_the_transformed_value_not_raw_sidecar_evidence()
-> Result<(), Box<dyn Error>> {
    let escaped = QueryFixture::new("query-transform-escaped-search")?;
    let escaped_schema = escaped
        .kernel
        .append_indexed_text_logs(vec![r#""\u0066oo""#], 1)?;
    let service = escaped.service(16)?;
    let query = service.plan_pipeline(
        escaped.context,
        r#"pipeline:v1 logs | range query_time -100 100 | json | search body contains "foo" | limit 1"#,
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service
        .execute_with_schema(query, escaped_schema.catalog())?
        .collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.reduced_pruning() && stats.decoded_records() == 1
    ));
    assert_eq!(first_record(&events)?.body_text(), Some("foo"));

    let object = QueryFixture::new("query-transform-object-search")?;
    let object_schema = object
        .kernel
        .append_indexed_text_logs(vec![r#"{"value":"foo"}"#], 1)?;
    let service = object.service(16)?;
    let query = service.plan_pipeline(
        object.context,
        r#"pipeline:v1 logs | range query_time -100 100 | json | search body contains "foo" | limit 1"#,
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service
        .execute_with_schema(query, object_schema.catalog())?
        .collect::<Vec<_>>();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.reduced_pruning() && stats.decoded_records() == 1
    ));
    Ok(())
}

#[test]
fn textual_predicates_must_follow_body_transform() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-transform-stage-order")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?;
    assert_eq!(
        service
            .plan_pipeline(
                fixture.context,
                r#"pipeline:v1 logs | range query_time -100 100 | search body contains "foo" | json | limit 1"#,
                budget,
            )
            .err()
            .ok_or("predicate-before-transform was accepted")?
            .code(),
        QueryFailureCode::UnsupportedQuery
    );
    service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | json | search body contains "foo" | limit 1"#,
        budget,
    )?;
    Ok(())
}

#[test]
fn temporal_exclusion_precedes_transform_parsing() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-transform-temporal-order")?;
    fixture.kernel.append_log("{malformed", 200, 1)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.decoded_records() == 1
    ));
    Ok(())
}

#[test]
fn transformed_predicate_cancellation_releases_transformed_memory() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-transform-predicate-cancellation")?;
    fixture
        .kernel
        .append_log(r#""timeout timeout timeout timeout timeout""#, 20, 1)?;
    let meter = CancellingOperatorCallMeter::shared(10);
    let service = positron_query::QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let query = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | cast body as string | search body contains "timeout" | limit 1"#,
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
            .with_cpu_work_units(128)?,
    )?;
    meter.bind(query.cancellation())?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
    ));

    let follow_up = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | json | limit 1"#,
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(128)?,
    )?;
    let follow_up_events = service.execute(follow_up)?.collect::<Vec<_>>();
    assert!(matches!(
        follow_up_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}
