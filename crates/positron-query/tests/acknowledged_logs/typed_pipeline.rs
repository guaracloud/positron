use std::error::Error;

use positron_query::{
    OrderDirection, QueryBudget, QueryEvent, QueryFailureCode, QueryService, QueryTerminal,
};

use super::terminal_and_bounds::QueryFixture;

#[test]
fn typed_projection_bytes_obey_the_exact_output_budget() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-projection-bytes")?;
    fixture.kernel.append_log("body-is-not-selected", 20, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source = "pipeline:v1 logs | range query_time -100 100 | project query_time, commit_position | limit 1";

    let exact = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 1, 16, 4, 60)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 1 && stats.output_bytes() == 16
    ));

    let exhausted = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 1, 15, 4, 60)?,
    )?;
    let exhausted_events = service.execute(exhausted)?.collect::<Vec<_>>();
    assert!(
        !exhausted_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        exhausted_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
    ));
    Ok(())
}

#[test]
fn typed_count_bytes_obey_the_exact_output_budget() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-count-bytes")?;
    fixture.kernel.append_log("counted", 20, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source = "pipeline:v1 logs | range query_time -100 100 | aggregate count | limit 1";

    let exact = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 1, 8, 4, 60)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 1 && stats.output_bytes() == 8
    ));

    let exhausted = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 1, 7, 4, 60)?,
    )?;
    let exhausted_events = service.execute(exhausted)?.collect::<Vec<_>>();
    assert!(
        !exhausted_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        exhausted_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
    ));
    Ok(())
}

#[test]
fn result_header_preserves_both_total_order_directions() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-order-header")?;
    fixture.kernel.append_log("ordered", 20, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | order by query_time desc, commit_position asc | limit 1",
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 4, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = match events.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("query header missing".into()),
    };
    assert_eq!(
        header.ordering().columns(),
        ["query_time", "commit_position"]
    );
    assert_eq!(
        header.ordering().directions(),
        [OrderDirection::Descending, OrderDirection::Ascending]
    );
    Ok(())
}

#[test]
fn versioned_pipeline_rejects_operator_combinations_it_cannot_execute() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("typed-operator-combinations")?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?;
    for source in [
        "pipeline:v1 logs | range query_time -100 100 | project body | aggregate count | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | aggregate count | project body | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | aggregate count | order by query_time asc, commit_position asc | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | order by query_time asc, commit_position asc | filter body == \"late\" | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | project body | filter body == \"late\" | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | aggregate count | filter body == \"late\" | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"one\" | search body == \"two\" | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | project body | project query_time | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | aggregate count | aggregate count | limit 1",
    ] {
        let failure = service
            .plan_pipeline(fixture.context, source, budget)
            .err()
            .ok_or("unexecuted operator combination was accepted")?;
        assert_eq!(failure.code(), QueryFailureCode::UnsupportedQuery);
    }
    Ok(())
}

#[test]
fn grouped_count_emits_deterministic_typed_intrinsic_rows() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-grouped-count")?;
    fixture.kernel.append_log("beta", 20, 1)?;
    fixture.kernel.append_log("alpha", 10, 2)?;
    fixture.kernel.append_log("beta", 20, 3)?;
    fixture.kernel.append_log("beta", 10, 4)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 61, 1_024, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = match events.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("query header missing".into()),
    };
    assert_eq!(header.schema().columns(), ["body", "query_time", "count"]);
    assert_eq!(header.ordering().columns(), ["body", "query_time"]);
    assert_eq!(
        header.ordering().directions(),
        [OrderDirection::Ascending, OrderDirection::Ascending]
    );
    let groups = events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .map(|record| {
            (
                record.body_text().map(str::to_owned),
                record.query_time().value(),
                record.count(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        groups,
        [
            (Some("alpha".to_owned()), 10, Some(1)),
            (Some("beta".to_owned()), 10, Some(1)),
            (Some("beta".to_owned()), 20, Some(2)),
        ]
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 3 && stats.output_bytes() == 61
    ));

    let output_exhausted = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 60, 1_024, 60)?,
    )?;
    let output_events = service.execute(output_exhausted)?.collect::<Vec<_>>();
    assert!(
        !output_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        output_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
    ));

    let memory_exhausted = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(228, 16, 16, 61, 1_024, 60)?,
    )?;
    let memory_events = service.execute(memory_exhausted)?.collect::<Vec<_>>();
    assert!(
        !memory_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        memory_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
    ));
    Ok(())
}
