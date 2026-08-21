use std::error::Error;

use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryService, QueryTerminal};

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
