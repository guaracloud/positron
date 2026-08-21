use std::error::Error;
use std::sync::Arc;

use positron_kernel::{SnapshotLeaseId, WorkClass};
use positron_query::{
    OrderDirection, QueryBudget, QueryEvent, QueryFailureCode, QueryService, QueryTerminal,
};

use super::support::{
    BlockingOperatorWorkMeter, CancellingStageWorkMeter, SequenceClock, TestClock,
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
        QueryBudget::new(1_048_576, 16, 16, 61, 1_024, 60)?.with_cpu_work_units(16)?,
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
        QueryBudget::new(1_048_576, 16, 16, 60, 1_024, 60)?.with_cpu_work_units(16)?,
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
        QueryBudget::new(228, 16, 16, 61, 1_024, 60)?.with_cpu_work_units(16)?,
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

    let work_exhausted = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 61, 1_024, 60)?.with_cpu_work_units(5)?,
    )?;
    let work_events = service.execute(work_exhausted)?.collect::<Vec<_>>();
    assert!(
        !work_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        work_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().cpu_work_units() == 6
    ));

    let commit_groups = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by commit_position | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 64, 1_024, 60)?.with_cpu_work_units(16)?,
    )?;
    let commit_events = service.execute(commit_groups)?.collect::<Vec<_>>();
    let commit_header = match commit_events.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("commit grouping header missing".into()),
    };
    assert_eq!(
        commit_header.schema().columns(),
        ["commit_position", "count"]
    );
    assert_eq!(commit_header.ordering().columns(), ["commit_position"]);
    assert_eq!(
        commit_events
            .iter()
            .filter_map(|event| match event {
                QueryEvent::Batch(batch) => Some(batch.records()),
                QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
            })
            .flatten()
            .filter(|record| record.count() == Some(1))
            .count(),
        4
    );
    assert!(matches!(
        commit_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 4 && stats.output_bytes() == 64
    ));
    Ok(())
}

#[test]
fn cancellation_interrupts_grouping_and_releases_query_resources() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-group-cancellation")?;
    for identity in 1_u8..=8 {
        fixture
            .kernel
            .append_log(&format!("group-{identity}"), i64::from(identity), identity)?;
    }
    let meter = BlockingOperatorWorkMeter::shared(4);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        8,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let before = fixture
        .kernel
        .authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 8",
        QueryBudget::new(1_048_576, 8, 8, 1_048_576, 1_024, 60)?.with_cpu_work_units(16)?,
    )?;
    let cancellation = query.cancellation();
    assert_eq!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before + 1
    );

    let events = std::thread::scope(|scope| -> Result<_, Box<dyn Error>> {
        let service = &service;
        let worker = scope.spawn(move || service.execute(query).map(Iterator::collect::<Vec<_>>));
        meter.wait_until_blocked()?;
        cancellation.cancel();
        meter.release()?;
        worker
            .join()
            .map_err(|_| "query execution thread panicked")?
            .map_err(Into::into)
    })?;
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, QueryEvent::Terminal(_)))
            .count(),
        1
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
    ));
    assert_eq!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before
    );
    let lease = events.iter().find_map(|event| match event {
        QueryEvent::Header(header) => Some(header.lease().identity()),
        QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
    });
    let lease = SnapshotLeaseId::new(lease.ok_or("cancelled query header missing")?)?;
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .resume_snapshot_lease(lease, 100)
            .expect_err("cancelled execution must release its snapshot lease")
            .code(),
        positron_kernel::LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn cancellation_is_observed_after_scan_and_before_output_construction() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("typed-stage-cancellation")?;
    fixture.kernel.append_log("one", 20, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 3, 1_024, 60)?,
    )?;
    query.cancellation().cancel();
    assert_eq!(
        service
            .execute(query)
            .expect_err("pre-cancelled query must not acquire execution resources")
            .code(),
        QueryFailureCode::Cancelled
    );

    for stage in [
        positron_query::QueryWorkStage::ScanDecode,
        positron_query::QueryWorkStage::Output,
    ] {
        let meter = CancellingStageWorkMeter::shared(stage);
        let service = QueryService::with_runtime(
            fixture.kernel.authority.governor(),
            fixture.kernel.ledger()?,
            1,
            TestClock::shared(100),
            Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
        );
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | project query_time | limit 1",
            QueryBudget::new(1_048_576, 1, 1, 8, 1_024, 60)?,
        )?;
        meter.bind(query.cancellation())?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, QueryEvent::Terminal(_)))
                .count(),
            1
        );
        assert!(matches!(
            events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::Cancelled
                    && incomplete.stats().records() == 0
                    && incomplete.stats().output_bytes() == 0
        ));
    }
    Ok(())
}

#[test]
fn operator_wall_budget_is_checked_before_output() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-operator-wall")?;
    fixture.kernel.append_log("one", 20, 1)?;
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        SequenceClock::shared([100, 100, 100, 100, 100, 160]),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"one\" | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 3, 1_024, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().wall_seconds() == 60
    ));
    Ok(())
}
