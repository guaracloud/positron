use std::error::Error;

use positron_kernel::{LedgerFailureCode, SnapshotLeaseId};
use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryService, QueryTerminal};

use super::support::TestClock;
use super::terminal_and_bounds::QueryFixture;

#[test]
fn sequential_non_resumable_completion_reclaims_every_snapshot_lease() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("lease-reclaim")?;
    let clock = TestClock::shared(100);
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        clock,
    );
    for _ in 0..65 {
        let query = service.plan_pipeline(
            fixture.context,
            "logs | range query_time -100 100 | limit 1",
            budget(),
        )?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        let header = match events.first() {
            Some(QueryEvent::Header(header)) => header,
            _ => return Err("query header missing".into()),
        };
        assert!(header.initial_cursor().is_none());
        let identity = SnapshotLeaseId::new(header.lease().identity())?;
        assert_eq!(
            fixture
                .kernel
                .ledger()?
                .resume_snapshot_lease(identity, 100)
                .expect_err("non-resumable terminal releases promptly")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
    }
    Ok(())
}

#[test]
fn paged_drop_retains_only_after_a_resume_cursor_is_delivered() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("paged-drop")?;
    fixture.kernel.append_log("one", 20, 1)?;
    fixture.kernel.append_log("two", 21, 2)?;
    let clock = TestClock::shared(100);
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        clock,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 2",
        budget(),
    )?;
    let mut stream = service.execute_page(query)?;
    let cursor = match stream.next() {
        Some(QueryEvent::Header(header)) => header
            .initial_cursor()
            .ok_or("paged header omitted resume cursor")?
            .clone(),
        _ => return Err("paged header missing".into()),
    };
    drop(stream);
    let resumed = service
        .resume(fixture.context, &cursor)?
        .collect::<Vec<_>>();
    assert!(
        resumed
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    Ok(())
}

#[test]
fn paged_drop_before_header_delivery_reclaims_every_snapshot_lease() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("paged-drop-before-header")?;
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
    );
    for _ in 0..65 {
        let query = service.plan_pipeline(
            fixture.context,
            "logs | range query_time -100 100 | limit 1",
            budget(),
        )?;
        drop(service.execute_page(query)?);
    }
    Ok(())
}

#[test]
fn observed_paged_completion_reclaims_every_snapshot_lease() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("paged-complete-reclaim")?;
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
    );
    for _ in 0..65 {
        let query = service.plan_pipeline(
            fixture.context,
            "logs | range query_time -100 100 | limit 1",
            budget(),
        )?;
        let events = service.execute_page(query)?.collect::<Vec<_>>();
        assert!(matches!(
            events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
        ));
    }
    Ok(())
}

#[test]
fn paged_drop_after_batch_before_terminal_replays_the_same_batch() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("paged-batch-ambiguity")?;
    fixture.kernel.append_log("one", 20, 1)?;
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    let mut stream = service.execute_page(query)?;
    let cursor = match stream.next() {
        Some(QueryEvent::Header(header)) => header
            .initial_cursor()
            .ok_or("paged header omitted resume cursor")?
            .clone(),
        _ => return Err("paged header missing".into()),
    };
    let original = match stream.next() {
        Some(QueryEvent::Batch(batch)) => (batch.sequence(), batch.digest()),
        _ => return Err("paged batch missing".into()),
    };
    drop(stream);

    let replayed = service
        .resume(fixture.context, &cursor)?
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some((batch.sequence(), batch.digest())),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("replayed batch missing")?;
    assert_eq!(replayed, original);
    Ok(())
}

#[test]
fn observed_paged_completion_makes_its_cursor_unavailable() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("paged-complete-terminal")?;
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    let events = service.execute_page(query)?.collect::<Vec<_>>();
    let cursor = match events.first() {
        Some(QueryEvent::Header(header)) => header
            .initial_cursor()
            .ok_or("paged header omitted resume cursor")?,
        _ => return Err("paged header missing".into()),
    };
    assert_eq!(
        service
            .resume(fixture.context, cursor)
            .expect_err("observed completion releases its snapshot lease")
            .code(),
        QueryFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn observed_paged_incomplete_is_terminal_and_not_resumable() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("paged-incomplete-terminal")?;
    fixture.kernel.append_log("one", 20, 1)?;
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget().with_cpu_work_units(2)?,
    )?;
    let events = service.execute_page(query)?.collect::<Vec<_>>();
    let cursor = match events.first() {
        Some(QueryEvent::Header(header)) => header
            .initial_cursor()
            .ok_or("paged header omitted resume cursor")?,
        _ => return Err("paged header missing".into()),
    };
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
    ));
    assert_eq!(
        service
            .resume(fixture.context, cursor)
            .expect_err("incomplete terminal releases its snapshot lease")
            .code(),
        QueryFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn cancellation_reports_only_delivered_batches_and_releases_idempotently()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("cancel-truth")?;
    fixture.kernel.append_log("one", 20, 1)?;
    fixture.kernel.append_log("two", 21, 2)?;
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 2",
        budget(),
    )?;
    let before_batch_cancellation = query.cancellation();
    let mut before_batch = service.execute_page(query)?;
    assert!(matches!(before_batch.next(), Some(QueryEvent::Header(_))));
    before_batch.cancel()?;
    assert!(before_batch_cancellation.is_cancelled());
    assert!(matches!(
        before_batch.next(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
                && incomplete.stats().records() == 0
                && incomplete.stats().scanned_bytes() == 0
                && incomplete.stats().last_sequence().is_none()
                && incomplete.stats().result_digest() == [0; 32]
    ));

    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 2",
        budget(),
    )?;
    let after_batch_cancellation = query.cancellation();
    let mut after_batch = service.execute_page(query)?;
    assert!(matches!(after_batch.next(), Some(QueryEvent::Header(_))));
    let (digest, output_bytes) = match after_batch.next() {
        Some(QueryEvent::Batch(batch)) => (
            batch.digest(),
            batch
                .records()
                .first()
                .and_then(|record| record.body_text())
                .unwrap_or_default()
                .len(),
        ),
        _ => return Err("result batch missing".into()),
    };
    after_batch.cancel()?;
    assert!(after_batch_cancellation.is_cancelled());
    assert!(matches!(
        after_batch.next(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
                && incomplete.stats().records() == 1
                && incomplete.stats().scanned_bytes() > 0
                && incomplete.stats().decoded_records() == 2
                && incomplete.stats().output_bytes() == u64::try_from(output_bytes)?
                && incomplete.stats().cpu_work_units() == 4
                && incomplete.stats().wall_seconds() == 0
                && incomplete.stats().last_sequence() == Some(0)
                && incomplete.stats().result_digest() == digest
    ));
    after_batch.cancel()?;
    assert!(after_batch.next().is_none());

    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 2",
        budget(),
    )?;
    let disconnect = query.cancellation();
    drop(service.execute_page(query)?);
    assert!(disconnect.is_cancelled());
    Ok(())
}

fn budget() -> QueryBudget {
    QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)
        .and_then(|budget| budget.with_cpu_work_units(16))
        .expect("fixture budget")
}
