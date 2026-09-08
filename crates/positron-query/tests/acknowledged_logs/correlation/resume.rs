use std::error::Error;

use positron_kernel::{
    CatalogPublicationFault, LedgerFailureCode, SnapshotLeaseId,
    with_catalog_publication_fault_after,
};
use positron_query::{CorrelationOutcome, QueryEvent, QueryFailureCode, QueryTerminal};

use super::super::support::{TestClock, zero_work_clock_service};
use super::super::terminal_and_bounds::QueryFixture;

#[test]
fn correlation_page_cursor_resumes_against_the_original_paired_frontiers()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-cursor")?;
    fixture.kernel.append_trace([0x81; 16], [0x82; 8], 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("first", 20, [0x81; 16], [0x82; 8], 2)?;
    fixture.kernel.append_trace([0x83; 16], [0x84; 8], 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("second", 21, [0x83; 16], [0x84; 8], 4)?;
    let service = fixture.correlation_service(1)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 2",
        super::budget(),
    )?;
    let first = service.execute_page(query)?.collect::<Vec<_>>();
    let cursor = first
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor.clone()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("paired correlation cursor missing")?;
    fixture.kernel.append_trace([0x85; 16], [0x86; 8], 22, 5)?;
    fixture
        .kernel
        .append_log_with_trace("later", 22, [0x85; 16], [0x86; 8], 6)?;
    let resumed = service
        .resume(fixture.context, &cursor)?
        .collect::<Vec<_>>();
    let batch = resumed
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("resumed correlation batch missing")?;
    assert_eq!(batch.records().len(), 1);
    assert_eq!(batch.records()[0].body_text(), Some("second"));
    assert!(matches!(
        resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn correlation_cursor_replays_the_same_paired_batch_after_an_ambiguous_disconnect()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-cursor-replay")?;
    let first_trace = [0x87; 16];
    let first_span = [0x88; 8];
    let second_trace = [0x89; 16];
    let second_span = [0x8a; 8];
    fixture
        .kernel
        .append_trace(first_trace, first_span, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("first", 20, first_trace, first_span, 2)?;
    fixture
        .kernel
        .append_trace(second_trace, second_span, 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("second", 21, second_trace, second_span, 4)?;
    let service = fixture.correlation_service(1)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 2",
        super::budget(),
    )?;
    let initial = service.execute_page(query)?.collect::<Vec<_>>();
    let cursor = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor.clone()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("paired continuation cursor missing")?;

    // Neither source may leak data appended after the cursor's paired snapshot.
    fixture.kernel.append_trace([0x8b; 16], [0x8c; 8], 22, 5)?;
    fixture
        .kernel
        .append_log_with_trace("later", 22, [0x8b; 16], [0x8c; 8], 6)?;

    let mut interrupted = service.resume(fixture.context, &cursor)?;
    assert!(matches!(interrupted.next(), Some(QueryEvent::Header(_))));
    let delivered = match interrupted.next() {
        Some(QueryEvent::Batch(batch)) => batch,
        _ => return Err("interrupted correlation resume did not emit its batch".into()),
    };
    assert_eq!(delivered.records()[0].body_text(), Some("second"));
    assert_eq!(
        delivered.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id: second_trace,
            span_id: Some(second_span),
        })
    );
    drop(interrupted);

    let replay = service
        .resume(fixture.context, &cursor)?
        .collect::<Vec<_>>();
    let replayed = replay
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("replayed correlation batch missing")?;
    assert_eq!(replayed, &delivered);
    assert_eq!(replayed.sequence(), delivered.sequence());
    assert_eq!(replayed.prior_digest(), delivered.prior_digest());
    assert_eq!(replayed.digest(), delivered.digest());
    assert!(matches!(
        replay.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn correlation_cursor_resumes_after_both_signal_stores_reopen() -> Result<(), Box<dyn Error>> {
    let mut fixture = QueryFixture::new("correlation-cursor-restart")?;
    let first_trace = [0x8d; 16];
    let first_span = [0x8e; 8];
    let second_trace = [0x8f; 16];
    let second_span = [0x90; 8];
    fixture
        .kernel
        .append_trace(first_trace, first_span, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("first", 20, first_trace, first_span, 2)?;
    fixture
        .kernel
        .append_trace(second_trace, second_span, 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("second", 21, second_trace, second_span, 4)?;
    let service = fixture.correlation_service(1)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 2",
        super::budget(),
    )?;
    let initial = service.execute_page(query)?.collect::<Vec<_>>();
    let cursor = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor.clone()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("paired continuation cursor missing before restart")?;
    drop(service);

    fixture
        .kernel
        .reopen_ledger()
        .map_err(|error| format!("reopen log ledger: {error}"))?;
    fixture
        .kernel
        .reopen_trace_ledger()
        .map_err(|error| format!("reopen trace ledger: {error}"))?;
    let resumed_service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(101),
    )
    .with_trace_ledger(fixture.kernel.trace_ledger()?);
    let resumed = resumed_service
        .resume(fixture.context, &cursor)
        .map_err(|error| format!("resume after paired restart: {error:?}"))?
        .collect::<Vec<_>>();
    let batch = resumed
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("restarted correlation resume batch missing")?;
    assert_eq!(batch.records()[0].body_text(), Some("second"));
    assert_eq!(
        batch.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id: second_trace,
            span_id: Some(second_span),
        })
    );
    assert!(matches!(
        resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn correlation_target_frontier_cleanup_surfaces_a_release_failure() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-target-frontier-cleanup")?;
    let first_trace = [0xa1; 16];
    let first_span = [0xa2; 8];
    let second_trace = [0xa3; 16];
    let second_span = [0xa4; 8];
    fixture
        .kernel
        .append_trace(first_trace, first_span, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("first", 20, first_trace, first_span, 2)?;
    fixture
        .kernel
        .append_trace(second_trace, second_span, 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("second", 21, second_trace, second_span, 4)?;
    let service = fixture.correlation_service(1)?;
    let plan = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 2",
        super::budget(),
    )?;
    let initial = service.execute_page(plan)?.collect::<Vec<_>>();
    let header = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("initial paired header missing")?;
    let source_lease = SnapshotLeaseId::new(header.lease().identity())?;
    let trace_lease = SnapshotLeaseId::new(
        header
            .correlation_snapshot()
            .ok_or("initial header omitted the trace lease")?
            .trace_lease()
            .identity(),
    )?;
    let cursor = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("initial paired cursor missing")?;
    let tampered = super::rewritten_cursor(&fixture.kernel, cursor, |payload| {
        let trace_frontier_last_byte = 4_511 + 1 + 32 + 8 + 7;
        let byte = payload
            .get_mut(trace_frontier_last_byte)
            .expect("fixed paired cursor trace frontier offset is in bounds");
        *byte ^= 1;
    })?;

    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 2, || {
            service.resume(fixture.context, &tampered)
        })
        .expect_err("target lease cleanup failure must be reported");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .snapshot_lease_usage(source_lease, 100)
            .expect_err("source cleanup must not retain a durable lease")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    assert_eq!(
        fixture
            .kernel
            .trace_ledger()?
            .snapshot_lease_usage(trace_lease, 100)
            .expect_err("target cleanup retry must remove the durable lease")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn correlation_resume_requires_the_complete_authenticated_pair_binding()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-missing-pair-binding")?;
    fixture.kernel.append_trace([0xb1; 16], [0xb2; 8], 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("first", 20, [0xb1; 16], [0xb2; 8], 2)?;
    fixture.kernel.append_trace([0xb3; 16], [0xb4; 8], 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("second", 21, [0xb3; 16], [0xb4; 8], 4)?;
    let service = fixture.correlation_service(1)?;
    let initial = service
        .execute_page(service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 2",
            super::budget(),
        )?)?
        .collect::<Vec<_>>();
    let header = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("paired header missing")?;
    let source_lease = SnapshotLeaseId::new(header.lease().identity())?;
    let cursor = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("paired continuation cursor missing")?;
    let pair_binding_bytes = 1 + 32 + 8 + 8 + 16;
    let pair_binding_start = cursor
        .as_bytes()
        .len()
        .checked_sub(32 + 2 + pair_binding_bytes)
        .ok_or("paired cursor is shorter than its public v6 trailer")?;
    let tampered = super::rewritten_cursor(&fixture.kernel, cursor, |payload| {
        payload
            .get_mut(pair_binding_start..pair_binding_start + pair_binding_bytes)
            .expect("paired cursor binding is present")
            .fill(0)
    })?;

    let failure = service
        .resume(fixture.context, &tampered)
        .expect_err("paired replay must reject an authenticated cursor without its target binding");
    assert_eq!(failure.code(), QueryFailureCode::InvalidCursor);
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .snapshot_lease_usage(source_lease, 100)
            .expect_err("invalid paired replay must release its source lease")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn correlation_resume_releases_both_leases_when_the_target_frontier_binding_changes()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-target-frontier-binding")?;
    fixture.kernel.append_trace([0xb5; 16], [0xb6; 8], 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("first", 20, [0xb5; 16], [0xb6; 8], 2)?;
    fixture.kernel.append_trace([0xb7; 16], [0xb8; 8], 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("second", 21, [0xb7; 16], [0xb8; 8], 4)?;
    let service = fixture.correlation_service(1)?;
    let initial = service
        .execute_page(service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 2",
            super::budget(),
        )?)?
        .collect::<Vec<_>>();
    let header = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("paired header missing")?;
    let source_lease = SnapshotLeaseId::new(header.lease().identity())?;
    let target_lease = SnapshotLeaseId::new(
        header
            .correlation_snapshot()
            .ok_or("paired header omitted trace lease")?
            .trace_lease()
            .identity(),
    )?;
    let cursor = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("paired continuation cursor missing")?;
    let pair_binding_bytes = 1 + 32 + 8 + 8 + 16;
    let pair_binding_start = cursor
        .as_bytes()
        .len()
        .checked_sub(32 + 2 + pair_binding_bytes)
        .ok_or("paired cursor is shorter than its public v6 trailer")?;
    let trace_frontier_last_byte = pair_binding_start + 1 + 32 + 8 + 7;
    let tampered = super::rewritten_cursor(&fixture.kernel, cursor, |payload| {
        let byte = payload
            .get_mut(trace_frontier_last_byte)
            .expect("paired cursor trace frontier is present");
        *byte ^= 1;
    })?;

    let failure = service
        .resume(fixture.context, &tampered)
        .expect_err("paired replay must reject a changed target frontier binding");
    assert_eq!(failure.code(), QueryFailureCode::InvalidCursor);
    for (ledger, identity, name) in [
        (fixture.kernel.ledger()?, source_lease, "source"),
        (fixture.kernel.trace_ledger()?, target_lease, "target"),
    ] {
        assert_eq!(
            ledger
                .snapshot_lease_usage(identity, 100)
                .expect_err("invalid paired replay must release each lease")
                .code(),
            LedgerFailureCode::SnapshotExpired,
            "{name} lease must be released"
        );
    }
    Ok(())
}
