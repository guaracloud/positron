use std::error::Error;

use positron_kernel::{
    CatalogPublicationFault, LedgerFailureCode, SnapshotLeaseId,
    with_catalog_publication_fault_after,
};
use positron_query::{QueryEvent, QueryFailureCode, QueryTerminal};

use super::super::support::{TestClock, zero_work_clock_service};
use super::super::terminal_and_bounds::QueryFixture;

#[test]
fn correlation_resume_rejects_an_authenticated_unrepresentable_source_frontier()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-source-frontier-overflow")?;
    for (trace_id, span_id, time, identity, body) in [
        ([0xc1; 16], [0xc2; 8], 20, 1, "first"),
        ([0xc3; 16], [0xc4; 8], 21, 3, "second"),
    ] {
        fixture
            .kernel
            .append_trace(trace_id, span_id, time, identity)?;
        fixture
            .kernel
            .append_log_with_trace(body, time, trace_id, span_id, identity + 1)?;
    }
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
    // The v6 source frontier follows magic, authentication epoch, principal,
    // tenant, authorization generation, catalog identity, and catalog generation.
    const SOURCE_FRONTIER_START: usize = 8 + 8 + 16 + 16 + 8 + 32 + 8;
    let tampered = super::rewritten_cursor(&fixture.kernel, cursor, |payload| {
        payload
            .get_mut(SOURCE_FRONTIER_START..SOURCE_FRONTIER_START + 8)
            .expect("paired cursor source frontier is present")
            .copy_from_slice(&u64::MAX.to_be_bytes());
    })?;
    drop(initial);

    let failure = service
        .resume(fixture.context, &tampered)
        .expect_err("authenticated overflow frontier must fail during paired replay");
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

#[test]
fn correlation_source_frontier_cleanup_retains_only_a_failed_target_release()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-source-frontier-target-release")?;
    for (trace_id, span_id, time, identity, body) in [
        ([0xd1; 16], [0xd2; 8], 20, 1, "first"),
        ([0xd3; 16], [0xd4; 8], 21, 3, "second"),
    ] {
        fixture
            .kernel
            .append_trace(trace_id, span_id, time, identity)?;
        fixture
            .kernel
            .append_log_with_trace(body, time, trace_id, span_id, identity + 1)?;
    }
    let baseline = fixture.kernel.authority.governor().inspect()?;
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
    // See the previous test for the v6 source-frontier field derivation.
    const SOURCE_FRONTIER_START: usize = 8 + 8 + 16 + 16 + 8 + 32 + 8;
    let tampered = super::rewritten_cursor(&fixture.kernel, cursor, |payload| {
        payload
            .get_mut(SOURCE_FRONTIER_START..SOURCE_FRONTIER_START + 8)
            .expect("paired cursor source frontier is present")
            .copy_from_slice(&u64::MAX.to_be_bytes());
    })?;
    drop(initial);
    // Source marker admission publishes first; the next publication is the
    // unresumed trace lease release. The source cleanup must still proceed.
    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 1, || {
            service.resume(fixture.context, &tampered)
        })
        .expect_err("failed target release must strengthen the semantic cursor failure");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .snapshot_lease_usage(source_lease, 100)
            .expect_err("source cleanup must complete despite target release failure")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    assert!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_total()
            > baseline.outstanding_total(),
        "only the target's kernel-pending release may retain bounded ownership"
    );

    let recovery_service = fixture.correlation_service(1)?;
    let recovery = recovery_service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        super::budget(),
    )?;
    let drain = recovery_service
        .execute_page(recovery)
        .expect_err("first paired admission drains the pending trace release");
    assert_eq!(drain.code(), QueryFailureCode::StoreUnavailable);
    let recovered = recovery_service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        super::budget(),
    )?;
    let recovered_events = recovery_service
        .execute_page(recovered)?
        .collect::<Vec<_>>();
    assert!(matches!(
        recovered_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    drop(recovered_events);
    assert_eq!(
        fixture
            .kernel
            .trace_ledger()?
            .snapshot_lease_usage(target_lease, 100)
            .expect_err("later paired admission must drain the pending target release")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);
    Ok(())
}

#[test]
fn correlation_source_frontier_cleanup_does_not_release_through_a_log_store_target()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-source-frontier-wrong-target")?;
    for (trace_id, span_id, time, identity, body) in [
        ([0xe1; 16], [0xe2; 8], 20, 1, "first"),
        ([0xe3; 16], [0xe4; 8], 21, 3, "second"),
    ] {
        fixture
            .kernel
            .append_trace(trace_id, span_id, time, identity)?;
        fixture
            .kernel
            .append_log_with_trace(body, time, trace_id, span_id, identity + 1)?;
    }
    let initial_service = fixture.correlation_service(1)?;
    let initial = initial_service
        .execute_page(initial_service.plan_pipeline(
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
    const SOURCE_FRONTIER_START: usize = 8 + 8 + 16 + 16 + 8 + 32 + 8;
    let tampered = super::rewritten_cursor(&fixture.kernel, cursor, |payload| {
        payload
            .get_mut(SOURCE_FRONTIER_START..SOURCE_FRONTIER_START + 8)
            .expect("paired cursor source frontier is present")
            .copy_from_slice(&u64::MAX.to_be_bytes());
    })?;
    drop(initial);
    let wrong_target_service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
    )
    .with_trace_ledger(fixture.kernel.ledger()?);

    let failure = wrong_target_service
        .resume(fixture.context, &tampered)
        .expect_err("a Log Store must not be used to release a paired trace lease");
    assert_eq!(failure.code(), QueryFailureCode::InvalidCursor);
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .snapshot_lease_usage(source_lease, 100)
            .expect_err("source lease must still clean up")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    assert!(
        fixture
            .kernel
            .trace_ledger()?
            .snapshot_lease_usage(target_lease, 100)
            .is_ok(),
        "wrong target authority must leave the trace lease untouched"
    );
    fixture
        .kernel
        .trace_ledger()?
        .release_snapshot_lease(target_lease)?;
    Ok(())
}
