use std::error::Error;

use positron_query::{QueryEvent, QueryFailureCode, QueryTerminal};

use super::super::terminal_and_bounds::QueryFixture;

use super::super::support::{KernelFixture, TestClock, zero_work_clock_service, zero_work_service};
use positron_domain::identity::TenantId;
use positron_kernel::{LedgerFailureCode, ResourceDimension, SnapshotLeaseId, WorkClass};
use positron_query::{CorrelationOutcome, QueryBudget, QueryBudgetDimension};

#[test]
fn correlation_reads_both_authenticated_sources_and_reports_a_missing_log_identifier()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-missing-log-identifier")?;
    fixture.kernel.append_log("accepted", 20, 1)?;
    let service = fixture.correlation_service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        super::budget(),
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    let batch = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("correlation result batch missing")?;
    assert_eq!(batch.records().len(), 1);
    assert_eq!(
        batch.correlation_outcome(0),
        Some(CorrelationOutcome::MissingLogTraceId)
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn correlation_preserves_matched_truth_for_schema_overflow_log_records()
-> Result<(), Box<dyn Error>> {
    let ordinary = QueryFixture::new("correlation-ordinary-representation")?;
    let overflow = QueryFixture::new("correlation-overflow-representation")?;
    let trace_id = [0xa5; 16];
    let span_id = [0xa6; 8];
    ordinary.kernel.append_trace(trace_id, span_id, 20, 1)?;
    ordinary
        .kernel
        .append_log_with_trace("same", 20, trace_id, span_id, 2)?;
    overflow.kernel.append_trace(trace_id, span_id, 20, 1)?;
    let schema = overflow
        .kernel
        .append_schema_overflow_log_with_trace("same", 20, trace_id, span_id, 2)?;
    assert!(schema.catalog().overflow_record_count() > 0);
    assert!(schema.catalog().overflow_byte_count() > 0);
    let source = "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1";
    let ordinary_service = ordinary.correlation_service(16)?;
    let ordinary_events = ordinary_service
        .execute(ordinary_service.plan_pipeline(ordinary.context, source, super::budget())?)?
        .collect::<Vec<_>>();
    let overflow_service = overflow.correlation_service(16)?;
    let overflow_events = overflow_service
        .execute_with_schema(
            overflow_service.plan_pipeline(overflow.context, source, super::budget())?,
            schema.catalog(),
        )?
        .collect::<Vec<_>>();
    let outcome =
        |events: &[QueryEvent]| -> Result<(Option<String>, CorrelationOutcome), Box<dyn Error>> {
            let batch = events
                .iter()
                .find_map(|event| match event {
                    QueryEvent::Batch(batch) => Some(batch),
                    QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
                })
                .ok_or("correlation batch missing")?;
            Ok((
                batch.records()[0].body_text().map(str::to_owned),
                batch
                    .correlation_outcome(0)
                    .ok_or("correlation outcome missing")?,
            ))
        };
    assert_eq!(outcome(&overflow_events)?, outcome(&ordinary_events)?);
    Ok(())
}

#[test]
fn correlation_rejects_target_scope_and_tenant_before_snapshot_admission()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-target-authorization")?;
    let source = "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1";
    let baseline = fixture.kernel.authority.governor().inspect()?;
    let wrong_scope = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    )
    .with_trace_ledger(fixture.kernel.ledger()?);
    let wrong_scope_query = wrong_scope.plan_pipeline(fixture.context, source, super::budget())?;
    assert_eq!(
        wrong_scope
            .execute(wrong_scope_query)
            .expect_err("a Log Store cannot be admitted as a trace target")
            .code(),
        QueryFailureCode::MalformedPersistentData
    );

    let foreign_tenant = TenantId::from_bytes([0xaf; 16])?;
    let foreign = KernelFixture::new(foreign_tenant, "correlation-foreign-target")?;
    let wrong_tenant = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    )
    .with_trace_ledger(foreign.trace_ledger()?);
    let wrong_tenant_query =
        wrong_tenant.plan_pipeline(fixture.context, source, super::budget())?;
    assert_eq!(
        wrong_tenant
            .execute(wrong_tenant_query)
            .expect_err("a foreign tenant trace target must be rejected")
            .code(),
        QueryFailureCode::Unauthorized
    );
    assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);
    Ok(())
}

#[test]
fn correlation_cursor_expiry_rejects_both_paired_snapshot_leases() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-paired-expiry")?;
    let trace_id = [0xa7; 16];
    let span_id = [0xa8; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, span_id, 2)?;
    fixture.kernel.append_trace([0xa9; 16], [0xaa; 8], 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("later", 21, [0xa9; 16], [0xaa; 8], 4)?;
    let clock = TestClock::shared(100);
    let service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        clock.clone(),
    )
    .with_trace_ledger(fixture.kernel.trace_ledger()?);
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
        .ok_or("paired expiry header missing")?;
    let source_lease = SnapshotLeaseId::new(header.lease().identity())?;
    let trace_lease = SnapshotLeaseId::new(
        header
            .correlation_snapshot()
            .ok_or("paired expiry header omitted trace provenance")?
            .trace_lease()
            .identity(),
    )?;
    let cursor = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("paired expiry cursor missing")?;
    clock.set(161);
    assert_eq!(
        service
            .resume(fixture.context, cursor)
            .expect_err("expired paired cursor must not admit either source")
            .code(),
        QueryFailureCode::SnapshotExpired
    );
    for (ledger, identity) in [
        (fixture.kernel.ledger()?, source_lease),
        (fixture.kernel.trace_ledger()?, trace_lease),
    ] {
        assert_eq!(
            ledger
                .snapshot_lease_usage(identity, 161)
                .expect_err("expired paired lease must remain unavailable")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
    }
    Ok(())
}

#[test]
fn correlation_memory_refusal_has_no_batch_and_an_admitted_batch_keeps_its_outcome_after_stream_drop()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-memory")?;
    let trace_id = [0x91; 16];
    let span_id = [0x92; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, span_id, 2)?;
    let service = fixture.correlation_service(16)?;
    let source = "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1";
    let baseline = fixture.kernel.authority.governor().inspect()?;

    let too_small = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 512, 60)?;
    let query = service.plan_pipeline(fixture.context, source, too_small)?;
    let refused = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(refused.first(), Some(QueryEvent::Header(_))));
    assert!(
        !refused
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        refused.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::BudgetExhausted
                && failure.stats().limiting_budget() == Some(QueryBudgetDimension::MemoryBytes)
    ));
    assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);

    let query = service.plan_pipeline(fixture.context, source, super::budget())?;
    let mut stream = service.execute(query)?;
    assert!(matches!(stream.next(), Some(QueryEvent::Header(_))));
    let batch = match stream.next() {
        Some(QueryEvent::Batch(batch)) => batch,
        _ => return Err("admitted correlation query did not return a batch".into()),
    };
    let retained = batch.clone();
    drop(stream);
    let held = fixture.kernel.authority.governor().inspect()?;
    assert_eq!(
        held.outstanding_for(WorkClass::InteractiveQueryTail),
        baseline.outstanding_for(WorkClass::InteractiveQueryTail) + 1
    );
    assert!(
        held.usage(ResourceDimension::MemoryBytes) > baseline.usage(ResourceDimension::MemoryBytes)
    );
    assert_eq!(
        retained.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id,
            span_id: Some(span_id),
        })
    );
    drop(batch);
    assert_eq!(fixture.kernel.authority.governor().inspect()?, held);
    drop(retained);
    assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);
    Ok(())
}

#[test]
fn correlation_cancellation_releases_both_paired_snapshot_leases() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-cancel-release")?;
    let trace_id = [0x99; 16];
    let span_id = [0x9a; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, span_id, 2)?;
    let service = fixture.correlation_service(16)?;
    let baseline = fixture.kernel.authority.governor().inspect()?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        super::budget(),
    )?;

    let mut stream = service.execute(query)?;
    let header = match stream.next() {
        Some(QueryEvent::Header(header)) => header,
        Some(QueryEvent::Batch(_) | QueryEvent::Terminal(_)) | None => {
            return Err("correlation query did not return its paired header".into());
        },
    };
    let source_lease = SnapshotLeaseId::new(header.lease().identity())?;
    let trace_lease = SnapshotLeaseId::new(
        header
            .correlation_snapshot()
            .ok_or("correlation header omitted the trace lease")?
            .trace_lease()
            .identity(),
    )?;
    stream.cancel()?;
    assert!(matches!(
        stream.next(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
    ));
    assert!(stream.next().is_none());
    drop(stream);
    assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .snapshot_lease_usage(source_lease, 100)
            .expect_err("cancelling must release the source snapshot lease")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    assert_eq!(
        fixture
            .kernel
            .trace_ledger()?
            .snapshot_lease_usage(trace_lease, 100)
            .expect_err("cancelling must release the trace snapshot lease")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}
