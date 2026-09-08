use std::error::Error;
use std::sync::Arc;

use positron_domain::identity::TenantId;
use positron_kernel::{
    CatalogPublicationFault, LedgerFailureCode, ResourceDimension, SnapshotLeaseId, WorkClass,
    with_catalog_publication_fault_after, with_catalog_publication_fault_sequence_after,
    with_catalog_publication_hook_after,
};
use positron_query::{
    CorrelationOutcome, QueryBudget, QueryBudgetDimension, QueryEvent, QueryFailureCode,
    QueryService, QueryTerminal,
};

use super::super::support::{
    CancellingOperatorCallMeter, KernelFixture, MergeWorkMeter, TestClock,
    publish_lifecycle_at_catalog_for_test, zero_work_clock_service, zero_work_service,
};
use super::super::terminal_and_bounds::QueryFixture;

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

#[test]
fn correlation_target_release_failure_is_terminal_and_retries_on_drop() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("correlation-target-release-retry")?;
    let trace_id = [0x9b; 16];
    let span_id = [0x9c; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, span_id, 2)?;
    let service = fixture.correlation_service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        super::budget(),
    )?;
    let mut stream = service.execute_page(query)?;
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

    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            stream.cancel()
        })
        .expect_err("target lease release failure must be reported to the client");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert!(matches!(
        stream.next(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::StoreUnavailable
    ));
    assert!(stream.next().is_none());
    drop(stream);
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .snapshot_lease_usage(source_lease, 100)
            .expect_err("source lease must be released despite target failure")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    assert_eq!(
        fixture
            .kernel
            .trace_ledger()?
            .snapshot_lease_usage(trace_lease, 100)
            .expect_err("drop must retry the failed target release")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn correlation_source_release_failure_is_terminal_and_retries_on_drop() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("correlation-source-release-retry")?;
    let trace_id = [0x97; 16];
    let span_id = [0x98; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, span_id, 2)?;
    let service = fixture.correlation_service(16)?;
    let mut stream = service.execute_page(service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        super::budget(),
    )?)?;
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
    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 1, || {
            stream.cancel()
        })
        .expect_err("source release failure must be reported after target release");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert!(matches!(
        stream.next(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::StoreUnavailable
    ));
    drop(stream);
    for (ledger, lease) in [
        (fixture.kernel.ledger()?, source_lease),
        (fixture.kernel.trace_ledger()?, trace_lease),
    ] {
        assert_eq!(
            ledger
                .snapshot_lease_usage(lease, 100)
                .expect_err("drop must release each paired lease")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
    }
    Ok(())
}

#[test]
fn correlation_target_admission_failure_releases_the_already_admitted_log_lease()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-target-admission-cleanup")?;
    let service = fixture.correlation_service(1)?;
    let baseline = fixture.kernel.authority.governor().inspect()?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        super::budget(),
    )?;

    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 1, || {
            service.execute_page(query)
        })
        .expect_err("target lease admission must report its publication failure");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);
    Ok(())
}

#[test]
fn correlation_sequential_target_admission_failure_releases_the_log_lease()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-sequential-target-admission-cleanup")?;
    let service = fixture.correlation_service(1)?;
    let baseline = fixture.kernel.authority.governor().inspect()?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        super::budget(),
    )?;

    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 1, || {
            service.execute(query)
        })
        .expect_err("sequential target lease admission must report its publication failure");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);
    Ok(())
}

#[test]
fn correlation_target_admission_retains_failed_source_cleanup_until_later_lease_activity()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-target-admission-cleanup-failure")?;
    let service = fixture.correlation_service(1)?;
    let baseline = fixture.kernel.authority.governor().inspect()?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        super::budget(),
    )?;

    let failure = with_catalog_publication_fault_sequence_after(
        &[
            (CatalogPublicationFault::SynchronizeCommit, 1),
            (CatalogPublicationFault::SynchronizeCommit, 0),
        ],
        || service.execute_page(query),
    )
    .expect_err("target admission and source cleanup failure must be surfaced");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);

    let retained = fixture.kernel.authority.governor().inspect()?;
    assert!(
        retained.outstanding_total() > baseline.outstanding_total(),
        "the failed release must retain its bounded durable reservation until the ledger retries it"
    );

    let recovery_service = fixture.service(1)?;
    let recovery = recovery_service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        super::budget(),
    )?;
    let drain_failure = recovery_service
        .execute_page(recovery)
        .expect_err("the first later admission must report the catalog change while draining");
    assert_eq!(drain_failure.code(), QueryFailureCode::StoreUnavailable);

    let recovered = recovery_service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        super::budget(),
    )?;
    drop(recovery_service.execute_page(recovered)?);
    assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);
    Ok(())
}

#[test]
fn correlation_requires_a_trace_target_before_either_execution_mode_admits_resources()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-missing-target")?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    let baseline = fixture.kernel.authority.governor().inspect()?;
    let source = "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1";

    let sequential = service.plan_pipeline(fixture.context, source, super::budget())?;
    assert_eq!(
        service
            .execute(sequential)
            .expect_err("sequential correlation must require a trace target")
            .code(),
        QueryFailureCode::StoreUnavailable
    );
    let paged = service.plan_pipeline(fixture.context, source, super::budget())?;
    assert_eq!(
        service
            .execute_page(paged)
            .expect_err("paged correlation must require a trace target")
            .code(),
        QueryFailureCode::StoreUnavailable
    );
    assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);
    Ok(())
}

#[test]
fn correlation_resume_rechecks_authorization_after_the_log_marker_is_admitted()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-resume-reauthorize")?;
    let trace_id = [0x91; 16];
    let span_id = [0x92; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("first", 20, trace_id, span_id, 2)?;
    fixture.kernel.append_trace([0x93; 16], [0x94; 8], 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("second", 21, [0x93; 16], [0x94; 8], 4)?;
    let service = fixture.correlation_service(1)?;
    let initial = service
        .execute_page(service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 2",
            super::budget(),
        )?)?
        .collect::<Vec<_>>();
    let cursor = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("paired continuation cursor missing")?;

    let failure = with_catalog_publication_hook_after(
        0,
        |catalog| {
            publish_lifecycle_at_catalog_for_test(catalog, 3, 0xd8)
                .expect("lifecycle revocation after source marker admission");
        },
        || service.resume(fixture.context, cursor),
    )
    .expect_err("authorization revocation after source marker admission must reject replay");
    assert_eq!(failure.code(), QueryFailureCode::AuthorizationChanged);
    Ok(())
}

#[test]
fn correlation_resume_rejects_a_missing_target_lease_and_releases_the_log_lease()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-missing-target-lease")?;
    let trace_id = [0x8d; 16];
    let span_id = [0x8e; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("first", 20, trace_id, span_id, 2)?;
    fixture.kernel.append_trace([0x8f; 16], [0x90; 8], 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("second", 21, [0x8f; 16], [0x90; 8], 4)?;
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
        .ok_or("paired cursor header missing")?;
    let source_lease = SnapshotLeaseId::new(header.lease().identity())?;
    let target_lease = SnapshotLeaseId::new(
        header
            .correlation_snapshot()
            .ok_or("paired cursor omitted trace lease")?
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
    fixture
        .kernel
        .trace_ledger()?
        .release_snapshot_lease(target_lease)?;

    let failure = service
        .resume(fixture.context, cursor)
        .expect_err("a missing target lease must fence paired replay");
    assert_eq!(failure.code(), QueryFailureCode::SnapshotExpired);
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .snapshot_lease_usage(source_lease, 100)
            .expect_err("failed paired replay must release the source lease")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn correlation_resume_without_a_target_service_releases_the_log_lease() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("correlation-resume-without-target-service")?;
    let trace_id = [0x8b; 16];
    let span_id = [0x8c; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("first", 20, trace_id, span_id, 2)?;
    fixture.kernel.append_trace([0x8d; 16], [0x8e; 8], 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("second", 21, [0x8d; 16], [0x8e; 8], 4)?;
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
        .ok_or("paired cursor header missing")?;
    let source_lease = SnapshotLeaseId::new(header.lease().identity())?;
    let cursor = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("paired continuation cursor missing")?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );

    let failure = service
        .resume(fixture.context, cursor)
        .expect_err("paired resume must require the original trace target service");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .snapshot_lease_usage(source_lease, 100)
            .expect_err("failed paired resume must release the source lease")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn correlation_resume_rejects_a_non_trace_target_service_and_releases_the_log_lease()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-resume-wrong-target-service")?;
    let trace_id = [0x89; 16];
    let span_id = [0x8a; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("first", 20, trace_id, span_id, 2)?;
    fixture.kernel.append_trace([0x8b; 16], [0x8c; 8], 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("second", 21, [0x8b; 16], [0x8c; 8], 4)?;
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
        .ok_or("paired cursor header missing")?;
    let source_lease = SnapshotLeaseId::new(header.lease().identity())?;
    let cursor = initial
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("paired continuation cursor missing")?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    )
    .with_trace_ledger(fixture.kernel.ledger()?);

    let failure = service
        .resume(fixture.context, cursor)
        .expect_err("paired resume must reject a Log Store target service");
    assert_eq!(failure.code(), QueryFailureCode::Unauthorized);
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .snapshot_lease_usage(source_lease, 100)
            .expect_err("failed paired resume must release the source lease")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn correlation_outcome_bytes_participate_in_the_public_output_budget() -> Result<(), Box<dyn Error>>
{
    let matched = QueryFixture::new("correlation-output-matched")?;
    let trace_id = [0x93; 16];
    let span_id = [0x94; 8];
    matched.kernel.append_trace(trace_id, span_id, 20, 1)?;
    matched
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, span_id, 2)?;
    let source = "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1";
    let output_budget = QueryBudget::new(1_048_576, 16, 16, 32, 1_048_576, 60)?;
    let service = matched.correlation_service(16)?;
    let query = service.plan_pipeline(matched.context, source, output_budget)?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.stats().limiting_budget() == Some(QueryBudgetDimension::OutputBytes)
    ));

    let missing = QueryFixture::new("correlation-output-missing")?;
    missing.kernel.append_log("accepted", 20, 1)?;
    let service = missing.correlation_service(16)?;
    let query = service.plan_pipeline(missing.context, source, output_budget)?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn correlation_target_scan_consumes_the_same_cumulative_decode_budget_as_the_log_source()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-target-cumulative-budget")?;
    let first_trace = [0x95; 16];
    let first_span = [0x96; 8];
    let second_trace = [0x97; 16];
    let second_span = [0x98; 8];
    fixture
        .kernel
        .append_trace(first_trace, first_span, 20, 1)?;
    fixture
        .kernel
        .append_trace(second_trace, second_span, 21, 2)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, first_trace, first_span, 3)?;
    let service = fixture.correlation_service(16)?;
    let budget = QueryBudget::new(1_048_576, 2, 16, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        budget,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(
        matches!(
            events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::BudgetExhausted
                    && incomplete.stats().limiting_budget() == Some(QueryBudgetDimension::DecodedRecords)
                    && incomplete.stats().decoded_records() == 2
        ),
        "unexpected correlation budget events: {events:?}"
    );
    Ok(())
}

#[test]
fn correlation_target_scan_exhaustion_frames_one_incomplete_terminal_before_log_delivery()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-target-scan-exhaustion")?;
    fixture.kernel.append_trace([0x99; 16], [0x9a; 8], 20, 1)?;
    fixture.kernel.append_trace([0x9b; 16], [0x9c; 8], 21, 2)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, [0x99; 16], [0x9a; 8], 3)?;
    let service = fixture.correlation_service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        QueryBudget::new(1_048_576, 1, 16, 1_048_576, 1_048_576, 60)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_))),
        "target scan exhaustion must not expose a log-only prefix: {events:?}"
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget() == Some(QueryBudgetDimension::DecodedRecords)
                && incomplete.stats().decoded_records() == 1
    ));
    Ok(())
}

#[test]
fn correlation_target_traversal_charges_cpu_work_before_a_target_heavy_result_is_emitted()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-target-cpu-budget")?;
    let matched_trace = [0xb1; 16];
    let matched_span = [0xb2; 8];
    for (trace, span, position) in [
        ([0xb3; 16], [0xb4; 8], 1),
        ([0xb5; 16], [0xb6; 8], 2),
        (matched_trace, matched_span, 3),
    ] {
        fixture.kernel.append_trace(trace, span, 20, position)?;
    }
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, matched_trace, matched_span, 4)?;
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
        Arc::new(MergeWorkMeter),
    )
    .with_trace_ledger(fixture.kernel.trace_ledger()?);
    let budget =
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(2)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        budget,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget() == Some(QueryBudgetDimension::CpuWorkUnits)
    ));
    Ok(())
}

#[test]
fn correlation_target_traversal_rechecks_cancellation_and_releases_query_resources()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-target-cancel")?;
    let matched_trace = [0xc1; 16];
    let matched_span = [0xc2; 8];
    for (trace, span, position) in [
        ([0xc3; 16], [0xc4; 8], 1),
        ([0xc5; 16], [0xc6; 8], 2),
        (matched_trace, matched_span, 3),
    ] {
        fixture.kernel.append_trace(trace, span, 20, position)?;
    }
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, matched_trace, matched_span, 4)?;
    let meter = CancellingOperatorCallMeter::shared(2);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    )
    .with_trace_ledger(fixture.kernel.trace_ledger()?);
    let before = fixture
        .kernel
        .authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    meter.bind(query.cancellation())?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
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
    Ok(())
}

#[test]
fn correlation_rejects_aggregation_until_a_typed_group_outcome_is_specified()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-aggregate-admission")?;
    let service = fixture.correlation_service(16)?;
    let budget = super::budget();
    let pipeline = "pipeline:v1 logs | range query_time -100 100 | correlate trace | aggregate count | limit 1";
    let sql = "SELECT COUNT(*) FROM logs CORRELATE TRACE WHERE query_time >= -100 AND query_time < 100 LIMIT 1";

    assert!(
        service
            .plan_pipeline(
                fixture.context,
                "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
                budget,
            )
            .is_ok()
    );
    assert!(
        service
            .plan_pipeline(
                fixture.context,
                "pipeline:v1 logs | range query_time -100 100 | aggregate count | limit 1",
                budget,
            )
            .is_ok()
    );
    let pipeline_failure = match service.plan_pipeline(fixture.context, pipeline, budget) {
        Ok(_) => return Err("aggregation unexpectedly accepted a correlation pipeline".into()),
        Err(failure) => failure,
    };
    assert_eq!(pipeline_failure.code(), QueryFailureCode::UnsupportedQuery);

    assert!(service
        .plan_sql(
            fixture.context,
            "SELECT body FROM logs CORRELATE TRACE WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
            budget,
        )
        .is_ok());
    assert!(
        service
            .plan_sql(
                fixture.context,
                "SELECT COUNT(*) FROM logs WHERE query_time >= -100 AND query_time < 100 LIMIT 1",
                budget,
            )
            .is_ok()
    );
    let sql_failure = match service.plan_sql(fixture.context, sql, budget) {
        Ok(_) => return Err("aggregation unexpectedly accepted correlation SQL".into()),
        Err(failure) => failure,
    };
    assert_eq!(sql_failure.code(), QueryFailureCode::UnsupportedQuery);
    Ok(())
}

#[test]
fn correlation_fails_closed_on_malformed_target_trace_data() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-malformed-trace")?;
    let trace_id = [0x6d; 16];
    let span_id = [0x6e; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, span_id, 2)?;
    fixture.kernel.append_malformed_trace_block(3)?;
    let service = fixture.correlation_service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        super::budget(),
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::MalformedPersistentData
    ));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, QueryEvent::Terminal(_)))
            .count(),
        1
    );
    Ok(())
}
