use std::error::Error;

use positron_query::{QueryEvent, QueryFailureCode, QueryTerminal};

use super::super::terminal_and_bounds::QueryFixture;

use std::sync::Arc;

use super::super::support::{
    FailAfterArmClock, MergeWorkMeter, publish_lifecycle_at_catalog_for_test, zero_work_service,
};
use positron_kernel::{
    CatalogPublicationFault, LedgerFailureCode, SnapshotLeaseId,
    with_catalog_publication_fault_after, with_catalog_publication_fault_sequence_after,
    with_catalog_publication_hook_after,
};
use positron_query::QueryService;

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
fn correlation_paired_release_failures_emit_one_terminal_and_retry_both_on_drop()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-paired-release-retry")?;
    let trace_id = [0x95; 16];
    let span_id = [0x96; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, span_id, 2)?;
    let baseline = fixture.kernel.authority.governor().inspect()?;
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

    let failure = with_catalog_publication_fault_sequence_after(
        &[
            (CatalogPublicationFault::SynchronizeCommit, 0),
            (CatalogPublicationFault::SynchronizeCommit, 0),
        ],
        || stream.cancel(),
    )
    .expect_err("both paired release publication failures must reach the client");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert!(matches!(
        stream.next(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::StoreUnavailable
    ));
    assert!(stream.next().is_none());
    assert!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_total()
            > baseline.outstanding_total(),
        "both failed releases must remain bounded by the kernel pending-release authority"
    );

    drop(stream);
    for (ledger, lease, name) in [
        (fixture.kernel.ledger()?, source_lease, "source"),
        (fixture.kernel.trace_ledger()?, trace_lease, "target"),
    ] {
        assert_eq!(
            ledger
                .snapshot_lease_usage(lease, 100)
                .expect_err("drop must retry each failed paired release")
                .code(),
            LedgerFailureCode::SnapshotExpired,
            "{name} lease must be released after the fault scope ends"
        );
    }
    assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);
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
fn correlation_pre_stream_clock_failure_releases_both_paired_snapshot_leases()
-> Result<(), Box<dyn Error>> {
    for (label, paginated) in [
        ("correlation-sequential-pre-stream-clock", false),
        ("correlation-paged-pre-stream-clock", true),
    ] {
        let fixture = QueryFixture::new(label)?;
        let trace_id = [0xc1; 16];
        let span_id = [0xc2; 8];
        fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
        fixture
            .kernel
            .append_log_with_trace("accepted", 20, trace_id, span_id, 2)?;
        let clock = FailAfterArmClock::shared(1);
        let service = QueryService::with_runtime(
            fixture.kernel.authority.governor(),
            fixture.kernel.ledger()?,
            1,
            Arc::clone(&clock) as Arc<dyn positron_query::QueryClock>,
            Arc::new(MergeWorkMeter),
        )
        .with_trace_ledger(fixture.kernel.trace_ledger()?);
        let baseline = fixture.kernel.authority.governor().inspect()?;
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
            super::budget(),
        )?;

        // The first armed read admits the paired snapshots. The page's next
        // read fails before its header can escape, exercising eager cleanup.
        clock.arm();
        let failure = if paginated {
            service.execute_page(query)
        } else {
            service.execute(query)
        }
        .expect_err("the pre-stream clock failure must remain a typed execution failure");
        assert_eq!(failure.code(), QueryFailureCode::Internal);
        assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);
    }
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
fn correlation_sequential_admission_retains_failed_source_cleanup_until_later_lease_activity()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-sequential-admission-cleanup-failure")?;
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
        || service.execute(query),
    )
    .expect_err("sequential target admission and source cleanup failure must be surfaced");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_total()
            > baseline.outstanding_total(),
        "the failed sequential cleanup must remain bounded in the ledger authority"
    );

    let recovery_service = fixture.service(1)?;
    let recovery = recovery_service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        super::budget(),
    )?;
    assert_eq!(
        recovery_service
            .execute(recovery)
            .expect_err("the first later admission must drain the pending source release")
            .code(),
        QueryFailureCode::StoreUnavailable
    );
    let recovered = recovery_service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        super::budget(),
    )?;
    drop(recovery_service.execute(recovered)?);
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
