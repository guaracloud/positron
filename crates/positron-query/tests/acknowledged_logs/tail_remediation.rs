use std::error::Error;
use std::fs;

use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, CatalogPublicationFault, CommittedLedgerReader, SegmentProtectionKey,
    SnapshotLeaseId, WorkClass, with_catalog_publication_fault_after,
};
use positron_query::{
    QueryBudget, QueryFailureCode, QueryService, TailCursor, TailEvent, TailPhase, TailSourceSet,
    TailStart, TailTerminal,
};

use super::support::{
    CancellingOperatorCallMeter, TestClock, tail_cursor_with_delivery_sequence,
    tail_cursor_with_snapshot_identity,
};
use super::terminal_and_bounds::QueryFixture;

fn budget(rows: u64) -> Result<QueryBudget, Box<dyn Error>> {
    Ok(QueryBudget::new(
        1_048_576, 16, rows, 1_048_576, 1_048_576, 60,
    )?)
}

#[test]
fn total_limit_is_rejected_for_both_tail_starts_before_resource_mutation()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-total-limit-admission")?;
    let service = fixture.service(16)?;
    let budget = budget(8)?;
    for start in [TailStart::Now, TailStart::Historical { max_rows: 4 }] {
        for source in [
            "pipeline:v1 logs | range query_time -100 100 | limit 1",
            "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        ] {
            let baseline = fixture.kernel.authority.governor().inspect()?;
            let query = if source.starts_with("SELECT") {
                service.plan_sql(fixture.context, source, budget)?
            } else {
                service.plan_pipeline(fixture.context, source, budget)?
            };
            assert!(matches!(
                service.tail(query, start),
                Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
            ));
            let after = fixture.kernel.authority.governor().inspect()?;
            assert_eq!(after.outstanding_total(), baseline.outstanding_total());
            for dimension in positron_kernel::ResourceDimension::ALL {
                assert_eq!(after.usage(dimension), baseline.usage(dimension));
            }
        }
    }
    Ok(())
}

#[test]
fn terminal_cursor_keeps_its_snapshot_lease_resumable() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-terminal-cursor-lease")?;
    let service = fixture.service(16)?;
    let budget = budget(1)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let cancellation = query.cancellation();
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    cancellation.cancel();
    let Some(TailEvent::Terminal(TailTerminal::Cancelled {
        cursor: Some(cursor),
        ..
    })) = tail.poll()
    else {
        return Err("cancel terminal omitted its resumable cursor".into());
    };
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let resumed = service.resume_tail(query, &cursor);
    assert!(resumed.is_ok(), "terminal cursor lost its durable lease");
    Ok(())
}

#[test]
fn tail_header_truthfully_describes_historical_and_live_ordering_phases()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-phase-header")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let mut historical = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    let Some(TailEvent::Header(header)) = historical.poll() else {
        return Err("historical tail omitted its header".into());
    };
    assert_eq!(
        header.tail_phase(),
        Some(TailPhase::HistoricalTemporalThenLiveCommitVector)
    );

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let mut live = service.tail(query, TailStart::Now)?;
    let Some(TailEvent::Header(header)) = live.poll() else {
        return Err("live tail omitted its header".into());
    };
    assert_eq!(header.tail_phase(), Some(TailPhase::LiveCommitVector));
    Ok(())
}

#[test]
fn tail_cursor_preserves_planning_cpu_work() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-planning-cpu")?;
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let state = TailCursor::decode(
        &fixture.kernel.ledger()?.control_tokens(),
        tail.safe_cursor(),
    )?;
    assert_eq!(state.cpu_work_units(), 1);
    Ok(())
}

#[test]
fn tail_nonmatching_record_persists_filter_cpu_in_safe_cursor() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-filter-cpu-progress")?;
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let budget =
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1_024)?;
    let query = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | search body contains "wanted" | limit all"#,
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let initial = TailCursor::decode(
        &fixture.kernel.ledger()?.control_tokens(),
        tail.safe_cursor(),
    )?;
    fixture.kernel.append_log("ignored", 1, 1)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));

    let state = TailCursor::decode(
        &fixture.kernel.ledger()?.control_tokens(),
        tail.safe_cursor(),
    )?;
    assert!(state.cpu_work_units() > initial.cpu_work_units());
    Ok(())
}

#[test]
fn tail_resume_seeds_and_advances_durable_primary_usage() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-durable-usage")?;
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query_source = "pipeline:v1 logs | range query_time -100 100 | limit all";
    let query_budget =
        QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1_024)?;
    let query = service.plan_pipeline(fixture.context, query_source, query_budget)?;
    let mut tail = service.tail(query, TailStart::Now)?;
    let Some(TailEvent::Header(header)) = tail.poll() else {
        return Err("tail omitted its header".into());
    };
    let lease = SnapshotLeaseId::new(header.lease().identity())?;
    fixture.kernel.append_log("durable", 1, 1)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Batch(_))));
    let delivery = tail.cursor().clone();
    let first = fixture.kernel.ledger()?.snapshot_lease_usage(lease, 100)?;
    assert!(first.scanned_bytes() > 0 || first.decoded_records() > 0);
    drop(tail);

    let query = service.plan_pipeline(fixture.context, query_source, query_budget)?;
    let mut resumed = service.resume_tail(query, &delivery)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    assert!(matches!(resumed.poll(), Some(TailEvent::Batch(_))));
    let second = fixture.kernel.ledger()?.snapshot_lease_usage(lease, 100)?;
    assert!(
        second.scanned_bytes() > first.scanned_bytes()
            || second.decoded_records() > first.decoded_records()
    );
    Ok(())
}

#[test]
fn tail_memory_budget_reserves_retained_plan_and_source_before_materialization()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-retained-memory-boundary")?;
    fixture.kernel.append_log("one-row", 1, 1)?;
    let service = fixture.service(16)?;
    let source = format!(
        "pipeline:v1 logs | range query_time -100 100 | limit all{}",
        " ".repeat(4_000)
    );
    let budget_for = |memory| {
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, memory, 60)
            .and_then(|budget| budget.with_cpu_work_units(1_024))
    };
    let mut lower = 1_u64;
    let mut upper = 1_048_576_u64;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        if service
            .plan_pipeline(fixture.context, &source, budget_for(middle)?)
            .is_ok()
        {
            upper = middle;
        } else {
            lower = middle.checked_add(1).ok_or("memory floor overflowed")?;
        }
    }
    let query = service.plan_pipeline(fixture.context, &source, budget_for(lower)?)?;
    assert!(matches!(
        service.tail(query, TailStart::Historical { max_rows: 1 }),
        Err(failure)
            if failure.code() == QueryFailureCode::BudgetExhausted
                && failure.limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::MemoryBytes)
    ));
    Ok(())
}

#[test]
fn total_limit_is_rejected_on_resume_before_history_or_lease_work() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-total-limit-resume")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(8)?,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let cursor = tail.safe_cursor().clone();
    let baseline = fixture.kernel.authority.governor().inspect()?;
    let query = service.plan_sql(
        fixture.context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        budget(8)?,
    )?;
    assert!(matches!(
        service.resume_tail(query, &cursor),
        Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
    ));
    let after = fixture.kernel.authority.governor().inspect()?;
    assert_eq!(after.outstanding_total(), baseline.outstanding_total());
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), baseline.usage(dimension));
    }
    drop(tail);
    Ok(())
}

#[test]
fn explicit_ordering_is_rejected_for_historical_and_live_tail() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-explicit-order-admission")?;
    let service = fixture.service(16)?;
    for (source, start) in [
        (
            "pipeline:v1 logs | range query_time -100 100 | order by query_time asc, commit_position asc | limit all",
            TailStart::Historical { max_rows: 1 },
        ),
        (
            "pipeline:v1 logs | range query_time -100 100 | order by query_time asc, commit_position asc | limit all",
            TailStart::Now,
        ),
        (
            "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT ALL",
            TailStart::Historical { max_rows: 1 },
        ),
        (
            "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT ALL",
            TailStart::Now,
        ),
    ] {
        let baseline = fixture.kernel.authority.governor().inspect()?;
        let query = if source.starts_with("SELECT") {
            service.plan_sql(fixture.context, source, budget(1)?)?
        } else {
            service.plan_pipeline(fixture.context, source, budget(1)?)?
        };
        assert!(matches!(
            service.tail(query, start),
            Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
        ));
        assert_eq!(
            fixture
                .kernel
                .authority
                .governor()
                .inspect()?
                .outstanding_total(),
            baseline.outstanding_total()
        );
    }
    Ok(())
}

#[test]
fn traces_are_rejected_at_source_admission() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-traces-admission")?;
    let traces = ActiveSegmentLedger::open(
        fixture.kernel.authority,
        fixture.kernel.catalog_for_test(),
        positron_kernel::SegmentScope::new(
            fixture
                .context
                .tenant_attribution()
                .ok_or("tenant")?
                .tenant_id(),
            SignalKind::Traces,
            VirtualShardId::new(3)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x73; 32])),
    )?;
    assert!(matches!(
        TailSourceSet::new(vec![traces.reader()?]),
        Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
    ));
    Ok(())
}

#[test]
fn source_set_rejections_keep_the_public_failure_types() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-source-set-rejections")?;
    assert!(matches!(
        TailSourceSet::new(Vec::new()),
        Err(failure) if failure.code() == QueryFailureCode::InvalidBudget
    ));

    let overlimit = (1..=65)
        .map(|value| {
            CommittedLedgerReader::open(
                fixture.kernel.authority,
                fixture.kernel.catalog_for_test(),
                positron_kernel::SegmentScope::new(
                    fixture
                        .context
                        .tenant_attribution()
                        .ok_or("tenant")?
                        .tenant_id(),
                    SignalKind::Logs,
                    VirtualShardId::new(value)?,
                ),
                SegmentProtectionKey::from_owned(Box::new([0x78; 32])),
            )
            .map_err(|failure| -> Box<dyn Error> { Box::new(failure) })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    assert!(matches!(
        TailSourceSet::new(overlimit),
        Err(failure) if failure.code() == QueryFailureCode::InvalidBudget
    ));

    let primary = fixture.kernel.ledger()?.reader()?;
    let duplicate = fixture.kernel.ledger()?.reader()?;
    assert!(matches!(
        TailSourceSet::new(vec![primary, duplicate]),
        Err(failure) if failure.code() == QueryFailureCode::Unauthorized
    ));

    let other_tenant = positron_domain::identity::TenantId::from_bytes([0x92; 16])?;
    let other = CommittedLedgerReader::open(
        fixture.kernel.authority,
        fixture.kernel.catalog_for_test(),
        positron_kernel::SegmentScope::new(
            other_tenant,
            SignalKind::Logs,
            VirtualShardId::new(66)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x79; 32])),
    )?;
    let primary = fixture.kernel.ledger()?.reader()?;
    assert!(matches!(
        TailSourceSet::new(vec![primary, other]),
        Err(failure) if failure.code() == QueryFailureCode::Unauthorized
    ));

    let traces = ActiveSegmentLedger::open(
        fixture.kernel.authority,
        fixture.kernel.catalog_for_test(),
        positron_kernel::SegmentScope::new(
            fixture
                .context
                .tenant_attribution()
                .ok_or("tenant")?
                .tenant_id(),
            SignalKind::Traces,
            VirtualShardId::new(67)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x7a; 32])),
    )?;
    assert!(matches!(
        TailSourceSet::new(vec![traces.reader()?]),
        Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
    ));
    Ok(())
}

#[test]
fn catalog_failure_during_active_revalidation_is_store_unavailable() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-catalog-revalidation-failure")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));

    let commits = fixture.kernel.catalog_data_root_for_test().join("commits");
    let commit = fs::read_dir(&commits)?
        .next()
        .ok_or("catalog commit missing")??
        .path();
    fs::remove_file(commit)?;

    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable { .. }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn mismatched_delivery_digest_fails_closed_during_replay() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-delivery-digest-mismatch")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("replay", 1, 1)?;
    let Some(TailEvent::Batch(_)) = tail.poll() else {
        return Err("tail batch missing".into());
    };
    let mut forged = tail.cursor().as_bytes().to_vec();
    let payload_len = forged.len().checked_sub(32).ok_or("cursor tag missing")?;
    let delivery_start = forged
        .get(..payload_len)
        .ok_or("cursor payload missing")?
        .windows(4)
        .position(|window| window == b"DLV1")
        .ok_or("delivery marker missing")?;
    let digest_start = delivery_start
        .checked_add(4 + 8)
        .ok_or("delivery digest offset overflow")?;
    *forged
        .get_mut(digest_start)
        .ok_or("delivery digest missing")? ^= 1;
    let authentication = fixture
        .kernel
        .ledger()?
        .control_tokens()
        .authenticate_query_cursor(
            b"tail-cursor-v3",
            forged.get(..payload_len).ok_or("cursor payload missing")?,
        )?;
    forged
        .get_mut(payload_len..)
        .ok_or("cursor tag missing")?
        .copy_from_slice(&authentication.tag());
    let forged = TailCursor::from_bytes(&forged)?;
    drop(tail);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let mut resumed = service.resume_tail(query, &forged)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    assert!(matches!(
        resumed.poll(),
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable { .. }))
    ));
    Ok(())
}

#[test]
fn resume_source_lease_publication_failure_is_store_unavailable() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-publication-failure")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let mut initial = service.tail(query, TailStart::Now)?;
    assert!(matches!(initial.poll(), Some(TailEvent::Header(_))));
    let cursor = initial.safe_cursor().clone();
    drop(initial);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let result =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            service.resume_tail(query, &cursor)
        });
    let failure = match result {
        Ok(_) => return Err("resume marker publication unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    Ok(())
}

#[test]
fn resume_rejects_a_source_snapshot_identity_switch() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-snapshot-identity")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let mut initial = service.tail(query, TailStart::Now)?;
    assert!(matches!(initial.poll(), Some(TailEvent::Header(_))));
    let cursor = tail_cursor_with_snapshot_identity(
        &fixture.kernel.ledger()?.control_tokens(),
        initial.safe_cursor(),
        [0x9a; 32],
    )?;
    drop(initial);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let failure = match service.resume_tail(query, &cursor) {
        Ok(_) => return Err("a snapshot identity switch unexpectedly resumed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    Ok(())
}

#[test]
fn live_scan_observes_cancellation_before_accounting_scanned_bytes() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-scan-cancel-observer")?;
    let meter = CancellingOperatorCallMeter::shared_for_stage(
        positron_query::QueryWorkStage::ScanDecode,
        1,
    );
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        meter.clone(),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    meter.bind(query.cancellation())?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("cancelled", 1, 1)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Cancelled { .. }))
    ));
    Ok(())
}

#[test]
fn cleanup_ranking_inspects_each_public_terminal_failure_code() -> Result<(), Box<dyn Error>> {
    {
        let fixture = QueryFixture::new("tail-cleanup-code-lag")?;
        fixture.kernel.append_logs(
            vec![
                (
                    Some(1),
                    Some(positron_domain::value::CandidateAttributeValue::string(
                        "one".to_owned(),
                    )),
                ),
                (
                    Some(2),
                    Some(positron_domain::value::CandidateAttributeValue::string(
                        "two".to_owned(),
                    )),
                ),
            ],
            1,
        )?;
        let service = fixture.service(16)?;
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | limit all",
            QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?,
        )?;
        let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
        assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
        assert!(matches!(tail.poll(), Some(TailEvent::Batch(_))));
    }
    {
        let fixture = QueryFixture::new("tail-cleanup-code-budget")?;
        let service = super::support::stage_work_service(
            fixture.kernel.authority.governor(),
            fixture.kernel.ledger()?,
            16,
        );
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | project body, query_time | limit all",
            QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1)?,
        )?;
        let mut tail = service.tail(query, TailStart::Now)?;
        assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
        fixture.kernel.append_log("budget", 1, 1)?;
        assert!(matches!(
            with_catalog_publication_fault_after(
                CatalogPublicationFault::SynchronizeCommit,
                0,
                || tail.poll(),
            ),
            Some(TailEvent::Terminal(TailTerminal::StoreUnavailable { .. }))
        ));
    }
    {
        let fixture = QueryFixture::new("tail-cleanup-code-expired")?;
        let clock = TestClock::shared(100);
        let service = super::support::zero_work_clock_service(
            fixture.kernel.authority.governor(),
            fixture.kernel.ledger()?,
            16,
            clock.clone(),
        );
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | limit all",
            budget(1)?,
        )?;
        let mut tail = service.tail(query, TailStart::Now)?;
        assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
        clock.set(160);
        assert!(matches!(
            with_catalog_publication_fault_after(
                CatalogPublicationFault::SynchronizeCommit,
                0,
                || tail.poll(),
            ),
            Some(TailEvent::Terminal(TailTerminal::StoreUnavailable { .. }))
        ));
    }
    {
        let fixture = QueryFixture::new("tail-cleanup-code-cancelled")?;
        let service = fixture.service(16)?;
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | limit all",
            budget(1)?,
        )?;
        let mut tail = service.tail(query, TailStart::Now)?;
        assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
        tail.cancel();
        assert!(matches!(
            tail.poll(),
            Some(TailEvent::Terminal(TailTerminal::Cancelled { .. }))
        ));
    }
    {
        let fixture = QueryFixture::new("tail-cleanup-code-disconnected")?;
        let service = fixture.service(16)?;
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | limit all",
            budget(1)?,
        )?;
        let mut tail = service.tail(query, TailStart::Now)?;
        assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
        tail.disconnect();
        assert!(matches!(
            tail.poll(),
            Some(TailEvent::Terminal(TailTerminal::Disconnected { .. }))
        ));
    }
    Ok(())
}

#[test]
fn resume_rejects_a_delivery_cursor_with_a_late_sequence() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-delivery-sequence")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let mut initial = service.tail(query, TailStart::Now)?;
    assert!(matches!(initial.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("delivery-sequence", 1, 1)?;
    assert!(matches!(initial.poll(), Some(TailEvent::Batch(_))));
    let forged = tail_cursor_with_delivery_sequence(
        &fixture.kernel.ledger()?.control_tokens(),
        initial.cursor(),
        1,
    )?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let failure = match service.resume_tail(query, &forged) {
        Ok(_) => return Err("a late delivery sequence unexpectedly resumed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::InvalidCursor);
    Ok(())
}

#[test]
fn secondary_only_sources_are_rejected_before_a_tail_lease_is_created() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-secondary-only-admission")?;
    let second = ActiveSegmentLedger::open(
        fixture.kernel.authority,
        fixture.kernel.catalog_for_test(),
        positron_kernel::SegmentScope::new(
            fixture
                .context
                .tenant_attribution()
                .ok_or("tenant")?
                .tenant_id(),
            SignalKind::Logs,
            VirtualShardId::new(2)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x74; 32])),
    )?;
    let sources = TailSourceSet::new(vec![second.reader()?])?;
    let service = fixture.service(16)?;
    let baseline = fixture.kernel.authority.governor().inspect()?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        budget(1)?,
    )?;
    assert!(matches!(
        service.tail_with_sources(query, TailStart::Now, sources),
        Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
    ));
    let after = fixture.kernel.authority.governor().inspect()?;
    assert_eq!(after.outstanding_total(), baseline.outstanding_total());
    Ok(())
}

#[test]
fn secondary_only_sources_are_rejected_before_resume_snapshot_work() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-secondary-only-resume")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    let mut initial = service.tail(query, TailStart::Now)?;
    assert!(matches!(initial.poll(), Some(TailEvent::Header(_))));
    let cursor = initial.safe_cursor().clone();
    let second = ActiveSegmentLedger::open(
        fixture.kernel.authority,
        fixture.kernel.catalog_for_test(),
        positron_kernel::SegmentScope::new(
            fixture
                .context
                .tenant_attribution()
                .ok_or("tenant")?
                .tenant_id(),
            SignalKind::Logs,
            VirtualShardId::new(2)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x76; 32])),
    )?;
    let sources = TailSourceSet::new(vec![second.reader()?])?;
    let baseline = fixture.kernel.authority.governor().inspect()?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(1)?,
    )?;
    assert!(matches!(
        service.resume_tail_with_sources(query, &cursor, sources),
        Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
    ));
    let after = fixture.kernel.authority.governor().inspect()?;
    assert_eq!(after.outstanding_total(), baseline.outstanding_total());
    drop(initial);
    Ok(())
}

#[test]
fn historical_tail_has_a_public_header_before_waiting_for_live_data() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-no-total-limit-live-transition")?;
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(8)?,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    Ok(())
}

#[test]
fn historical_tail_orders_records_across_multiple_committed_blocks() -> Result<(), Box<dyn Error>> {
    let mut fixture = QueryFixture::new("tail-historical-ordering")?;
    fixture.kernel.append_log("later", 20, 1)?;
    fixture.kernel.seal_and_reopen()?;
    fixture.kernel.append_log("earlier", 10, 2)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(2)?,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 2 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("historical batch missing".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("earlier"));
    assert_eq!(batch.records()[1].body_text(), Some("later"));
    Ok(())
}

#[test]
fn unbounded_tail_spans_historical_batches_resume_and_live_transition() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-unbounded-transition")?;
    fixture.kernel.append_log("historical-first", 1, 1)?;
    fixture.kernel.append_log("historical-second", 2, 2)?;
    let service = fixture.service(16)?;
    let source = "pipeline:v1 logs | range query_time -100 100 | limit all";
    let query = service.plan_pipeline(fixture.context, source, budget(8)?)?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(first)) = tail.poll() else {
        return Err("first historical batch missing".into());
    };
    assert_eq!(first.records()[0].body_text(), Some("historical-first"));
    tail.acknowledge(first.sequence(), first.digest())?;
    let Some(TailEvent::Batch(second)) = tail.poll() else {
        return Err("second historical batch missing".into());
    };
    let delivery = tail.cursor().clone();
    assert_eq!(second.records()[0].body_text(), Some("historical-second"));
    drop(tail);

    let query = service.plan_pipeline(fixture.context, source, budget(8)?)?;
    let mut resumed = service.resume_tail(query, &delivery)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(repeated)) = resumed.poll() else {
        return Err("resumed historical batch missing".into());
    };
    assert_eq!(repeated.sequence(), second.sequence());
    assert_eq!(repeated.digest(), second.digest());
    assert!(repeated.records()[0].replayed());
    resumed.acknowledge(repeated.sequence(), repeated.digest())?;

    fixture.kernel.append_log("live-after-history", 3, 3)?;
    let Some(TailEvent::Batch(live)) = resumed.poll() else {
        return Err("live transition batch missing".into());
    };
    assert_eq!(live.records()[0].body_text(), Some("live-after-history"));
    assert!(!live.records()[0].replayed());
    resumed.acknowledge(live.sequence(), live.digest())?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Idle)));
    Ok(())
}

#[test]
fn multi_shard_resume_after_ack_and_new_commits_preserves_accounting() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-multi-shard-resume-accounting")?;
    let second = ActiveSegmentLedger::open(
        fixture.kernel.authority,
        fixture.kernel.catalog_for_test(),
        positron_kernel::SegmentScope::new(
            fixture
                .context
                .tenant_attribution()
                .ok_or("tenant")?
                .tenant_id(),
            SignalKind::Logs,
            VirtualShardId::new(2)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x77; 32])),
    )?;
    let service = fixture.service(16)?;
    let source = "pipeline:v1 logs | range query_time -100 100 | limit all";
    let sources = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?, second.reader()?])?;
    let query = service.plan_pipeline(fixture.context, source, budget(8)?)?;
    let mut tail = service.tail_with_sources(query, TailStart::Now, sources)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("primary-history", 1, 1)?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![(
            Some(2),
            Some(positron_domain::value::CandidateAttributeValue::string(
                "secondary-history".to_owned(),
            )),
        )],
        2,
    )?;
    let Some(TailEvent::Batch(history)) = tail.poll() else {
        return Err("multi-shard history batch missing".into());
    };
    assert_eq!(history.records().len(), 2);
    tail.acknowledge(history.sequence(), history.digest())?;
    let cursor = tail.cursor().clone();

    fixture.kernel.append_log("primary-live", 3, 3)?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![(
            Some(4),
            Some(positron_domain::value::CandidateAttributeValue::string(
                "secondary-live".to_owned(),
            )),
        )],
        4,
    )?;
    drop(tail);
    let baseline = fixture.kernel.authority.governor().inspect()?;

    let sources = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?, second.reader()?])?;
    let query = service.plan_pipeline(fixture.context, source, budget(8)?)?;
    let mut resumed = service.resume_tail_with_sources(query, &cursor, sources)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(live)) = resumed.poll() else {
        return Err("multi-shard resumed batch missing".into());
    };
    assert_eq!(live.records().len(), 2);
    assert_eq!(live.sequence(), 1);
    resumed.acknowledge(live.sequence(), live.digest())?;
    assert_eq!(
        resumed.poll().ok_or("resumed tail did not become idle")?,
        TailEvent::Idle
    );
    drop(resumed);
    let after = fixture.kernel.authority.governor().inspect()?;
    assert!(after.outstanding_total() <= baseline.outstanding_total());
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert!(after.usage(dimension) <= baseline.usage(dimension));
    }
    Ok(())
}

#[test]
fn historical_decoded_records_exhaustion_has_no_prefix_and_reports_dimension()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-historical-decoded-budget")?;
    fixture.kernel.append_log("decoded-first", 1, 1)?;
    fixture.kernel.append_log("decoded-second", 2, 2)?;
    let service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        QueryBudget::new(1_048_576, 1, 4, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1_024)?,
    )?;
    let failure = match service.tail(query, TailStart::Historical { max_rows: 1 }) {
        Ok(_) => return Err("decoded budget refusal exposed a historical prefix".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
    assert_eq!(
        failure.limiting_budget(),
        Some(positron_query::QueryBudgetDimension::DecodedRecords)
    );
    Ok(())
}

#[test]
fn late_sequence_delivery_cursor_replays_once_without_double_counting() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-late-delivery-cursor")?;
    fixture.kernel.append_log("first", 1, 1)?;
    fixture.kernel.append_log("second", 2, 2)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(8)?,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(first)) = tail.poll() else {
        return Err("first batch missing".into());
    };
    tail.acknowledge(first.sequence(), first.digest())?;
    let safe_cursor = tail.cursor().clone();
    let Some(TailEvent::Batch(second)) = tail.poll() else {
        return Err("second batch missing".into());
    };
    assert_eq!(second.sequence(), 1);
    let delivery_cursor = tail.cursor().clone();
    assert_ne!(delivery_cursor, safe_cursor);
    drop(tail);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget(8)?,
    )?;
    let mut resumed = service.resume_tail(query, &delivery_cursor)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(repeated)) = resumed.poll() else {
        return Err("late repeated batch missing".into());
    };
    assert_eq!(repeated.sequence(), second.sequence());
    assert_eq!(repeated.digest(), second.digest());
    assert!(
        repeated
            .records()
            .iter()
            .all(positron_query::QueryRecord::replayed)
    );
    resumed.disconnect();
    let Some(TailEvent::Terminal(positron_query::TailTerminal::Disconnected { stats, .. })) =
        resumed.poll()
    else {
        return Err("replay terminal missing".into());
    };
    assert_eq!(stats.repeated_batch_count(), 1);
    assert_eq!(stats.emitted_records(), 1);
    Ok(())
}

#[test]
fn drop_defers_a_release_fault_without_leaking_across_sixty_five_sessions()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-drop-release-fault-loop")?;
    let service = fixture.service(16)?;
    let source = "pipeline:v1 logs | range query_time -100 100 | limit all";
    let budget = budget(1)?;
    for _ in 0..65 {
        let baseline = fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail);
        let query = service.plan_pipeline(fixture.context, source, budget)?;
        let mut tail = service.tail(query, TailStart::Now)?;
        let identity = match tail.poll().ok_or("tail header missing")? {
            TailEvent::Header(header) => SnapshotLeaseId::new(header.lease().identity())?,
            _ => return Err("tail header missing".into()),
        };
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            drop(tail);
        });
        let ledger = fixture.kernel.ledger()?;
        assert_eq!(
            ledger
                .resume_snapshot_lease(identity, 100)
                .expect_err("deferred Drop release must remove the lease")
                .code(),
            positron_kernel::LedgerFailureCode::SnapshotExpired
        );
        assert_eq!(
            fixture
                .kernel
                .authority
                .governor()
                .inspect()?
                .outstanding_for(WorkClass::InteractiveQueryTail),
            baseline
        );
    }
    Ok(())
}
