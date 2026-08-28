use std::error::Error;
use std::sync::Mutex;

use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::value::AttributeValueKind;
use positron_kernel::{
    ActiveSegmentLedger, CatalogPublicationFault, CommittedLedgerReader, SegmentProtectionKey,
    SnapshotLeaseId, WorkClass, with_catalog_publication_fault_after,
    with_catalog_publication_fault_sequence_after,
};
use positron_query::{
    QueryBudget, QueryEvent, QueryFailureCode, QueryService, QueryTerminal, TailCursor,
    TailCursorState, TailEvent, TailPosition, TailSourceSet, TailStart, TailTerminal,
};

use super::support::{
    CancellingOperatorCallMeter, CancellingStageWorkMeter, ConstantWorkMeter, FailAfterArmClock,
    FailAfterArmOutputMeter, StepClock, TestClock, merge_work_service, stage_work_service,
    tail_cursor_with_cpu_progress, tail_cursor_with_source_binding, tail_cursor_with_source_lease,
    zero_work_clock_service,
};
use super::terminal_and_bounds::QueryFixture;

struct OperatorOverflowWorkMeter;

static TAIL_CURSOR_FAULT_LOCK: Mutex<()> = Mutex::new(());

impl positron_query::QueryWorkMeter for OperatorOverflowWorkMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        Ok(u64::from(stage == positron_query::QueryWorkStage::Operators) * u64::MAX)
    }
}

#[test]
fn tail_reads_acknowledged_history_then_stays_idle_until_disconnect() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-history")?;
    fixture.kernel.append_log("one", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("tail batch missing".into());
    };
    assert_eq!(batch.records().len(), 1);
    assert_eq!(batch.records()[0].body_text(), Some("one"));
    tail.acknowledge(batch.sequence(), batch.digest())?;
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    fixture.kernel.append_log("live", 2, 2)?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("live tail batch missing after ingest append".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("live"));
    tail.acknowledge(batch.sequence(), batch.digest())?;
    tail.disconnect();
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Disconnected { .. }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_revalidation_failure_emits_one_terminal() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-revalidation-failure")?;
    let clock = FailAfterArmClock::shared(0);
    let service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        clock.clone(),
    );
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    clock.arm();
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_terminal_stats_count_only_acknowledged_rows_and_digest() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-terminal-stats")?;
    fixture.kernel.append_log("undelivered", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("tail batch missing".into());
    };
    tail.disconnect();
    let Some(TailEvent::Terminal(TailTerminal::Disconnected { stats, .. })) = tail.poll() else {
        return Err("tail terminal missing".into());
    };
    assert_eq!(stats.emitted_records(), 0);
    assert_eq!(stats.emitted_bytes(), 0);
    assert_eq!(stats.result_digest(), [0; 32]);
    assert!(stats.memory_peak_bytes() > 0);
    assert!(stats.cpu_work_units() <= budget.cpu_work_units());
    assert_eq!(stats.elapsed_seconds(), 0);
    assert_eq!(stats.last_sequence(), None);
    assert_eq!(stats.cumulative_budget().output_rows(), 1);
    assert!(!stats.reduced_pruning());
    assert!(stats.scanned_bytes() > 0);
    assert!(stats.decoded_records() > 0);
    assert_eq!(batch.records().len(), 1);
    Ok(())
}

#[test]
fn tail_resume_frames_cumulative_elapsed_overflow_before_delivery() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-elapsed-overflow")?;
    fixture.kernel.append_log("elapsed", 1, 1)?;
    let clock = TestClock::shared(100);
    let service = positron_query::QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        clock.clone(),
        std::sync::Arc::new(ConstantWorkMeter(0)),
    );
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let mut bytes = tail.cursor().as_bytes().to_vec();
    drop(tail);

    let extension_start = 260 + 16;
    let markers_end = extension_start + 4 + 2 + 16;
    let elapsed_offset = markers_end + 8;
    bytes[elapsed_offset..elapsed_offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    let payload_len = bytes.len().checked_sub(32).ok_or("cursor tag missing")?;
    let authentication = fixture
        .kernel
        .ledger()?
        .control_tokens()
        .authenticate_query_cursor(
            b"tail-cursor-v3",
            bytes.get(..payload_len).ok_or("cursor payload missing")?,
        )?;
    bytes
        .get_mut(payload_len..)
        .ok_or("cursor tag missing")?
        .copy_from_slice(&authentication.tag());
    let cursor = TailCursor::from_bytes(&bytes)?;

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut resumed = service
        .resume_tail(query, &cursor)
        .map_err(|failure| format!("resume: {failure:?}"))?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    clock.set(101);
    assert!(matches!(
        resumed.poll(),
        Some(TailEvent::Terminal(TailTerminal::BudgetExhausted {
            cursor: Some(_),
            stats,
        })) if stats.limiting_budget() == Some(positron_query::QueryBudgetDimension::WallSeconds)
    ));
    assert!(resumed.poll().is_none());
    Ok(())
}

#[test]
fn tail_terminal_stats_accumulate_resume_and_repeat_counts() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-terminal-resume-stats")?;
    fixture.kernel.append_log("repeat", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut first = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(first.poll(), Some(TailEvent::Header(_))));
    assert!(matches!(first.poll(), Some(TailEvent::Batch(_))));
    let cursor = first.cursor().clone();
    first.disconnect();
    let first_memory_peak = match first.poll() {
        Some(TailEvent::Terminal(TailTerminal::Disconnected { stats, .. })) => {
            assert_eq!(stats.resume_count(), 0);
            assert_eq!(stats.repeated_batch_count(), 0);
            stats.memory_peak_bytes()
        },
        _ => return Err("initial tail terminal missing".into()),
    };
    assert!(first_memory_peak > 0);
    assert!(first.poll().is_none());

    drop(first);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut resumed = service.resume_tail(query, &cursor)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    assert!(matches!(resumed.poll(), Some(TailEvent::Batch(_))));
    resumed.disconnect();
    assert!(matches!(
        resumed.poll(),
        Some(TailEvent::Terminal(TailTerminal::Disconnected { stats, .. }))
            if stats.resume_count() == 1
                && stats.repeated_batch_count() == 1
                && stats.memory_peak_bytes() >= first_memory_peak
    ));
    Ok(())
}

#[test]
fn tail_poll_requires_an_explicit_acknowledgement_before_advancing_cursor()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-explicit-ack")?;
    fixture.kernel.append_log("one", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let safe_cursor = tail.safe_cursor().clone();
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("tail batch missing".into());
    };

    assert_eq!(tail.safe_cursor(), &safe_cursor);
    assert_eq!(
        tail.acknowledge(batch.sequence() + 1, batch.digest())
            .expect_err("out-of-order acknowledgement must be rejected")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    assert_eq!(
        tail.acknowledge(batch.sequence(), [9; 32])
            .expect_err("forged acknowledgement digest must be rejected")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    tail.acknowledge(batch.sequence(), batch.digest())?;
    tail.acknowledge(batch.sequence(), batch.digest())?;
    assert_ne!(tail.cursor(), &safe_cursor);
    tail.disconnect();
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Disconnected { .. }))
    ));
    Ok(())
}

#[test]
fn tail_acknowledges_a_same_shard_live_batch_in_commit_order() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-live-same-shard-order")?;
    let service = merge_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));

    fixture.kernel.append_logs(
        vec![
            (
                Some(1),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "first".to_owned(),
                )),
            ),
            (
                Some(2),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "second".to_owned(),
                )),
            ),
        ],
        1,
    )?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("same-shard live batch missing".into());
    };
    let bodies = batch
        .records()
        .iter()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["first", "second"]);
    let sequence = batch.sequence();
    let digest = batch.digest();
    tail.acknowledge(sequence, digest)?;

    let state = TailCursor::decode(&fixture.kernel.ledger()?.control_tokens(), tail.cursor())?;
    assert_eq!(state.positions().len(), 1);
    assert_eq!(state.positions()[0].shard(), VirtualShardId::new(1)?);
    assert_eq!(state.positions()[0].position().value(), 1);
    assert_eq!(state.positions()[0].ordinal().value(), 1);
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    Ok(())
}

#[test]
fn tail_rejects_an_acknowledgement_before_a_batch_is_pending_and_remains_usable()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-ack-before-pending")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert_eq!(
        tail.acknowledge(7, [0x5a; 32])
            .expect_err("an acknowledgement without a pending batch must fail")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));

    fixture.kernel.append_log("usable", 1, 1)?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("tail did not remain usable after an invalid acknowledgement".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("usable"));
    tail.acknowledge(batch.sequence(), batch.digest())?;
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn tail_ack_cursor_encode_failure_keeps_safe_progress_and_terminalizes_once()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-ack-encode-failure")?;
    fixture.kernel.append_log("one", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let safe_cursor = tail.safe_cursor().clone();
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("acknowledgement failure batch missing".into());
    };
    let _fault_lock = TAIL_CURSOR_FAULT_LOCK
        .lock()
        .map_err(|_| "fault lock poisoned")?;
    positron_query::fail_next_tail_cursor_encode();
    assert_eq!(
        tail.acknowledge(batch.sequence(), batch.digest())
            .expect_err("injected cursor encoding failure must be returned")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    assert_eq!(tail.cursor(), &safe_cursor);
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable {
            stats,
            cursor: Some(cursor),
        })) if cursor == safe_cursor && stats.emitted_records() == 0
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_disconnect_before_ack_replays_the_same_batch_identity() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-ack-replay")?;
    fixture.kernel.append_log("one", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(first)) = tail.poll() else {
        return Err("initial tail batch missing".into());
    };
    let cursor = tail.cursor().clone();
    tail.disconnect();
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Disconnected { .. }))
    ));
    drop(tail);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut resumed = service.resume_tail(query, &cursor)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(repeated)) = resumed.poll() else {
        return Err("replayed tail batch missing".into());
    };
    assert_eq!(repeated.sequence(), first.sequence());
    assert_eq!(repeated.digest(), first.digest());
    assert_eq!(repeated.prior_digest(), first.prior_digest());
    assert_eq!(repeated.records().len(), first.records().len());
    assert_eq!(
        repeated.records()[0].body_text(),
        first.records()[0].body_text()
    );
    assert!(repeated.records()[0].replayed());
    Ok(())
}

#[test]
fn tail_drop_releases_its_durable_lease_and_admission() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-drop-release")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let baseline = fixture
        .kernel
        .authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    let lease_identity = match tail.poll() {
        Some(TailEvent::Header(header)) => SnapshotLeaseId::new(header.lease().identity())?,
        _ => return Err("tail header missing".into()),
    };
    assert!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail)
            > baseline
    );
    drop(tail);
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .resume_snapshot_lease(lease_identity, 100)
            .expect_err("dropped tail must release its durable lease")
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
    Ok(())
}

#[test]
fn tail_resume_maps_a_released_source_lease_to_store_unavailable() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-released-lease")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    let lease_identity = match tail.poll() {
        Some(TailEvent::Header(header)) => SnapshotLeaseId::new(header.lease().identity())?,
        _ => return Err("tail header missing".into()),
    };
    let cursor = tail.cursor().clone();
    fixture
        .kernel
        .ledger()?
        .release_snapshot_lease(lease_identity)?;
    drop(tail);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let failure = match service.resume_tail(query, &cursor) {
        Ok(_) => return Err("a released source lease unexpectedly resumed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    Ok(())
}

#[test]
fn tail_release_failure_is_one_terminal_and_drop_retries_deferred_cleanup()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-release-retry")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    let lease_identity = match tail.poll() {
        Some(TailEvent::Header(header)) => SnapshotLeaseId::new(header.lease().identity())?,
        _ => return Err("tail header missing".into()),
    };
    tail.disconnect();
    let terminal =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            tail.poll()
        });
    assert!(matches!(
        terminal,
        Some(TailEvent::Terminal(TailTerminal::Disconnected {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    drop(tail);
    assert!(
        fixture
            .kernel
            .ledger()?
            .resume_snapshot_lease(lease_identity, 100)
            .is_ok()
    );
    Ok(())
}

#[test]
fn tail_historical_admission_failure_releases_the_lease_before_returning()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-admission-release")?;
    fixture.kernel.append_malformed_log_block(1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let baseline = fixture
        .kernel
        .authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    if service
        .tail(query, TailStart::Historical { max_rows: 1 })
        .is_ok()
    {
        return Err("malformed historical data unexpectedly admitted".into());
    }
    assert_eq!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        baseline
    );
    Ok(())
}

#[test]
fn tail_terminal_and_drop_paths_reclaim_lease_capacity_repeatedly() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-terminal-release-loop")?;
    let clock = TestClock::shared(100);
    let service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        clock.clone(),
    );
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    for attempt in 0..65 {
        clock.set(100);
        let baseline = fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail);
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | limit all",
            budget,
        )?;
        let mut tail = service.tail(query, TailStart::Now)?;
        match tail.poll() {
            Some(TailEvent::Header(_)) => {},
            _ => return Err("tail header missing".into()),
        }
        let terminal_cursor = match attempt % 4 {
            0 => {
                tail.cancel();
                let Some(TailEvent::Terminal(TailTerminal::Cancelled {
                    cursor: Some(cursor),
                    ..
                })) = tail.poll()
                else {
                    return Err("cancel terminal omitted its cursor".into());
                };
                Some(cursor)
            },
            1 => {
                tail.disconnect();
                let Some(TailEvent::Terminal(TailTerminal::Disconnected {
                    cursor: Some(cursor),
                    ..
                })) = tail.poll()
                else {
                    return Err("disconnect terminal omitted its cursor".into());
                };
                Some(cursor)
            },
            _ => None,
        };
        if terminal_cursor.is_some() {
            assert!(tail.poll().is_none());
        }
        drop(tail);
        if let Some(cursor) = terminal_cursor.as_ref() {
            let query = service
                .plan_pipeline(
                    fixture.context,
                    "pipeline:v1 logs | range query_time -100 100 | limit all",
                    budget,
                )
                .map_err(|failure| format!("attempt {attempt} plan failed: {failure:?}"))?;
            let resumed = service
                .resume_tail(query, cursor)
                .map_err(|failure| format!("attempt {attempt} resume failed: {failure:?}"))?;
            drop(resumed);
        }
        clock.set(100);
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

#[test]
fn tail_cursor_resumes_after_ledger_reopen_without_a_gap() -> Result<(), Box<dyn Error>> {
    let mut fixture = QueryFixture::new("tail-restart-resume")?;
    fixture.kernel.append_log("before-restart", 1, 1)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let cursor = {
        let service = fixture.service(16)?;
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | limit all",
            budget,
        )?;
        let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
        assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
        let Some(TailEvent::Batch(batch)) = tail.poll() else {
            return Err("restart history batch missing".into());
        };
        tail.acknowledge(batch.sequence(), batch.digest())?;
        tail.cursor().clone()
    };

    fixture.kernel.reopen_ledger()?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut resumed = service.resume_tail(query, &cursor)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    assert!(matches!(resumed.poll(), Some(TailEvent::Idle)));

    fixture.kernel.append_log("after-restart", 2, 2)?;
    let Some(TailEvent::Batch(batch)) = resumed.poll() else {
        return Err("restarted tail missed the post-restart record".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("after-restart"));
    resumed.disconnect();
    assert!(matches!(
        resumed.poll(),
        Some(TailEvent::Terminal(TailTerminal::Disconnected { .. }))
    ));
    Ok(())
}

#[test]
fn tail_historical_resume_rejects_a_pruned_handoff_before_ack() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-historical-pruned-handoff")?;
    fixture.kernel.append_log("historical", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(_)) = tail.poll() else {
        return Err("historical batch missing".into());
    };
    let handoff = fixture
        .kernel
        .ledger()?
        .reader()?
        .snapshot()?
        .frontier()
        .value()
        .checked_add(1)
        .ok_or("handoff overflow")?;
    let mut bytes = tail.cursor().as_bytes().to_vec();
    let payload_len = bytes.len().checked_sub(32).ok_or("cursor tag missing")?;
    let positions_end = 276_usize;
    let extension_start = positions_end;
    let handoff_offset = extension_start
        .checked_add(14)
        .ok_or("handoff offset overflow")?;
    bytes
        .get_mut(handoff_offset..handoff_offset + 8)
        .ok_or("handoff bytes missing")?
        .copy_from_slice(&handoff.to_be_bytes());
    let protector = fixture.kernel.ledger()?.control_tokens();
    let authentication = protector.authenticate_query_cursor(
        b"tail-cursor-v3",
        bytes.get(..payload_len).ok_or("cursor payload missing")?,
    )?;
    bytes
        .get_mut(payload_len..)
        .ok_or("cursor tag missing")?
        .copy_from_slice(&authentication.tag());
    let forged = TailCursor::from_bytes(&bytes)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    assert!(matches!(
        service.resume_tail(query, &forged),
        Err(failure) if failure.code() == QueryFailureCode::StoreUnavailable
    ));
    Ok(())
}

#[test]
fn tail_historical_cursor_rejects_a_corrupted_continuation_key() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-historical-key-corruption")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(1),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "first".to_owned(),
                )),
            ),
            (
                Some(2),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "second".to_owned(),
                )),
            ),
        ],
        1,
    )?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("historical key batch missing".into());
    };
    tail.acknowledge(batch.sequence(), batch.digest())?;
    let cursor = tail.cursor().clone();
    let protector = fixture.kernel.ledger()?.control_tokens();
    let authenticate = |bytes: &mut Vec<u8>| -> Result<(), Box<dyn Error>> {
        let payload_len = bytes.len().checked_sub(32).ok_or("cursor tag missing")?;
        let authentication = protector.authenticate_query_cursor(
            b"tail-cursor-v3",
            bytes.get(..payload_len).ok_or("cursor payload missing")?,
        )?;
        bytes
            .get_mut(payload_len..)
            .ok_or("cursor tag missing")?
            .copy_from_slice(&authentication.tag());
        Ok(())
    };
    let positions_end = 276_usize;
    let stats_end = positions_end + 6 + 16 + 18;

    let mut invalid_flag = cursor.as_bytes().to_vec();
    invalid_flag[stats_end] = 2;
    authenticate(&mut invalid_flag)?;
    assert_eq!(
        TailCursor::decode(&protector, &TailCursor::from_bytes(&invalid_flag)?)
            .expect_err("unknown historical key flag")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    let mut absent_key = cursor.as_bytes().to_vec();
    absent_key[stats_end] = 1;
    let key_start = stats_end + 1;
    absent_key
        .get_mut(key_start..key_start + 68)
        .ok_or("historical key bytes missing")?
        .fill(0);
    authenticate(&mut absent_key)?;
    assert_eq!(
        TailCursor::decode(&protector, &TailCursor::from_bytes(&absent_key)?)
            .expect_err("zero historical key")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    Ok(())
}

#[test]
fn tail_cursor_tamper_fails_closed_on_resume() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let mut bytes = tail.cursor().as_bytes().to_vec();
    let slot = bytes.get_mut(24).ok_or("tail cursor body is bounded")?;
    *slot ^= 1;
    let tampered = positron_query::TailCursor::from_bytes(&bytes)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    assert!(service.resume_tail(query, &tampered).is_err());
    Ok(())
}

#[test]
fn tail_cursor_public_state_and_wire_boundaries_fail_closed() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-cursor-boundaries")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let cursor = tail.cursor().clone();
    let state = TailCursor::decode(&fixture.kernel.ledger()?.control_tokens(), &cursor)?;
    assert_eq!(state.principal(), fixture.context.principal_id());
    assert_eq!(
        state.tenant(),
        fixture
            .context
            .tenant_attribution()
            .ok_or("tenant")?
            .tenant_id()
    );
    assert_eq!(
        state.authorization_generation(),
        fixture.context.authorization_generation()
    );
    assert_eq!(state.plan_digest(), state.plan_digest());
    assert_eq!(state.signal_digest(), state.signal_digest());
    assert!(state.budget_digest().iter().any(|byte| *byte != 0));
    assert_eq!(state.sequence(), 0);
    assert_eq!(state.prior_digest(), [0; 32]);
    assert_eq!(
        state.positions()[0].ordinal(),
        positron_domain::routing::RecordOrdinal::first()
    );
    assert!(
        state
            .validate_for_resume(
                state.principal(),
                state.tenant(),
                state.authorization_generation(),
                [0; 32],
                state.signal_digest(),
                100,
            )
            .is_err()
    );
    assert!(
        state
            .validate_for_resume(
                state.principal(),
                state.tenant(),
                state.authorization_generation(),
                state.plan_digest(),
                state.signal_digest(),
                state.expiry(),
            )
            .is_err()
    );
    assert!(
        TailCursorState::new(
            state.principal(),
            state.tenant(),
            state.authorization_generation(),
            state.plan_digest(),
            state.signal_digest(),
            Vec::new(),
            state.expiry(),
            state.sequence(),
            state.prior_digest(),
        )
        .is_err()
    );
    assert!(
        TailCursorState::new(
            state.principal(),
            state.tenant(),
            state.authorization_generation(),
            state.plan_digest(),
            state.signal_digest(),
            vec![state.positions()[0], state.positions()[0]],
            state.expiry(),
            state.sequence(),
            state.prior_digest(),
        )
        .is_err()
    );
    assert!(TailCursor::from_bytes(&[]).is_err());
    let mut bad_version = cursor.as_bytes().to_vec();
    bad_version[9] = 0;
    assert!(
        TailCursor::decode(
            &fixture.kernel.ledger()?.control_tokens(),
            &TailCursor::from_bytes(&bad_version)?,
        )
        .is_err()
    );
    let mut bad_count = cursor.as_bytes().to_vec();
    bad_count[258] = 0;
    bad_count[259] = 0;
    assert!(
        TailCursor::decode(
            &fixture.kernel.ledger()?.control_tokens(),
            &TailCursor::from_bytes(&bad_count)?,
        )
        .is_err()
    );
    let protector = fixture.kernel.ledger()?.control_tokens();
    let authenticate = |bytes: &mut Vec<u8>| -> Result<(), Box<dyn Error>> {
        let payload_len = bytes.len().checked_sub(32).ok_or("cursor tag missing")?;
        let authentication = protector.authenticate_query_cursor(
            b"tail-cursor-v3",
            bytes.get(..payload_len).ok_or("cursor payload missing")?,
        )?;
        bytes
            .get_mut(payload_len..)
            .ok_or("cursor tag missing")?
            .copy_from_slice(&authentication.tag());
        Ok(())
    };
    let mut zero_count = cursor.as_bytes().to_vec();
    authenticate(&mut zero_count)?;
    zero_count[258] = 0;
    zero_count[259] = 0;
    authenticate(&mut zero_count)?;
    assert!(TailCursor::decode(&protector, &TailCursor::from_bytes(&zero_count)?).is_err());

    let mut mismatched_length = cursor.as_bytes().to_vec();
    mismatched_length[258] = 0;
    mismatched_length[259] = 2;
    authenticate(&mut mismatched_length)?;
    assert!(TailCursor::decode(&protector, &TailCursor::from_bytes(&mismatched_length)?,).is_err());

    let mut short_positions = cursor.as_bytes().to_vec();
    short_positions[258] = 0;
    short_positions[259] = 2;
    short_positions.truncate(292 + 32 - 7);
    authenticate(&mut short_positions)?;
    assert!(TailCursor::decode(&protector, &TailCursor::from_bytes(&short_positions)?).is_err());

    let mut short_stats = cursor.as_bytes().to_vec();
    short_stats.truncate(300 + 32 - 1);
    authenticate(&mut short_stats)?;
    assert!(TailCursor::decode(&protector, &TailCursor::from_bytes(&short_stats)?).is_err());

    let mut mismatched_marker_count = cursor.as_bytes().to_vec();
    mismatched_marker_count[280] = 0;
    mismatched_marker_count[281] = 2;
    authenticate(&mut mismatched_marker_count)?;
    assert!(
        TailCursor::decode(
            &protector,
            &TailCursor::from_bytes(&mismatched_marker_count)?,
        )
        .is_err()
    );

    let mut invalid_extension = cursor.as_bytes().to_vec();
    invalid_extension[276] ^= 1;
    authenticate(&mut invalid_extension)?;
    assert!(TailCursor::decode(&protector, &TailCursor::from_bytes(&invalid_extension)?).is_err());

    let mut invalid_runtime_flag = cursor.as_bytes().to_vec();
    invalid_runtime_flag[298] = 2;
    authenticate(&mut invalid_runtime_flag)?;
    assert!(
        TailCursor::decode(&protector, &TailCursor::from_bytes(&invalid_runtime_flag)?,).is_err()
    );

    let mut mismatched_binding_count = cursor.as_bytes().to_vec();
    mismatched_binding_count[304] = 0;
    mismatched_binding_count[305] = 2;
    authenticate(&mut mismatched_binding_count)?;
    assert!(
        TailCursor::decode(
            &protector,
            &TailCursor::from_bytes(&mismatched_binding_count)?,
        )
        .is_err()
    );

    let mut truncated_binding_payload = cursor.as_bytes().to_vec();
    let payload_len = truncated_binding_payload
        .len()
        .checked_sub(32)
        .ok_or("cursor tag missing")?;
    let bindings_start = truncated_binding_payload
        .get(..payload_len)
        .ok_or("cursor payload missing")?
        .windows(4)
        .position(|window| window == b"TB01")
        .ok_or("source bindings missing")?;
    assert!(bindings_start < payload_len);
    truncated_binding_payload.truncate(payload_len - 1);
    truncated_binding_payload.extend_from_slice(&[0; 32]);
    authenticate(&mut truncated_binding_payload)?;
    let failure = TailCursor::decode(
        &protector,
        &TailCursor::from_bytes(&truncated_binding_payload)?,
    )
    .expect_err("truncated authenticated bindings must fail closed");
    assert_eq!(failure.code(), QueryFailureCode::InvalidCursor);

    let mut trailing_binding = cursor.as_bytes().to_vec();
    let payload_len = trailing_binding
        .len()
        .checked_sub(32)
        .ok_or("cursor tag missing")?;
    trailing_binding.insert(payload_len, 0);
    authenticate(&mut trailing_binding)?;
    assert!(TailCursor::decode(&protector, &TailCursor::from_bytes(&trailing_binding)?).is_err());

    let mut invalid_marker = cursor.as_bytes().to_vec();
    invalid_marker[260 + 14] = 2;
    authenticate(&mut invalid_marker)?;
    assert!(TailCursor::decode(&protector, &TailCursor::from_bytes(&invalid_marker)?,).is_err());

    let two_positions = TailCursorState::new(
        state.principal(),
        state.tenant(),
        state.authorization_generation(),
        state.plan_digest(),
        state.signal_digest(),
        vec![
            state.positions()[0],
            TailPosition::new(VirtualShardId::new(2)?, state.positions()[0].position()),
        ],
        state.expiry(),
        state.sequence(),
        state.prior_digest(),
    )?;
    let two_position_cursor = TailCursor::encode(&protector, &two_positions)?;
    let mut inconsistent_marker = two_position_cursor.as_bytes().to_vec();
    inconsistent_marker[244 + 16 + 14] = 1;
    authenticate(&mut inconsistent_marker)?;
    assert!(
        TailCursor::decode(&protector, &TailCursor::from_bytes(&inconsistent_marker)?,).is_err()
    );

    let mut trailing = cursor.as_bytes().to_vec();
    trailing.push(0);
    assert!(
        TailCursor::decode(
            &fixture.kernel.ledger()?.control_tokens(),
            &TailCursor::from_bytes(&trailing)?,
        )
        .is_err()
    );
    assert!(format!("{cursor:?}").contains("opaque"));
    assert!(TailSourceSet::new(Vec::new()).is_err());
    let reader = fixture.kernel.ledger()?.reader()?;
    let duplicate_sources = TailSourceSet::new(vec![reader, fixture.kernel.ledger()?.reader()?]);
    assert!(matches!(
        duplicate_sources,
        Err(failure) if failure.code() == QueryFailureCode::Unauthorized
    ));
    let traces = ActiveSegmentLedger::open(
        fixture.kernel.authority,
        fixture.kernel.catalog_for_test(),
        positron_kernel::SegmentScope::new(
            state.tenant(),
            SignalKind::Traces,
            VirtualShardId::new(3)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x63; 32])),
    )?;
    assert!(matches!(
        TailSourceSet::new(vec![traces.reader()?]),
        Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
    ));
    Ok(())
}

#[test]
fn tail_rejects_a_source_without_a_ledger_lease_capability_before_snapshot_work()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-source-lease-capability")?;
    let reader = CommittedLedgerReader::open(
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
        SegmentProtectionKey::from_owned(Box::new([0x64; 32])),
    )?;
    let sources = TailSourceSet::new(vec![reader])?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?,
    )?;
    assert!(matches!(
        service.tail_with_sources(query, TailStart::Now, sources),
        Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
    ));
    Ok(())
}

#[test]
fn tail_rejects_a_source_for_another_tenant_and_invalid_buffer_budget() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-source-tenant-boundary")?;
    let other_tenant = positron_domain::identity::TenantId::from_bytes([0x91; 16])?;
    let other = CommittedLedgerReader::open(
        fixture.kernel.authority,
        fixture.kernel.catalog_for_test(),
        positron_kernel::SegmentScope::new(other_tenant, SignalKind::Logs, VirtualShardId::new(2)?),
        SegmentProtectionKey::from_owned(Box::new([0x65; 32])),
    )?;
    let sources = TailSourceSet::new(vec![other])?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?,
    )?;
    assert!(matches!(
        service.tail_with_sources(query, TailStart::Now, sources),
        Err(failure) if failure.code() == QueryFailureCode::Unauthorized
    ));

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        QueryBudget::new(1_048_576, 16, 1, 16_777_217, 1_048_576, 60)?,
    )?;
    assert!(matches!(
        service.tail(query, TailStart::Now),
        Err(failure) if failure.code() == QueryFailureCode::InvalidBudget
    ));
    Ok(())
}

#[test]
fn tail_scan_cancellation_is_one_typed_terminal() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-scan-cancel")?;
    let meter = CancellingStageWorkMeter::shared(positron_query::QueryWorkStage::ScanDecode);
    let service = positron_query::QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        meter.clone(),
    );
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    meter.bind(query.cancellation())?;
    let mut tail = match service.tail(query, TailStart::Now) {
        Ok(tail) => tail,
        Err(failure) => return Err(format!("tail admission failed: {failure:?}").into()),
    };
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("cancelled", 1, 1)?;
    let event = tail.poll();
    assert!(matches!(
        event,
        Some(TailEvent::Terminal(TailTerminal::Cancelled {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_operator_cpu_budget_fails_before_delivering_an_overrun_batch() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-operator-cpu-boundary")?;
    let service = stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source =
        "pipeline:v1 logs | range query_time -100 100 | project body, query_time | limit all";
    let minimum_plan_cpu = (1..=1_024)
        .find_map(|units| {
            let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)
                .ok()?
                .with_cpu_work_units(units)
                .ok()?;
            service
                .plan_pipeline(fixture.context, source, budget)
                .ok()
                .map(|_| units)
        })
        .ok_or("no plan-admissible CPU budget")?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?
        .with_cpu_work_units(minimum_plan_cpu)?;
    let query = service
        .plan_pipeline(fixture.context, source, budget)
        .map_err(|failure| format!("tail operator plan failed: {failure:?}"))?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_logs(
        (1_i64..=2)
            .map(|event_time| {
                (
                    Some(event_time),
                    Some(positron_domain::value::CandidateAttributeValue::string(
                        "cpu".to_owned(),
                    )),
                )
            })
            .collect(),
        1,
    )?;
    let event = tail.poll();
    assert!(matches!(
        event,
        Some(TailEvent::Terminal(TailTerminal::BudgetExhausted {
            cursor: Some(_),
            stats,
        })) if stats.limiting_budget() == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_operator_work_overflow_emits_one_terminal_without_a_batch() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-operator-work-overflow")?;
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        std::sync::Arc::new(OperatorOverflowWorkMeter),
    );
    let budget =
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1_024)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | project body | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let safe_cursor = tail.cursor().clone();
    fixture.kernel.append_log("operator-overflow", 1, 1)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::BudgetExhausted {
            cursor: Some(cursor),
            stats,
        })) if cursor == safe_cursor
            && stats.limiting_budget()
                == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
            && stats.emitted_records() == 0
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_resume_cpu_progress_overflow_is_terminal_without_advancing() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-cpu-overflow")?;
    let service = stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source =
        "pipeline:v1 logs | range query_time -100 100 | project body, query_time | limit all";
    let budget =
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1_024)?;
    let query = service.plan_pipeline(fixture.context, source, budget)?;
    let mut initial = service.tail(query, TailStart::Now)?;
    assert!(matches!(initial.poll(), Some(TailEvent::Header(_))));
    let forged = tail_cursor_with_cpu_progress(
        &fixture.kernel.ledger()?.control_tokens(),
        initial.cursor(),
        u64::MAX,
    )?;
    drop(initial);

    let query = service.plan_pipeline(fixture.context, source, budget)?;
    let mut resumed = service
        .resume_tail(query, &forged)
        .map_err(|failure| format!("resume tail: {failure:?}"))?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    let safe_cursor = resumed.cursor().clone();
    fixture.kernel.append_log("resume-cpu-overflow", 1, 1)?;
    assert!(matches!(
        resumed.poll(),
        Some(TailEvent::Terminal(TailTerminal::BudgetExhausted {
            cursor: Some(cursor),
            stats,
        })) if cursor == safe_cursor
            && stats.limiting_budget()
                == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
            && stats.emitted_records() == 0
    ));
    assert!(resumed.poll().is_none());
    Ok(())
}

#[test]
fn tail_materialize_cpu_addition_overflow_preserves_cursor() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-materialize-cpu-overflow")?;
    let initial_service = stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source =
        "pipeline:v1 logs | range query_time -100 100 | project body, query_time | limit all";
    let budget =
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1_024)?;
    fixture
        .kernel
        .append_log("materialize-cpu-overflow", 1, 1)?;
    let query = initial_service.plan_pipeline(fixture.context, source, budget)?;
    let mut initial = initial_service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(initial.poll(), Some(TailEvent::Header(_))));
    let forged = tail_cursor_with_cpu_progress(
        &fixture.kernel.ledger()?.control_tokens(),
        initial.cursor(),
        budget.cpu_work_units() - 1,
    )?;
    drop(initial);

    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        std::sync::Arc::new(OperatorOverflowWorkMeter),
    );
    let query = service.plan_pipeline(fixture.context, source, budget)?;
    let mut resumed = service.resume_tail(query, &forged)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    let safe_cursor = resumed.cursor().clone();
    assert!(matches!(
        resumed.poll(),
        Some(TailEvent::Terminal(TailTerminal::BudgetExhausted {
            cursor: Some(cursor),
            stats,
        })) if cursor == safe_cursor
            && stats.limiting_budget()
                == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
            && stats.emitted_records() == 0
    ));
    assert!(resumed.poll().is_none());
    Ok(())
}

#[test]
fn tail_materialize_cpu_multiplication_overflow_preserves_cursor() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-materialize-cpu-multiplication-overflow")?;
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        std::sync::Arc::new(OperatorOverflowWorkMeter),
    );
    let source = "pipeline:v1 logs | range query_time -100 100 | cast body as string | project body, query_time | limit all";
    let budget =
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1_024)?;
    let query = service
        .plan_pipeline(fixture.context, source, budget)
        .map_err(|failure| format!("plan: {failure:?}"))?;
    let mut tail = service
        .tail(query, TailStart::Now)
        .map_err(|failure| format!("tail: {failure:?}"))?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let safe_cursor = tail.cursor().clone();
    fixture
        .kernel
        .append_log("materialize-cpu-multiplication-overflow", 2, 2)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::BudgetExhausted {
            cursor: Some(cursor),
            stats,
        })) if cursor == safe_cursor
            && stats.limiting_budget()
                == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
            && stats.emitted_records() == 0
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_admission_rejects_wall_expiry_overflow() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-expiry-overflow")?;
    let service = positron_query::QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(u64::MAX),
        std::sync::Arc::new(ConstantWorkMeter(0)),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?,
    )?;
    assert!(matches!(
        service.tail(query, TailStart::Now),
        Err(failure) if failure.code() == QueryFailureCode::InvalidBudget
    ));
    Ok(())
}

#[test]
fn tail_output_size_work_failure_is_terminal_before_delivery() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-output-work-failure")?;
    let meter = FailAfterArmOutputMeter::shared(0);
    meter.arm();
    let work_meter: std::sync::Arc<dyn positron_query::QueryWorkMeter> = meter;
    let service = positron_query::QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        work_meter,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | project body | limit all",
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("output-failure", 1, 1)?;
    let event = tail.poll();
    assert!(matches!(
        event,
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_digest_work_failure_is_terminal_before_delivery() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-digest-work-failure")?;
    let meter = FailAfterArmOutputMeter::shared(1);
    meter.arm();
    let work_meter: std::sync::Arc<dyn positron_query::QueryWorkMeter> = meter;
    let service = positron_query::QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        work_meter,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | project body | limit all",
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("digest-failure", 1, 1)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_historical_output_work_failures_never_publish_a_batch() -> Result<(), Box<dyn Error>> {
    for (name, fail_after) in [("size", 0), ("digest", 1)] {
        let fixture_name = format!("tail-historical-{name}-failure");
        let fixture = QueryFixture::new(&fixture_name)?;
        fixture
            .kernel
            .append_log("historical-output-failure", 1, 1)?;
        let meter = FailAfterArmOutputMeter::shared(fail_after);
        meter.arm();
        let work_meter: std::sync::Arc<dyn positron_query::QueryWorkMeter> = meter;
        let service = positron_query::QueryService::with_runtime(
            fixture.kernel.authority.governor(),
            fixture.kernel.ledger()?,
            16,
            TestClock::shared(100),
            work_meter,
        );
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | project body | limit all",
            QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?,
        )?;
        let failure = match service.tail(query, TailStart::Historical { max_rows: 1 }) {
            Ok(_) => return Err("historical output failure unexpectedly admitted".into()),
            Err(failure) => failure,
        };
        assert_eq!(failure.code(), QueryFailureCode::Internal);
    }
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn tail_terminal_cursor_sync_failure_is_framed_once() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-terminal-sync-failure")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let _fault_lock = TAIL_CURSOR_FAULT_LOCK
        .lock()
        .map_err(|_| "fault lock poisoned")?;
    positron_query::fail_next_tail_cursor_encode();
    tail.disconnect();
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_admission_rejects_cancelled_and_invalid_historical_requests() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-admission-boundaries")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let failure = match service.tail(query, TailStart::Historical { max_rows: 0 }) {
        Ok(_) => return Err("zero historical rows unexpectedly admitted".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::InvalidBudget);
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    query.cancellation().cancel();
    let failure = match service.tail(query, TailStart::Now) {
        Ok(_) => return Err("cancelled admission unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::Cancelled);
    Ok(())
}

#[test]
fn tail_revalidates_expiry_and_lifecycle_before_following() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-revalidate-expiry")?;
    let clock = TestClock::shared(100);
    let service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        clock.clone(),
    );
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    clock.set(160);
    let event = tail.poll();
    assert!(matches!(
        event,
        Some(TailEvent::Terminal(TailTerminal::Expired {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());

    let fixture = QueryFixture::new("tail-revalidate-lifecycle")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.publish_lifecycle_for_test(3, 0xd4)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::AuthorizationChanged {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_admission_rejects_expired_budget_and_cursor_vector_mismatch() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-admission-expired")?;
    let clock = TestClock::shared(100);
    let service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        clock.clone(),
    );
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    clock.set(160);
    let failure = match service.tail(query, TailStart::Now) {
        Ok(_) => return Err("expired tail admission unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::SnapshotExpired);

    let fixture = QueryFixture::new("tail-resume-vector")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let state = TailCursor::decode(&fixture.kernel.ledger()?.control_tokens(), tail.cursor())?;
    let positions = vec![
        state.positions()[0],
        TailPosition::new(VirtualShardId::new(2)?, state.positions()[0].position()),
    ];
    let vector_cursor = TailCursor::encode(
        &fixture.kernel.ledger()?.control_tokens(),
        &TailCursorState::new(
            state.principal(),
            state.tenant(),
            state.authorization_generation(),
            state.plan_digest(),
            state.signal_digest(),
            positions,
            state.expiry(),
            state.sequence(),
            state.prior_digest(),
        )?,
    )?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let failure = match service.resume_tail(query, &vector_cursor) {
        Ok(_) => return Err("mismatched cursor vector unexpectedly resumed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::InvalidCursor);

    let missing_source_position = TailCursor::encode(
        &fixture.kernel.ledger()?.control_tokens(),
        &TailCursorState::new(
            state.principal(),
            state.tenant(),
            state.authorization_generation(),
            state.plan_digest(),
            state.signal_digest(),
            vec![TailPosition::new(
                VirtualShardId::new(2)?,
                state.positions()[0].position(),
            )],
            state.expiry(),
            state.sequence(),
            state.prior_digest(),
        )?,
    )?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let failure = match service.resume_tail(query, &missing_source_position) {
        Ok(_) => return Err("cursor without a source position unexpectedly resumed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::InvalidCursor);
    Ok(())
}

#[test]
fn tail_follow_maps_a_later_store_failure_to_one_terminal() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-follow-store-failure")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_malformed_log_block(1)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_follow_maps_cumulative_budget_exhaustion_to_one_terminal() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-follow-budget")?;
    let service = stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let budget =
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(2)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"budget\" | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_logs(
        (1_i64..=16)
            .map(|event_time| {
                (
                    Some(event_time),
                    Some(positron_domain::value::CandidateAttributeValue::string(
                        "budget".to_owned(),
                    )),
                )
            })
            .collect(),
        1,
    )?;
    let mut budget_terminal = false;
    for _ in 0..4 {
        match tail.poll() {
            Some(TailEvent::Terminal(TailTerminal::BudgetExhausted {
                cursor: Some(_), ..
            })) => {
                budget_terminal = true;
                break;
            },
            Some(_) => {},
            None => break,
        }
    }
    assert!(budget_terminal);
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_follow_maps_output_bytes_budget_to_one_terminal() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-follow-output-bytes")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | project body | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("larger-than-budget", 1, 1)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::BudgetExhausted {
            cursor: Some(_),
            ..
        }))
    ));

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | project body | limit 1",
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute_page(query)?.collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    Ok(())
}

#[test]
fn tail_follow_rechecks_output_rows_after_acknowledgement() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-follow-output-rows")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));

    fixture.kernel.append_log("first", 1, 1)?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("first tail batch missing".into());
    };
    tail.acknowledge(batch.sequence(), batch.digest())?;

    fixture.kernel.append_log("second", 2, 2)?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("second tail batch missing".into());
    };
    tail.acknowledge(batch.sequence(), batch.digest())?;

    fixture.kernel.append_log("third", 3, 3)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::BudgetExhausted {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn page_operator_cancellation_reports_a_framed_terminal() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("page-cancel-after-scan")?;
    fixture.kernel.append_log("cancel-after-scan", 1, 1)?;
    let meter = CancellingStageWorkMeter::shared(positron_query::QueryWorkStage::Operators);
    let service = positron_query::QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
        std::sync::Arc::clone(&meter) as std::sync::Arc<dyn positron_query::QueryWorkMeter>,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"cancel-after-scan\" | limit 1",
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?,
    )?;
    meter.bind(query.cancellation())?;
    let mut stream = service.execute_page(query)?;
    assert!(matches!(stream.next(), Some(QueryEvent::Header(_))));
    let event = stream.next();
    let debug = format!("{event:?}");
    assert!(
        matches!(
            event.as_ref(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::Cancelled
        ),
        "unexpected event: {debug}"
    );
    Ok(())
}

#[test]
fn tail_external_cancellation_is_revalidated_before_following() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-follow-cancellation")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let cancellation = query.cancellation();
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    cancellation.cancel();
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Cancelled {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_cursor_binds_a_bounded_multi_shard_source_set() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-shards")?;
    fixture.kernel.append_log("one", 1, 1)?;
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
        SegmentProtectionKey::from_owned(Box::new([0x35; 32])),
    )?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![(
            Some(2),
            Some(positron_domain::value::CandidateAttributeValue::string(
                "two".to_owned(),
            )),
        )],
        2,
    )?;
    let sources = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?, second.reader()?])?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail =
        service.tail_with_sources(query, TailStart::Historical { max_rows: 4 }, sources)?;
    let state = TailCursor::decode(&fixture.kernel.ledger()?.control_tokens(), tail.cursor())?;
    assert_eq!(state.positions().len(), 2);
    assert_eq!(state.positions()[0].shard(), VirtualShardId::new(1)?);
    assert_eq!(state.positions()[1].shard(), VirtualShardId::new(2)?);
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("multi-shard tail batch missing".into());
    };
    assert_eq!(batch.records().len(), 2);
    assert_eq!(batch.records()[0].body_text(), Some("one"));
    assert_eq!(batch.records()[1].body_text(), Some("two"));
    tail.acknowledge(batch.sequence(), batch.digest())
        .map_err(|failure| format!("historical ack: {failure:?}"))?;
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    fixture.kernel.append_log("live-one", 3, 3)?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![(
            Some(4),
            Some(positron_domain::value::CandidateAttributeValue::string(
                "live-two".to_owned(),
            )),
        )],
        4,
    )?;
    let event = tail.poll();
    let Some(TailEvent::Batch(batch)) = event else {
        return Err(format!("multi-shard live tail batch missing: {event:?}").into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("live-one"));
    assert_eq!(batch.records()[1].body_text(), Some("live-two"));
    tail.acknowledge(batch.sequence(), batch.digest())
        .map_err(|failure| format!("live ack: {failure:?}"))?;
    let cursor = tail.cursor().clone();
    let mismatch = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?])?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    assert!(
        service
            .resume_tail_with_sources(query, &cursor, mismatch)
            .is_err()
    );
    Ok(())
}

#[test]
fn tail_multi_shard_secondary_release_failure_is_deferred_and_retried() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-secondary-release-retry")?;
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
        SegmentProtectionKey::from_owned(Box::new([0x71; 32])),
    )?;
    let sources = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?, second.reader()?])?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let baseline = fixture
        .kernel
        .authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail_with_sources(query, TailStart::Now, sources)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    tail.disconnect();
    let terminal =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 1, || {
            tail.poll()
        });
    assert!(matches!(
        terminal,
        Some(TailEvent::Terminal(TailTerminal::Disconnected {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    drop(tail);
    assert!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail)
            > baseline
    );
    Ok(())
}

#[test]
fn tail_historical_max_rows_is_global_across_shards() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-global-shard-limit")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(1),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "one-a".to_owned(),
                )),
            ),
            (
                Some(2),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "one-b".to_owned(),
                )),
            ),
        ],
        1,
    )?;
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
        SegmentProtectionKey::from_owned(Box::new([0x45; 32])),
    )?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![
            (
                Some(3),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "two-a".to_owned(),
                )),
            ),
            (
                Some(4),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "two-b".to_owned(),
                )),
            ),
        ],
        2,
    )?;
    let sources = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?, second.reader()?])?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 8, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail =
        service.tail_with_sources(query, TailStart::Historical { max_rows: 2 }, sources)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("global shard-limited batch missing".into());
    };
    assert_eq!(batch.records().len(), 2);
    tail.acknowledge(batch.sequence(), batch.digest())?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("remaining bounded historical batch missing".into());
    };
    assert_eq!(batch.records().len(), 2);
    tail.acknowledge(batch.sequence(), batch.digest())?;
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    Ok(())
}

#[test]
fn tail_historical_global_order_preserves_unselected_source_candidates()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-global-order-no-loss")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(20),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "a-late".to_owned(),
                )),
            ),
            (
                Some(1),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "a-early".to_owned(),
                )),
            ),
        ],
        1,
    )?;
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
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![(
            Some(2),
            Some(positron_domain::value::CandidateAttributeValue::string(
                "b-middle".to_owned(),
            )),
        )],
        2,
    )?;
    let sources = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?, second.reader()?])?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 8, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail =
        service.tail_with_sources(query, TailStart::Historical { max_rows: 2 }, sources)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(first)) = tail.poll() else {
        return Err("first historical batch missing".into());
    };
    let first_bodies = first
        .records()
        .iter()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(first_bodies, ["a-early", "b-middle"]);
    tail.acknowledge(first.sequence(), first.digest())?;

    let Some(TailEvent::Batch(second_batch)) = tail.poll() else {
        return Err("unselected historical candidate was lost".into());
    };
    let second_bodies = second_batch
        .records()
        .iter()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(second_bodies, ["a-late"]);
    tail.acknowledge(second_batch.sequence(), second_batch.digest())?;
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    Ok(())
}

#[test]
fn tail_historical_resume_uses_the_admission_snapshot_after_new_commits()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-history-pinned-resume")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(1),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "historical".to_owned(),
                )),
            ),
            (
                Some(2),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "historical-second".to_owned(),
                )),
            ),
        ],
        1,
    )?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("historical batch missing".into());
    };
    tail.acknowledge(batch.sequence(), batch.digest())?;
    let cursor = tail.cursor().clone();
    drop(tail);

    fixture.kernel.append_log("newer-commit", 0, 2)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut resumed = service.resume_tail(query, &cursor)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = resumed.poll() else {
        return Err("pinned historical row was replaced by a fresh snapshot".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("historical-second"));
    Ok(())
}

#[test]
fn tail_historical_budget_exhaustion_never_delivers_an_unknown_prefix() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-historical-budget-prefix")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(1),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "historical-first".to_owned(),
                )),
            ),
            (
                Some(2),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "historical-second".to_owned(),
                )),
            ),
        ],
        1,
    )?;
    let service = fixture.service(16)?;
    let budget =
        QueryBudget::new(1_048_576, 16, 4, 1, 1_048_576, 60)?.with_cpu_work_units(1_024)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let failure = match service.tail(query, TailStart::Historical { max_rows: 4 }) {
        Ok(_) => return Err("historical admission exposed an unknown prefix".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
    assert_eq!(
        failure.limiting_budget(),
        Some(positron_query::QueryBudgetDimension::OutputBytes)
    );

    Ok(())
}

#[test]
fn tail_historical_scan_budget_fails_before_a_retained_record() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-historical-scan-budget")?;
    fixture.kernel.append_log("scan-budget", 1, 1)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        QueryBudget::new(1, 1_024, 1, 1_048_576, 1_048_576, 60)?,
    )?;
    let failure = match service.tail(query, TailStart::Historical { max_rows: 1 }) {
        Ok(_) => return Err("a scan budget refusal exposed a historical prefix".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
    assert_eq!(
        failure.limiting_budget(),
        Some(positron_query::QueryBudgetDimension::ScannedBytes)
    );
    Ok(())
}

#[test]
fn tail_historical_cancellation_never_delivers_a_partial_window() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-historical-cancel-window")?;
    fixture.kernel.append_logs(
        (1_i64..=2)
            .map(|event_time| {
                (
                    Some(event_time),
                    Some(positron_domain::value::CandidateAttributeValue::string(
                        "historical-cancel".to_owned(),
                    )),
                )
            })
            .collect(),
        1,
    )?;
    let meter = CancellingStageWorkMeter::shared(positron_query::QueryWorkStage::Operators);
    let service = positron_query::QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        std::sync::Arc::clone(&meter) as std::sync::Arc<dyn positron_query::QueryWorkMeter>,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | project body | limit all",
        QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?,
    )?;
    meter.bind(query.cancellation())?;
    let failure = match service.tail(query, TailStart::Historical { max_rows: 4 }) {
        Ok(_) => return Err("cancelled historical materialization exposed a prefix".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::Cancelled);
    Ok(())
}

#[test]
fn tail_historical_cancellation_during_record_processing_never_publishes_a_batch()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-historical-cancel-record")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(1),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "first".to_owned(),
                )),
            ),
            (
                Some(2),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "second".to_owned(),
                )),
            ),
        ],
        1,
    )?;
    let meter = CancellingOperatorCallMeter::shared(1);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        meter.clone(),
    );
    let budget =
        QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1_024)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    meter.bind(query.cancellation())?;
    let failure = match service.tail(query, TailStart::Historical { max_rows: 4 }) {
        Ok(_) => return Err("cancelled historical materialization published".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::Cancelled);
    Ok(())
}

#[test]
fn tail_historical_empty_result_advances_only_after_the_snapshot_scan() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-historical-empty-result")?;
    fixture.kernel.append_log("not-selected", 1, 1)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"absent\" | limit all",
        QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    Ok(())
}

#[test]
fn tail_historical_rejects_a_batch_that_exceeds_output_limits() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-historical-output-limits")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(1),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "first".to_owned(),
                )),
            ),
            (
                Some(2),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "second".to_owned(),
                )),
            ),
        ],
        1,
    )?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        QueryBudget::new(1_048_576, 16, 2, 1, 1_048_576, 60)?,
    )?;
    let failure = match service.tail(query, TailStart::Historical { max_rows: 2 }) {
        Ok(_) => return Err("historical bytes unexpectedly exceeded their budget".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
    assert_eq!(
        failure.limiting_budget(),
        Some(positron_query::QueryBudgetDimension::OutputBytes)
    );

    Ok(())
}

#[test]
fn tail_historical_descending_order_keeps_commit_and_ordinal_ties_deterministic()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-historical-descending-ties")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(7),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "ordinal-first".to_owned(),
                )),
            ),
            (
                Some(7),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "ordinal-second".to_owned(),
                )),
            ),
        ],
        1,
    )?;
    fixture.kernel.append_log("newer-commit", 7, 2)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | order by query_time desc, commit_position desc | limit all",
        QueryBudget::new(1_048_576, 16, 3, 1_048_576, 1_048_576, 60)?,
    )?;
    assert!(matches!(
        service.tail(query, TailStart::Historical { max_rows: 3 }),
        Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
    ));
    Ok(())
}

#[test]
fn tail_now_advances_past_a_nonmatching_scan_before_following() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-live-filtered-cursor")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | search body contains "wanted" | limit all"#,
        QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("ignored", 1, 1)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    fixture.kernel.append_log("wanted", 2, 2)?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("tail did not follow after a nonmatching scan".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("wanted"));
    Ok(())
}

#[test]
fn tail_live_multi_shard_order_uses_commit_vector_not_event_time() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-live-shard-order")?;
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
        SegmentProtectionKey::from_owned(Box::new([0x56; 32])),
    )?;
    let sources = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?, second.reader()?])?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail_with_sources(query, TailStart::Now, sources)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("late-event", 90, 1)?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![(
            Some(1),
            Some(positron_domain::value::CandidateAttributeValue::string(
                "early-event".to_owned(),
            )),
        )],
        2,
    )?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("live multi-shard batch missing".into());
    };
    let bodies = batch
        .records()
        .iter()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["late-event", "early-event"]);
    Ok(())
}

#[test]
fn tail_ack_rolls_source_lease_forward_for_post_admission_commits() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-live-lease-roll")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("post-admission", 1, 1)?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("post-admission batch missing".into());
    };
    let initial_cursor = tail.cursor().as_bytes().to_vec();
    tail.acknowledge(batch.sequence(), batch.digest())?;
    let state = TailCursor::decode(&fixture.kernel.ledger()?.control_tokens(), tail.cursor())?;
    assert_eq!(state.positions()[0].position().value(), 1);
    assert_eq!(
        state
            .source_frontier(VirtualShardId::new(1)?)
            .map(|value| value.value()),
        Some(1)
    );
    assert_ne!(initial_cursor, tail.cursor().as_bytes());
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn tail_lease_roll_encode_failure_keeps_the_old_safe_binding() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-live-lease-roll-failure")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let safe_cursor = tail.cursor().clone();
    fixture.kernel.append_log("post-admission", 1, 1)?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("post-admission batch missing".into());
    };
    let _fault_lock = TAIL_CURSOR_FAULT_LOCK
        .lock()
        .map_err(|_| "fault lock poisoned")?;
    positron_query::fail_next_tail_cursor_encode();
    assert_eq!(
        tail.acknowledge(batch.sequence(), batch.digest())
            .expect_err("cursor encoding failure must be returned")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    assert_eq!(tail.cursor(), &safe_cursor);
    let state = TailCursor::decode(&fixture.kernel.ledger()?.control_tokens(), tail.cursor())?;
    assert_eq!(
        state
            .source_frontier(VirtualShardId::new(1)?)
            .map(|value| value.value()),
        Some(0)
    );
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable { .. }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_lease_roll_rejects_an_expired_replacement_before_publication() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-live-lease-roll-expiry")?;
    let clock = StepClock::shared(0);
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        clock,
    );
    let budget =
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 5)?.with_cpu_work_units(1_024)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("expired-roll", 1, 1)?;
    let event = tail.poll();
    let Some(TailEvent::Batch(batch)) = event else {
        return Err(format!("expired replacement batch missing: {event:?}").into());
    };
    assert_eq!(
        tail.acknowledge(batch.sequence(), batch.digest())
            .expect_err("an expired replacement must reject the acknowledgement")
            .code(),
        QueryFailureCode::SnapshotExpired
    );
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Expired { .. }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_multi_source_lease_roll_failure_restores_every_old_binding() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-live-lease-roll-rollback")?;
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
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    let third = ActiveSegmentLedger::open(
        fixture.kernel.authority,
        fixture.kernel.catalog_for_test(),
        positron_kernel::SegmentScope::new(
            fixture
                .context
                .tenant_attribution()
                .ok_or("tenant")?
                .tenant_id(),
            SignalKind::Logs,
            VirtualShardId::new(3)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![(
            Some(2),
            Some(positron_domain::value::CandidateAttributeValue::string(
                "historical-two".to_owned(),
            )),
        )],
        2,
    )?;
    fixture.kernel.append_log("historical-primary", 1, 1)?;
    let sources = TailSourceSet::new(vec![
        fixture.kernel.ledger()?.reader()?,
        second.reader()?,
        third.reader()?,
    ])?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 5, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail =
        service.tail_with_sources(query, TailStart::Historical { max_rows: 2 }, sources)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let batch = match tail.poll() {
        Some(TailEvent::Batch(batch)) => batch,
        event => {
            return Err(format!("post-admission multi-source batch missing: {event:?}").into());
        },
    };
    assert_eq!(batch.records().len(), 2);
    tail.acknowledge(batch.sequence(), batch.digest())?;
    drop(batch);
    fixture.kernel.append_log("live-primary-three", 3, 3)?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![(
            Some(4),
            Some(positron_domain::value::CandidateAttributeValue::string(
                "live-secondary-three".to_owned(),
            )),
        )],
        4,
    )?;
    fixture.kernel.append_logs_to(
        &third,
        VirtualShardId::new(3)?,
        vec![(
            Some(5),
            Some(positron_domain::value::CandidateAttributeValue::string(
                "live-tertiary-three".to_owned(),
            )),
        )],
        5,
    )?;
    let baseline = fixture.kernel.authority.governor().inspect()?;
    let event = tail.poll();
    let Some(TailEvent::Batch(batch)) = event else {
        return Err(format!("post-historical live batch missing: {event:?}").into());
    };
    assert_eq!(batch.records().len(), 3);
    let safe_cursor = tail.safe_cursor().clone();
    let failure = with_catalog_publication_fault_sequence_after(
        &[
            (CatalogPublicationFault::SynchronizeCommit, 2),
            (CatalogPublicationFault::SynchronizeCommit, 0),
            (CatalogPublicationFault::SynchronizeCommit, 0),
        ],
        || tail.acknowledge(batch.sequence(), batch.digest()),
    )
    .expect_err("a rollback publication failure must reject the ack");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert_eq!(tail.cursor(), &safe_cursor);
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable {
            cursor: None,
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    drop(batch);
    drop(tail);
    let after = fixture.kernel.authority.governor().inspect()?;
    assert!(after.outstanding_total() <= baseline.outstanding_total());
    Ok(())
}

#[test]
fn tail_primary_lease_rolls_back_after_secondary_publication_failure() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-live-primary-lease-roll-rollback")?;
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
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    let sources = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?, second.reader()?])?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail_with_sources(query, TailStart::Now, sources)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let safe_cursor = tail.cursor().clone();
    fixture.kernel.append_log("primary-roll", 1, 1)?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![(
            Some(2),
            Some(positron_domain::value::CandidateAttributeValue::string(
                "secondary-roll".to_owned(),
            )),
        )],
        2,
    )?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("primary rollback batch missing".into());
    };
    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 1, || {
            tail.acknowledge(batch.sequence(), batch.digest())
        })
        .expect_err("a secondary publication failure must roll back the primary lease");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert_eq!(tail.cursor(), &safe_cursor);
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_lease_roll_restarts_from_the_new_safe_frontier() -> Result<(), Box<dyn Error>> {
    let mut fixture = QueryFixture::new("tail-live-lease-roll-restart")?;
    let cursor = {
        let service = fixture.service(16)?;
        let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | limit all",
            budget,
        )?;
        let mut tail = service.tail(query, TailStart::Now)?;
        assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
        fixture.kernel.append_log("before-restart", 1, 1)?;
        let Some(TailEvent::Batch(batch)) = tail.poll() else {
            return Err("pre-restart batch missing".into());
        };
        tail.acknowledge(batch.sequence(), batch.digest())?;
        let cursor = tail.cursor().clone();
        drop(tail);
        cursor
    };
    fixture.kernel.reopen_ledger()?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut resumed = service.resume_tail(query, &cursor)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("after-restart", 2, 2)?;
    let event = resumed.poll();
    let Some(TailEvent::Batch(batch)) = event else {
        return Err(format!("post-restart batch missing: {event:?}").into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("after-restart"));
    Ok(())
}

#[test]
fn tail_secondary_only_sources_are_rejected_at_admission() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-secondary-only-resume")?;
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
        SegmentProtectionKey::from_owned(Box::new([0x57; 32])),
    )?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![(
            Some(1),
            Some(positron_domain::value::CandidateAttributeValue::string(
                "secondary-history".to_owned(),
            )),
        )],
        1,
    )?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let sources = TailSourceSet::new(vec![second.reader()?])?;
    assert!(matches!(
        service.tail_with_sources(query, TailStart::Historical { max_rows: 1 }, sources),
        Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
    ));
    Ok(())
}

#[test]
fn tail_multi_shard_history_uses_canonical_query_time_order() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-shard-order")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(20),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "late".to_owned(),
                )),
            ),
            (
                Some(1),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "tie-one".to_owned(),
                )),
            ),
        ],
        1,
    )?;
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
        SegmentProtectionKey::from_owned(Box::new([0x55; 32])),
    )?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![
            (
                Some(1),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "early".to_owned(),
                )),
            ),
            (
                Some(1),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "tie-two".to_owned(),
                )),
            ),
        ],
        2,
    )?;
    let sources = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?, second.reader()?])?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail =
        service.tail_with_sources(query, TailStart::Historical { max_rows: 4 }, sources)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("multi-shard ordered batch missing".into());
    };
    let bodies = batch
        .records()
        .iter()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["early", "tie-one", "tie-two", "late"]);
    tail.acknowledge(batch.sequence(), batch.digest())?;
    drop(tail);

    let limited_service = merge_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let limited_budget =
        QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1)?;
    let query = limited_service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        limited_budget,
    )?;
    let sources = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?, second.reader()?])?;
    let mut limited = limited_service.tail_with_sources(query, TailStart::Now, sources)?;
    assert!(matches!(limited.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_logs(
        vec![
            (
                Some(30),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "future-one".to_owned(),
                )),
            ),
            (
                Some(31),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "future-two".to_owned(),
                )),
            ),
        ],
        3,
    )?;
    fixture.kernel.append_logs_to(
        &second,
        VirtualShardId::new(2)?,
        vec![
            (
                Some(32),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "future-three".to_owned(),
                )),
            ),
            (
                Some(33),
                Some(positron_domain::value::CandidateAttributeValue::string(
                    "future-four".to_owned(),
                )),
            ),
        ],
        4,
    )?;
    let event = limited.poll();
    assert!(
        matches!(
            event,
            Some(TailEvent::Terminal(TailTerminal::BudgetExhausted {
                cursor: Some(_),
                ..
            }))
        ),
        "unexpected event: {event:?}"
    );
    Ok(())
}

#[test]
fn tail_resume_does_not_mark_rows_from_an_idle_cursor_as_replayed() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-replay")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let cursor = tail.cursor().clone();
    drop(tail);
    fixture.kernel.append_log("replayed", 1, 1)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut resumed = service.resume_tail(query, &cursor)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = resumed.poll() else {
        return Err("replayed tail batch missing".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("replayed"));
    assert!(!batch.records()[0].replayed());
    Ok(())
}

#[test]
fn tail_resume_starts_after_the_last_delivered_record_in_a_multi_record_block()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-partial-block-resume")?;
    fixture.kernel.append_logs(
        (1_i64..=3)
            .map(|event_time| {
                (
                    Some(event_time),
                    Some(positron_domain::value::CandidateAttributeValue::string(
                        format!("row-{event_time}"),
                    )),
                )
            })
            .collect(),
        1,
    )?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut first = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(first.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = first.poll() else {
        return Err("first partial tail batch missing".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("row-1"));
    first.acknowledge(batch.sequence(), batch.digest())?;
    let cursor = first.cursor().clone();
    drop(first);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut resumed = service.resume_tail(query, &cursor)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = resumed.poll() else {
        return Err("resumed partial tail batch missing".into());
    };
    let bodies = batch
        .records()
        .iter()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["row-2", "row-3"]);
    assert!(batch.records().iter().all(|record| !record.replayed()));
    Ok(())
}

#[test]
fn tail_resume_preserves_batch_chain_and_cumulative_output_budget() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-chain")?;
    fixture.kernel.append_log("first", 1, 1)?;
    fixture.kernel.append_log("second", 2, 2)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(first)) = tail.poll() else {
        return Err("first tail batch missing".into());
    };
    tail.acknowledge(first.sequence(), first.digest())?;
    let cursor = tail.cursor().clone();
    assert_eq!(first.sequence(), 0);
    assert_eq!(first.prior_digest(), [0; 32]);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut resumed = service.resume_tail(query, &cursor)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(second)) = resumed.poll() else {
        return Err("resumed tail batch missing".into());
    };
    assert_eq!(second.sequence(), 1);
    assert_eq!(second.prior_digest(), first.digest());
    assert_eq!(second.records()[0].body_text(), Some("second"));
    resumed.acknowledge(second.sequence(), second.digest())?;
    assert!(matches!(
        resumed.poll(),
        Some(TailEvent::Terminal(TailTerminal::BudgetExhausted {
            cursor: Some(_),
            ..
        }))
    ));
    assert!(resumed.poll().is_none());
    Ok(())
}

#[test]
fn tail_resume_retains_the_original_expiry() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-expiry")?;
    fixture.kernel.append_log("first", 1, 1)?;
    let clock = TestClock::shared(100);
    let service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        clock.clone(),
    );
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let cursor = tail.cursor().clone();
    clock.set(160);
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let failure = match service.resume_tail(query, &cursor) {
        Ok(_) => return Err("expired original tail unexpectedly resumed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::SnapshotExpired);
    Ok(())
}

#[test]
fn tail_resume_rejects_a_changed_cumulative_budget() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-budget-binding")?;
    let service = fixture.service(16)?;
    let original_budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        original_budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let cursor = tail.cursor().clone();

    let changed_budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        changed_budget,
    )?;
    let failure = match service.resume_tail(query, &cursor) {
        Ok(_) => return Err("changed tail budget unexpectedly resumed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::AuthorizationChanged);
    Ok(())
}

#[test]
fn tail_resume_rejects_a_cursor_beyond_retained_history() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-history-unavailable")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let state = TailCursor::decode(&fixture.kernel.ledger()?.control_tokens(), tail.cursor())?;
    let future = positron_domain::routing::CommitPosition::origin()
        .advance_by(std::num::NonZeroU64::new(999).ok_or("future cursor position")?)?;
    let future_state = TailCursorState::new(
        state.principal(),
        state.tenant(),
        state.authorization_generation(),
        state.plan_digest(),
        state.signal_digest(),
        vec![TailPosition::new(state.positions()[0].shard(), future)],
        state.expiry(),
        state.sequence(),
        state.prior_digest(),
    )?;
    let cursor = TailCursor::encode(&fixture.kernel.ledger()?.control_tokens(), &future_state)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let failure = match service.resume_tail(query, &cursor) {
        Ok(_) => return Err("cursor beyond the retained frontier unexpectedly resumed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    Ok(())
}

#[test]
fn tail_resume_rejects_a_record_cursor_without_its_retained_block() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-record-history-gap")?;
    fixture.kernel.append_log("frontier", 1, 10)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let mut bytes = tail.cursor().as_bytes().to_vec();
    drop(tail);

    let position_offset = 260 + 4;
    bytes[position_offset..position_offset + 8].copy_from_slice(&5_u64.to_be_bytes());
    bytes[260 + 14] = 1;
    let payload_len = bytes.len().checked_sub(32).ok_or("cursor tag missing")?;
    let authentication = fixture
        .kernel
        .ledger()?
        .control_tokens()
        .authenticate_query_cursor(
            b"tail-cursor-v3",
            bytes.get(..payload_len).ok_or("cursor payload missing")?,
        )?;
    bytes
        .get_mut(payload_len..)
        .ok_or("cursor tag missing")?
        .copy_from_slice(&authentication.tag());
    let cursor = TailCursor::from_bytes(&bytes)?;
    let decoded = TailCursor::decode(&fixture.kernel.ledger()?.control_tokens(), &cursor)?;
    assert!(decoded.record_bound());

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    assert!(matches!(
        service.resume_tail(query, &cursor),
        Err(failure) if failure.code() == QueryFailureCode::StoreUnavailable
    ));
    Ok(())
}

#[test]
fn tail_resume_rejects_a_source_binding_with_a_different_frontier() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-binding-frontier")?;
    fixture.kernel.append_log("frontier-binding", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let cursor = tail_cursor_with_source_binding(
        &fixture.kernel.ledger()?.control_tokens(),
        tail.cursor(),
        None,
        Some(2),
    )?;

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let failure = match service.resume_tail(query, &cursor) {
        Ok(_) => return Err("a source binding frontier mismatch resumed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    Ok(())
}

#[test]
fn tail_resume_rejects_an_unknown_source_lease_without_mutation() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume-unknown-lease")?;
    fixture.kernel.append_log("unknown-lease", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut initial = service.tail(query, TailStart::Now)?;
    assert!(matches!(initial.poll(), Some(TailEvent::Header(_))));
    let cursor = tail_cursor_with_source_lease(
        &fixture.kernel.ledger()?.control_tokens(),
        initial.cursor(),
        [0xa7; 16],
    )?;
    let cursor_bytes = cursor.as_bytes().to_vec();
    drop(initial);
    let baseline = fixture.kernel.authority.governor().inspect()?;

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let failure = match service.resume_tail(query, &cursor) {
        Ok(_) => return Err("an unknown source lease unexpectedly resumed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    let after = fixture.kernel.authority.governor().inspect()?;
    assert_eq!(after.outstanding_total(), baseline.outstanding_total());
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), baseline.usage(dimension));
    }
    assert_eq!(cursor.as_bytes(), cursor_bytes.as_slice());
    Ok(())
}

#[test]
fn tail_resume_rejects_a_source_binding_with_a_different_generation() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-resume-binding-generation")?;
    fixture.kernel.append_log("generation-binding", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut initial = service.tail(query, TailStart::Now)?;
    assert!(matches!(initial.poll(), Some(TailEvent::Header(_))));
    let cursor = tail_cursor_with_source_binding(
        &fixture.kernel.ledger()?.control_tokens(),
        initial.cursor(),
        Some(u64::MAX),
        None,
    )?;
    let cursor_bytes = cursor.as_bytes().to_vec();
    drop(initial);
    let baseline = fixture.kernel.authority.governor().inspect()?;

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let failure = match service.resume_tail(query, &cursor) {
        Ok(_) => return Err("a source binding generation mismatch resumed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    let after = fixture.kernel.authority.governor().inspect()?;
    assert_eq!(after.outstanding_total(), baseline.outstanding_total());
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), baseline.usage(dimension));
    }
    assert_eq!(cursor.as_bytes(), cursor_bytes.as_slice());
    Ok(())
}

#[test]
fn tail_sql_rejects_a_total_limit_like_pipeline_tail() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-sql-parity")?;
    fixture.kernel.append_log("sql-value", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let source = "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 4";
    let query = service.plan_sql(fixture.context, source, budget)?;
    assert!(matches!(
        service.tail(query, TailStart::Historical { max_rows: 4 }),
        Err(failure) if failure.code() == QueryFailureCode::UnsupportedQuery
    ));
    Ok(())
}

#[test]
fn tail_rejects_future_knowledge_operators_with_a_typed_failure() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-unsupported")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count | limit all",
        budget,
    )?;
    let failure = match service.tail(query, TailStart::Now) {
        Ok(_) => return Err("aggregate tail unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::UnsupportedQuery);
    Ok(())
}

#[test]
fn tail_now_rejects_an_explicit_time_ordering() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-explicit-live-order")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | order by query_time asc, commit_position asc | limit all",
        budget,
    )?;
    let failure = match service.tail(query, TailStart::Now) {
        Ok(_) => return Err("a live explicit time ordering unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::UnsupportedQuery);
    Ok(())
}

#[test]
fn tail_reads_committed_active_and_sealed_rows_without_a_complete_terminal()
-> Result<(), Box<dyn Error>> {
    let mut fixture = QueryFixture::new("tail-sealed")?;
    fixture.kernel.append_log("sealed", 1, 1)?;
    fixture.kernel.seal_and_reopen()?;
    fixture.kernel.append_log("active", 2, 2)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("active and sealed tail batch missing".into());
    };
    let bodies = batch
        .records()
        .iter()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["sealed", "active"]);
    tail.acknowledge(batch.sequence(), batch.digest())?;
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    Ok(())
}

#[test]
fn tail_overflow_is_a_single_lag_terminal_and_never_complete() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-lag")?;
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
    let budget = QueryBudget::new(1_048_576, 16, 4, 300, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::ConsumerLagged { .. }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_cancel_is_one_typed_terminal_and_not_complete() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-cancel")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    tail.cancel();
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Cancelled { .. }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_cancel_and_disconnect_drop_buffered_rows_before_the_terminal() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-buffered-terminal")?;
    fixture.kernel.append_log("buffered", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut cancelled = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(cancelled.poll(), Some(TailEvent::Header(_))));
    cancelled.cancel();
    assert!(matches!(
        cancelled.poll(),
        Some(TailEvent::Terminal(TailTerminal::Cancelled { .. }))
    ));
    assert!(cancelled.poll().is_none());

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut disconnected = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(disconnected.poll(), Some(TailEvent::Header(_))));
    disconnected.disconnect();
    assert!(matches!(
        disconnected.poll(),
        Some(TailEvent::Terminal(TailTerminal::Disconnected { .. }))
    ));
    assert!(disconnected.poll().is_none());
    Ok(())
}

#[test]
fn tail_fails_closed_when_authenticated_history_is_malformed() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-history-corrupt")?;
    fixture.kernel.append_malformed_log_block(9)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let failure = match service.tail(query, TailStart::Historical { max_rows: 4 }) {
        Ok(_) => return Err("malformed tail history unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::MalformedPersistentData);
    Ok(())
}

#[test]
fn tail_preserves_typed_json_transform_values_at_the_public_record_seam()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-json")?;
    fixture
        .kernel
        .append_log(r#"{"service":"api","count":7,"ok":true}"#, 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit all",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("JSON tail batch missing".into());
    };
    let body = batch.records()[0].body_value().ok_or("JSON body missing")?;
    assert_eq!(body.kind(), AttributeValueKind::KeyValueList);
    assert_eq!(
        body.key_value_entry(1)
            .and_then(|entry| entry.value().as_signed_integer()),
        Some(7)
    );
    Ok(())
}

#[test]
fn tail_applies_logfmt_search_and_temporal_projection_before_delivery() -> Result<(), Box<dyn Error>>
{
    let search_fixture = QueryFixture::new("tail-search")?;
    search_fixture.kernel.append_log("service=api", 20, 1)?;
    search_fixture.kernel.append_log("service=worker", 21, 2)?;
    let service = search_fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        search_fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | search body contains "api" | limit all"#,
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("tail search batch missing".into());
    };
    assert_eq!(batch.records().len(), 1);
    assert_eq!(batch.records()[0].body_text(), Some("service=api"));

    let fixture = QueryFixture::new("tail-logfmt-projection")?;
    fixture.kernel.append_log(r#"service=api count=7"#, 20, 1)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | logfmt | project body, query_time, ingest_time | limit all"#,
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    let Some(TailEvent::Header(header)) = tail.poll() else {
        return Err("tail typed header missing".into());
    };
    assert_eq!(header.schema().columns().len(), 3);
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("tail typed batch missing".into());
    };
    assert_eq!(batch.records().len(), 1);
    let record = batch.records().first().ok_or("tail typed record missing")?;
    assert_eq!(
        record.body_value().map(|body| body.kind()),
        Some(AttributeValueKind::KeyValueList)
    );
    assert_eq!(
        record.query_time(),
        positron_domain::time::UnixNanoseconds::new(20)
    );
    assert_eq!(
        record
            .ingest_time_value()
            .map(|time| time.instant().value()),
        Some(50)
    );
    Ok(())
}

#[test]
fn tail_advances_the_safe_cursor_when_a_bounded_scan_has_no_matching_rows()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-filtered-cursor")?;
    fixture.kernel.append_log("present", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | search body contains "missing" | limit all"#,
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    fixture.kernel.append_log("missing", 2, 2)?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("filtered tail did not follow after advancing its safe cursor".into());
    };
    assert_eq!(batch.records().len(), 1);
    assert_eq!(batch.records()[0].body_text(), Some("missing"));
    Ok(())
}

#[test]
fn repeated_unacknowledged_delivery_keeps_memory_accounted() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-repeated-delivery-memory")?;
    fixture.kernel.append_log("first", 1, 1)?;
    let service = fixture.service(16)?;
    let budget_for = |memory| {
        QueryBudget::new(1_048_576, 16, 2, 1_048_576, memory, 60)
            .and_then(|budget| budget.with_cpu_work_units(1_024))
    };
    let source = "pipeline:v1 logs | range query_time -100 100 | limit all";
    let mut lower = 1_u64;
    let mut upper = 4_096_u64;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        if service
            .plan_pipeline(fixture.context, source, budget_for(middle)?)
            .is_ok()
        {
            upper = middle;
        } else {
            lower = middle.checked_add(1).ok_or("memory floor overflowed")?;
        }
    }
    let budget = budget_for(lower.checked_add(780).ok_or("memory budget overflowed")?)?;
    let query = service.plan_pipeline(fixture.context, source, budget)?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(first)) = tail.poll() else {
        return Err("initial tail batch missing".into());
    };
    let identity = (first.sequence(), first.digest());
    let mut repeats = Vec::new();
    for _ in 0..8 {
        let Some(TailEvent::Batch(repeated)) = tail.poll() else {
            return Err("pending batch was not repeatable".into());
        };
        assert_eq!((repeated.sequence(), repeated.digest()), identity);
        repeats.push(repeated);
    }
    tail.acknowledge(identity.0, identity.1)?;
    fixture.kernel.append_log("second", 2, 2)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::ConsumerLagged { .. }))
    ));
    drop(repeats);
    drop(first);
    Ok(())
}

#[test]
fn acknowledged_resume_preserves_runtime_statistics() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-ack-resume-runtime-stats")?;
    fixture.kernel.append_log("runtime-stats", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut first = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(first.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = first.poll() else {
        return Err("runtime-statistics batch missing".into());
    };
    first.acknowledge(batch.sequence(), batch.digest())?;
    let cursor = first.cursor().clone();
    first.disconnect();
    let Some(TailEvent::Terminal(TailTerminal::Disconnected { stats, .. })) = first.poll() else {
        return Err("initial runtime-statistics terminal missing".into());
    };
    let initial_peak = stats.memory_peak_bytes();
    assert!(initial_peak > 0);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    let mut resumed = service.resume_tail(query, &cursor)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    resumed.disconnect();
    let Some(TailEvent::Terminal(TailTerminal::Disconnected { stats, .. })) = resumed.poll() else {
        return Err("resumed runtime-statistics terminal missing".into());
    };
    assert!(stats.memory_peak_bytes() >= initial_peak);
    Ok(())
}

#[test]
fn tail_merge_cancellation_is_observed_before_candidate_mutation() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-merge-cancel")?;
    let meter = CancellingOperatorCallMeter::shared(1);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        meter.clone(),
    );
    let budget =
        QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1_024)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit all",
        budget,
    )?;
    meter.bind(query.cancellation())?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_log("first", 1, 1)?;
    fixture.kernel.append_log("second", 2, 2)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Cancelled { .. }))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}
