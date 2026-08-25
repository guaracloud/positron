use std::error::Error;

use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::value::AttributeValueKind;
use positron_kernel::{ActiveSegmentLedger, SegmentProtectionKey};
use positron_query::{
    QueryBudget, QueryEvent, QueryFailureCode, TailCursor, TailCursorState, TailEvent,
    TailPosition, TailSourceSet, TailStart, TailTerminal,
};

use super::support::{
    CancellingStageWorkMeter, TestClock, stage_work_service, zero_work_clock_service,
};
use super::terminal_and_bounds::QueryFixture;

#[test]
fn tail_reads_acknowledged_history_then_stays_idle_until_disconnect() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-history")?;
    fixture.kernel.append_log("one", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("tail batch missing".into());
    };
    assert_eq!(batch.records().len(), 1);
    assert_eq!(batch.records()[0].body_text(), Some("one"));
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    fixture.kernel.append_log("live", 2, 2)?;
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("live tail batch missing after ingest append".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("live"));
    tail.disconnect();
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Disconnected(_)))
    ));
    assert!(tail.poll().is_none());
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
            "pipeline:v1 logs | range query_time -100 100 | limit 2",
            budget,
        )?;
        let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
        assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
        assert!(matches!(tail.poll(), Some(TailEvent::Batch(_))));
        tail.cursor().clone()
    };

    fixture.kernel.reopen_ledger()?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 2",
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
        Some(TailEvent::Terminal(TailTerminal::Disconnected(_)))
    ));
    Ok(())
}

#[test]
fn tail_cursor_tamper_fails_closed_on_resume() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let mut bytes = tail.cursor().as_bytes().to_vec();
    let slot = bytes.get_mut(24).ok_or("tail cursor body is bounded")?;
    *slot ^= 1;
    let tampered = positron_query::TailCursor::from_bytes(&bytes)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
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
    bad_count[242] = 0;
    bad_count[243] = 0;
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
    zero_count[242] = 0;
    zero_count[243] = 0;
    authenticate(&mut zero_count)?;
    assert!(TailCursor::decode(&protector, &TailCursor::from_bytes(&zero_count)?).is_err());

    let mut mismatched_length = cursor.as_bytes().to_vec();
    mismatched_length[242] = 0;
    mismatched_length[243] = 2;
    authenticate(&mut mismatched_length)?;
    assert!(TailCursor::decode(&protector, &TailCursor::from_bytes(&mismatched_length)?,).is_err());

    let mut invalid_marker = cursor.as_bytes().to_vec();
    invalid_marker[244 + 14] = 2;
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
    let trace_sources = TailSourceSet::new(vec![traces.reader()?])?;
    let trace_query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        budget,
    )?;
    let _trace_tail = service.tail_with_sources(trace_query, TailStart::Now, trace_sources)?;
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
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
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
        Some(TailEvent::Terminal(TailTerminal::Cancelled(Some(_))))
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
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        budget,
    )?;
    let failure = match service.tail(query, TailStart::Historical { max_rows: 0 }) {
        Ok(_) => return Err("zero historical rows unexpectedly admitted".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::InvalidBudget);
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    clock.set(160);
    let event = tail.poll();
    assert!(matches!(
        event,
        Some(TailEvent::Terminal(TailTerminal::Expired(Some(_))))
    ));
    assert!(tail.poll().is_none());

    let fixture = QueryFixture::new("tail-revalidate-lifecycle")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.publish_lifecycle_for_test(3, 0xd4)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::AuthorizationChanged(
            Some(_)
        )))
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
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    fixture.kernel.append_malformed_log_block(1)?;
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::StoreUnavailable(Some(_))))
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
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"budget\" | limit 16",
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
            Some(TailEvent::Terminal(TailTerminal::BudgetExhausted(Some(_)))) => {
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
fn tail_external_cancellation_is_revalidated_before_following() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-follow-cancellation")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        budget,
    )?;
    let cancellation = query.cancellation();
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    cancellation.cancel();
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Cancelled(Some(_))))
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
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
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
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("multi-shard live tail batch missing".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("live-one"));
    assert_eq!(batch.records()[1].body_text(), Some("live-two"));
    let cursor = tail.cursor().clone();
    let mismatch = TailSourceSet::new(vec![fixture.kernel.ledger()?.reader()?])?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 8",
        budget,
    )?;
    let mut tail =
        service.tail_with_sources(query, TailStart::Historical { max_rows: 2 }, sources)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("global shard-limited batch missing".into());
    };
    assert_eq!(batch.records().len(), 2);
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("remaining bounded historical batch missing".into());
    };
    assert_eq!(batch.records().len(), 2);
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    Ok(())
}

#[test]
fn tail_resume_exposes_replayed_rows_after_an_undelivered_cursor() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-replay")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let cursor = tail.cursor().clone();
    drop(tail);
    fixture.kernel.append_log("replayed", 1, 1)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
        budget,
    )?;
    let mut resumed = service.resume_tail(query, &cursor)?;
    assert!(matches!(resumed.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = resumed.poll() else {
        return Err("replayed tail batch missing".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("replayed"));
    assert!(batch.records()[0].replayed());
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
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
        budget,
    )?;
    let mut first = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(first.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = first.poll() else {
        return Err("first partial tail batch missing".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some("row-1"));
    let cursor = first.cursor().clone();
    drop(first);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 2",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 1 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(first)) = tail.poll() else {
        return Err("first tail batch missing".into());
    };
    let cursor = tail.cursor().clone();
    assert_eq!(first.sequence(), 0);
    assert_eq!(first.prior_digest(), [0; 32]);

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 2",
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
    assert!(matches!(
        resumed.poll(),
        Some(TailEvent::Terminal(TailTerminal::BudgetExhausted(Some(_))))
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
        "pipeline:v1 logs | range query_time -100 100 | limit 2",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let cursor = tail.cursor().clone();
    clock.set(160);
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 2",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        original_budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let cursor = tail.cursor().clone();

    let changed_budget = QueryBudget::new(1_048_576, 16, 2, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 2",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 2",
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
fn tail_sql_materialization_matches_the_ordinary_query_record() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-sql-parity")?;
    fixture.kernel.append_log("sql-value", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let source = "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 4";
    let ordinary = service
        .execute(service.plan_sql(fixture.context, source, budget)?)?
        .collect::<Vec<_>>();
    let expected = ordinary
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch
                .records()
                .first()
                .and_then(|record| record.body_text()),
            _ => None,
        })
        .ok_or("ordinary SQL record missing")?;
    let query = service.plan_sql(fixture.context, source, budget)?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    let Some(TailEvent::Batch(batch)) = tail.poll() else {
        return Err("tail SQL batch missing".into());
    };
    assert_eq!(batch.records()[0].body_text(), Some(expected));
    Ok(())
}

#[test]
fn tail_rejects_future_knowledge_operators_with_a_typed_failure() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-unsupported")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count | limit 1",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
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
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::ConsumerLagged(_)))
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
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Now)?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    tail.cancel();
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Cancelled(_)))
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
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
        budget,
    )?;
    let mut cancelled = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(cancelled.poll(), Some(TailEvent::Header(_))));
    cancelled.cancel();
    assert!(matches!(
        cancelled.poll(),
        Some(TailEvent::Terminal(TailTerminal::Cancelled(_)))
    ));
    assert!(cancelled.poll().is_none());

    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
        budget,
    )?;
    let mut disconnected = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(disconnected.poll(), Some(TailEvent::Header(_))));
    disconnected.disconnect();
    assert!(matches!(
        disconnected.poll(),
        Some(TailEvent::Terminal(TailTerminal::Disconnected(_)))
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
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
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
        "pipeline:v1 logs | range query_time -100 100 | json | limit 4",
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
        r#"pipeline:v1 logs | range query_time -100 100 | search body contains "api" | limit 4"#,
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
        r#"pipeline:v1 logs | range query_time -100 100 | logfmt | project body, query_time, ingest_time | limit 4"#,
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
        r#"pipeline:v1 logs | range query_time -100 100 | search body contains "missing" | limit 4"#,
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
