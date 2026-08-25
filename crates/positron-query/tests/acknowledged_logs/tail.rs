use std::error::Error;

use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::value::AttributeValueKind;
use positron_kernel::{ActiveSegmentLedger, SegmentProtectionKey};
use positron_query::{
    QueryBudget, QueryEvent, QueryFailureCode, TailCursor, TailEvent, TailSourceSet, TailStart,
    TailTerminal,
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
