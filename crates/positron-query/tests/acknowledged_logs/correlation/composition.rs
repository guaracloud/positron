use std::error::Error;

use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_kernel::{LedgerFailureCode, SnapshotLeaseId};
use positron_policy::NativeLogAttribute;
use positron_query::{
    CorrelationOutcome, QueryBudget, QueryBudgetDimension, QueryEvent, QueryTerminal,
};
use positron_signals::SchemaPath;

use super::super::support::{TestClock, zero_work_clock_service};
use super::super::terminal_and_bounds::QueryFixture;

#[test]
fn sql_correlation_page_resume_binds_sidecar_to_projected_time_values() -> Result<(), Box<dyn Error>>
{
    use positron_query::ResultValueType;

    let fixture = QueryFixture::new("correlation-sql-projected-page-resume")?;
    let first_trace = [0xa1; 16];
    let first_span = [0xa2; 8];
    let second_trace = [0xa3; 16];
    let second_span = [0xa4; 8];
    let third_trace = [0xa5; 16];
    let third_span = [0xa6; 8];
    for (trace, span, time, identity, body) in [
        (first_trace, first_span, 20, 1, "first"),
        (second_trace, second_span, 21, 3, "second"),
        (third_trace, third_span, 22, 5, "third"),
    ] {
        fixture.kernel.append_trace(trace, span, time, identity)?;
        fixture
            .kernel
            .append_log_with_trace(body, time, trace, span, identity + 1)?;
    }
    let service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
    )
    .with_trace_ledger(fixture.kernel.trace_ledger()?);
    let source = "SELECT body, query_time, event_time, ingest_time, commit_position FROM logs CORRELATE TRACE WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time DESC, commit_position DESC LIMIT 3";

    let query = service
        .plan_sql(fixture.context, source, super::budget())
        .map_err(|failure| format!("projected correlation plan failed: {failure:?}"))?;
    let first = service
        .execute_page(query)
        .map_err(|failure| format!("projected correlation initial page failed: {failure:?}"))?
        .collect::<Vec<_>>();
    let header = first
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("projected correlation header missing")?;
    assert_eq!(
        header.schema().types(),
        [
            ResultValueType::NativeValue,
            ResultValueType::QueryTime,
            ResultValueType::EventTime,
            ResultValueType::IngestTime,
            ResultValueType::CommitPosition,
        ]
    );
    assert!(header.correlation_snapshot().is_some());
    let initial_batch = first
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.clone()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("projected initial correlation batch missing")?;
    let initial_record = initial_batch
        .records()
        .first()
        .ok_or("projected initial correlation record missing")?;
    assert_eq!(initial_record.body_text(), Some("third"));
    assert_eq!(initial_record.query_time().value(), 22);
    assert_eq!(
        initial_record.event_time().map(|time| time.value()),
        Some(22)
    );
    assert!(initial_record.ingest_time_value().is_some());
    assert_eq!(
        initial_batch.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id: third_trace,
            span_id: Some(third_span),
        })
    );
    let cursor = first
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor.clone()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("projected correlation cursor missing")?;

    let resumed = service
        .resume(fixture.context, &cursor)
        .map_err(|failure| format!("projected correlation resume failed: {failure:?}"))?
        .collect::<Vec<_>>();
    let resumed_batch = resumed
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.clone()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("projected resumed correlation batch missing")?;
    let resumed_record = resumed_batch
        .records()
        .first()
        .ok_or("projected resumed correlation record missing")?;
    assert_eq!(resumed_record.body_text(), Some("second"));
    assert_eq!(resumed_record.query_time().value(), 21);
    assert_eq!(
        resumed_record.event_time().map(|time| time.value()),
        Some(21)
    );
    assert!(resumed_record.ingest_time_value().is_some());
    assert_eq!(
        resumed_batch.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id: second_trace,
            span_id: Some(second_span),
        })
    );
    assert!(matches!(
        resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Continued(_)))
    ));
    let next_cursor = resumed
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor.clone()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("projected resumed correlation cursor missing")?;

    let replay = service
        .resume(fixture.context, &cursor)
        .map_err(|failure| format!("projected correlation replay failed: {failure:?}"))?
        .collect::<Vec<_>>();
    let replayed_batch = replay
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("projected replayed correlation batch missing")?;
    assert_eq!(replayed_batch, &resumed_batch);
    assert_eq!(replayed_batch.digest(), resumed_batch.digest());
    let final_page = service
        .resume(fixture.context, &next_cursor)?
        .collect::<Vec<_>>();
    let final_batch = final_page
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("projected final correlation batch missing")?;
    assert_eq!(final_batch.records()[0].body_text(), Some("first"));
    assert_eq!(
        final_batch.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id: first_trace,
            span_id: Some(first_span),
        })
    );
    assert!(matches!(
        final_page.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn filtered_pipeline_and_sql_correlation_page_resumes_preserve_selected_outcomes()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-filtered-page-resume")?;
    let early_trace = [0xb1; 16];
    let early_span = [0xb2; 8];
    let excluded_trace = [0xb3; 16];
    let excluded_span = [0xb4; 8];
    let late_trace = [0xb5; 16];
    let late_span = [0xb6; 8];
    for (trace, span, time, identity, body) in [
        (early_trace, early_span, 20, 1, "keep-early"),
        (excluded_trace, excluded_span, 21, 3, "drop"),
        (late_trace, late_span, 22, 5, "keep-late"),
    ] {
        fixture.kernel.append_trace(trace, span, time, identity)?;
        fixture
            .kernel
            .append_log_with_trace(body, time, trace, span, identity + 1)?;
    }
    let service = fixture.correlation_service(1)?;
    let pipeline = "pipeline:v1 logs | range query_time -100 100 | search body contains \"keep\" | correlate trace | limit 2";
    let sql = "SELECT body FROM logs CORRELATE TRACE WHERE query_time >= -100 AND query_time < 100 AND body CONTAINS \"keep\" ORDER BY query_time, commit_position LIMIT 2";

    let pipeline_events = service
        .execute_page(service.plan_pipeline(fixture.context, pipeline, super::budget())?)?
        .collect::<Vec<_>>();
    let sql_events = service
        .execute_page(service.plan_sql(fixture.context, sql, super::budget())?)?
        .collect::<Vec<_>>();
    let batch = |events: &[QueryEvent]| -> Result<positron_query::QueryBatch, Box<dyn Error>> {
        events
            .iter()
            .find_map(|event| match event {
                QueryEvent::Batch(batch) => Some(batch.clone()),
                QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
            })
            .ok_or_else(|| "filtered correlation batch missing".into())
    };
    let cursor = |events: &[QueryEvent]| -> Result<positron_query::QueryCursor, Box<dyn Error>> {
        events
            .iter()
            .find_map(|event| match event {
                QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor.clone()),
                QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
            })
            .ok_or_else(|| "filtered correlation cursor missing".into())
    };
    let pipeline_batch = batch(&pipeline_events)?;
    let sql_batch = batch(&sql_events)?;
    assert_eq!(pipeline_batch, sql_batch);
    assert_eq!(pipeline_batch.records()[0].body_text(), Some("keep-early"));
    assert_eq!(
        pipeline_batch.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id: early_trace,
            span_id: Some(early_span),
        })
    );
    assert!(matches!(
        pipeline_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Continued(_)))
    ));
    assert!(matches!(
        sql_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Continued(_)))
    ));
    let pipeline_resume = service
        .resume(fixture.context, &cursor(&pipeline_events)?)?
        .collect::<Vec<_>>();
    let sql_resume = service
        .resume(fixture.context, &cursor(&sql_events)?)?
        .collect::<Vec<_>>();
    let pipeline_resumed_batch = batch(&pipeline_resume)?;
    let sql_resumed_batch = batch(&sql_resume)?;
    assert_eq!(pipeline_resumed_batch, sql_resumed_batch);
    assert_eq!(
        pipeline_resumed_batch.records()[0].body_text(),
        Some("keep-late")
    );
    assert_eq!(
        pipeline_resumed_batch.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id: late_trace,
            span_id: Some(late_span),
        })
    );
    assert!(matches!(
        pipeline_resume.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    assert!(matches!(
        sql_resume.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn transformed_pipeline_and_sql_correlation_page_resumes_keep_log_trace_identity()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-transformed-page-resume")?;
    let first_trace = [0xc1; 16];
    let first_span = [0xc2; 8];
    let second_trace = [0xc3; 16];
    let second_span = [0xc4; 8];
    for (trace, span, time, identity, body) in [
        (first_trace, first_span, 20, 1, "41"),
        (second_trace, second_span, 21, 3, "42"),
    ] {
        fixture.kernel.append_trace(trace, span, time, identity)?;
        fixture
            .kernel
            .append_log_with_trace(body, time, trace, span, identity + 1)?;
    }
    let service = fixture.correlation_service(1)?;
    let pipeline = "pipeline:v1 logs | range query_time -100 100 | cast body as int | correlate trace | limit 2";
    let sql = "SELECT CAST(body AS int) FROM logs CORRELATE TRACE WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 2";
    let batch = |events: &[QueryEvent]| -> Result<positron_query::QueryBatch, Box<dyn Error>> {
        events
            .iter()
            .find_map(|event| match event {
                QueryEvent::Batch(batch) => Some(batch.clone()),
                QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
            })
            .ok_or_else(|| "transformed correlation batch missing".into())
    };
    let cursor = |events: &[QueryEvent]| -> Result<positron_query::QueryCursor, Box<dyn Error>> {
        events
            .iter()
            .find_map(|event| match event {
                QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor.clone()),
                QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
            })
            .ok_or_else(|| "transformed correlation cursor missing".into())
    };

    let pipeline_events = service
        .execute_page(service.plan_pipeline(fixture.context, pipeline, super::budget())?)?
        .collect::<Vec<_>>();
    let sql_events = service
        .execute_page(service.plan_sql(fixture.context, sql, super::budget())?)?
        .collect::<Vec<_>>();
    let pipeline_batch = batch(&pipeline_events)?;
    let sql_batch = batch(&sql_events)?;
    assert_eq!(pipeline_batch, sql_batch);
    assert_eq!(
        pipeline_batch.records()[0]
            .body_value()
            .and_then(positron_domain::value::ValidatedAttributeValue::as_signed_integer),
        Some(41)
    );
    assert_eq!(
        pipeline_batch.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id: first_trace,
            span_id: Some(first_span),
        })
    );

    let pipeline_resumed = service
        .resume(fixture.context, &cursor(&pipeline_events)?)?
        .collect::<Vec<_>>();
    let sql_resumed = service
        .resume(fixture.context, &cursor(&sql_events)?)?
        .collect::<Vec<_>>();
    let pipeline_resumed_batch = batch(&pipeline_resumed)?;
    let sql_resumed_batch = batch(&sql_resumed)?;
    assert_eq!(pipeline_resumed_batch, sql_resumed_batch);
    assert_eq!(
        pipeline_resumed_batch.records()[0]
            .body_value()
            .and_then(positron_domain::value::ValidatedAttributeValue::as_signed_integer),
        Some(42)
    );
    assert_eq!(
        pipeline_resumed_batch.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id: second_trace,
            span_id: Some(second_span),
        })
    );
    assert!(matches!(
        pipeline_resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    assert!(matches!(
        sql_resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn correlation_cursor_charges_sidecar_output_bytes_across_pages_and_releases_both_leases()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-cursor-output-bytes")?;
    let first_trace = [0xd1; 16];
    let first_span = [0xd2; 8];
    let second_trace = [0xd3; 16];
    let second_span = [0xd4; 8];
    for (trace, span, time, identity) in [
        (first_trace, first_span, 20, 1),
        (second_trace, second_span, 21, 3),
    ] {
        fixture.kernel.append_trace(trace, span, time, identity)?;
        fixture
            .kernel
            .append_log_with_trace("same", time, trace, span, identity + 1)?;
    }
    let service = fixture.correlation_service(1)?;
    let source = "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 2";

    let measured = service
        .execute(service.plan_pipeline(fixture.context, source, super::budget())?)?
        .collect::<Vec<_>>();
    let total_output_bytes = match measured.last() {
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats))) => stats.output_bytes(),
        _ => return Err("correlation output measurement did not complete".into()),
    };
    let per_row_output_bytes = total_output_bytes
        .checked_div(2)
        .filter(|bytes| *bytes > 0 && total_output_bytes == *bytes * 2)
        .ok_or("identical correlation rows did not produce equal output sizes")?;
    let budget = QueryBudget::new(1_048_576, 1_024, 1_024, per_row_output_bytes, 1_048_576, 60)?;
    let first = service
        .execute_page(service.plan_pipeline(fixture.context, source, budget)?)?
        .collect::<Vec<_>>();
    let first_header = first
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("output-limited correlation header missing")?;
    let source_lease = SnapshotLeaseId::new(first_header.lease().identity())?;
    let trace_lease = SnapshotLeaseId::new(
        first_header
            .correlation_snapshot()
            .ok_or("output-limited correlation trace provenance missing")?
            .trace_lease()
            .identity(),
    )?;
    assert!(matches!(
        first.iter().find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        }),
        Some(batch) if batch.correlation_outcome(0)
            == Some(CorrelationOutcome::Matched {
                trace_id: first_trace,
                span_id: Some(first_span),
            })
    ));
    let cursor = first
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor.clone()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("first output-limited correlation cursor missing")?;

    let resumed = service
        .resume(fixture.context, &cursor)?
        .collect::<Vec<_>>();
    assert!(
        matches!(resumed.first(), Some(QueryEvent::Header(header)) if header
        .correlation_snapshot()
        .is_some())
    );
    assert!(
        !resumed
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    let incomplete = match resumed.last() {
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete))) => incomplete,
        _ => return Err("second correlation page did not frame an incomplete terminal".into()),
    };
    assert_eq!(
        incomplete.stats().limiting_budget(),
        Some(QueryBudgetDimension::OutputBytes)
    );
    assert_eq!(incomplete.stats().records(), 1);
    assert_eq!(incomplete.stats().output_bytes(), per_row_output_bytes);
    for (ledger, lease) in [
        (fixture.kernel.ledger()?, source_lease),
        (fixture.kernel.trace_ledger()?, trace_lease),
    ] {
        assert_eq!(
            ledger
                .snapshot_lease_usage(lease, 100)
                .expect_err("output failure must release the paired snapshot lease")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
    }
    Ok(())
}

#[test]
fn schema_backed_attribute_correlation_preserves_selected_trace_outcome()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("schema-backed-correlation")?;
    let selected_trace = [0xe1; 16];
    let selected_span = [0xe2; 8];
    let excluded_trace = [0xe3; 16];
    let excluded_span = [0xe4; 8];
    fixture
        .kernel
        .append_trace(selected_trace, selected_span, 20, 1)?;
    fixture
        .kernel
        .append_trace(excluded_trace, excluded_span, 21, 2)?;
    let path = SchemaPath::root(AttributeNamespace::Record, "service".to_owned())?;
    let schema = fixture.kernel.append_indexed_attribute_logs_with_trace(
        vec![
            (
                Some(20),
                vec![NativeLogAttribute::new(
                    AttributeNamespace::Record,
                    "service".to_owned(),
                    vec![CandidateAttributeValue::string("api".to_owned())],
                )],
                selected_trace,
                selected_span,
            ),
            (
                Some(21),
                vec![NativeLogAttribute::new(
                    AttributeNamespace::Record,
                    "service".to_owned(),
                    vec![CandidateAttributeValue::string("worker".to_owned())],
                )],
                excluded_trace,
                excluded_span,
            ),
        ],
        3,
        &path,
    )?;
    let service = fixture.correlation_service(16)?;
    let source = r#"pipeline:v1 logs | range query_time -100 100 | filter record["service"] any == string("api") | correlate trace | limit 2"#;
    let events = service
        .execute_with_schema(
            service.plan_pipeline(fixture.context, source, super::budget())?,
            schema.catalog(),
        )?
        .collect::<Vec<_>>();
    let batch = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("schema-backed correlation batch missing")?;
    assert_eq!(batch.records().len(), 1);
    assert_eq!(
        batch.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id: selected_trace,
            span_id: Some(selected_span),
        })
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}
