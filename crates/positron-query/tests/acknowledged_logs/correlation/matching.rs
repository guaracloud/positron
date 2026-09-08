use std::error::Error;

use positron_query::{CorrelationOutcome, QueryEvent, QueryTerminal};

use super::super::terminal_and_bounds::QueryFixture;

#[test]
fn correlation_matches_a_log_trace_identifier_against_the_tenant_trace_store()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-matched")?;
    let trace_id = [0x71; 16];
    fixture.kernel.append_trace(trace_id, [0x72; 8], 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, [0x72; 8], 2)?;
    let service = fixture.correlation_service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        super::budget(),
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("correlation header missing")?;
    let provenance = header
        .correlation_snapshot()
        .ok_or("paired correlation provenance missing")?;
    assert_eq!(provenance.logs(), header.snapshot());
    assert!(provenance.traces().frontier() >= 1);
    assert_ne!(
        provenance.trace_lease().identity(),
        header.lease().identity()
    );
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
        Some(CorrelationOutcome::Matched {
            trace_id,
            span_id: Some([0x72; 8]),
        })
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn correlation_matches_a_trace_identifier_without_constraining_the_span()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-trace-id-only")?;
    let trace_id = [0x70; 16];
    fixture.kernel.append_trace(trace_id, [0x71; 8], 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace_id("accepted", 20, trace_id, 2)?;
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
        .ok_or("trace-id-only correlation batch missing")?;
    assert_eq!(batch.records()[0].body_text(), Some("accepted"));
    assert_eq!(
        batch.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id,
            span_id: None,
        })
    );
    Ok(())
}

#[test]
fn correlation_does_not_match_a_different_span_in_the_same_trace() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-wrong-span")?;
    let trace_id = [0x73; 16];
    fixture.kernel.append_trace(trace_id, [0x74; 8], 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, [0x75; 8], 2)?;
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
    assert_eq!(
        batch.correlation_outcome(0),
        Some(CorrelationOutcome::MissingTraceTarget {
            trace_id,
            span_id: Some([0x75; 8]),
        })
    );
    Ok(())
}

#[test]
fn correlation_preserves_trace_matches_across_sealed_and_active_native_segments()
-> Result<(), Box<dyn Error>> {
    let mut fixture = QueryFixture::new("correlation-sealed-active")?;
    let sealed_trace = [0x7a; 16];
    let sealed_span = [0x7b; 8];
    let active_trace = [0x7c; 16];
    let active_span = [0x7d; 8];
    fixture
        .kernel
        .append_trace(sealed_trace, sealed_span, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("sealed", 20, sealed_trace, sealed_span, 2)?;
    fixture.kernel.seal_and_reopen()?;
    fixture.kernel.seal_and_reopen_trace()?;
    fixture
        .kernel
        .append_trace(active_trace, active_span, 21, 3)?;
    fixture
        .kernel
        .append_log_with_trace("active", 21, active_trace, active_span, 4)?;
    let service = fixture.correlation_service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 2",
        super::budget(),
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    let batch = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("sealed-and-active correlation batch missing")?;
    assert_eq!(
        batch
            .records()
            .iter()
            .filter_map(|record| record.body_text())
            .collect::<Vec<_>>(),
        ["sealed", "active"]
    );
    assert_eq!(
        batch.correlation_outcome(0),
        Some(CorrelationOutcome::Matched {
            trace_id: sealed_trace,
            span_id: Some(sealed_span),
        })
    );
    assert_eq!(
        batch.correlation_outcome(1),
        Some(CorrelationOutcome::Matched {
            trace_id: active_trace,
            span_id: Some(active_span),
        })
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn correlation_reports_conflicting_selected_trace_evidence_as_ambiguous()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-ambiguous")?;
    let trace_id = [0x76; 16];
    let span_id = [0x77; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture.kernel.append_trace(trace_id, span_id, 21, 2)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, span_id, 3)?;
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
    assert_eq!(
        batch.correlation_outcome(0),
        Some(CorrelationOutcome::Ambiguous {
            trace_id,
            span_id: Some(span_id),
        })
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn correlation_keeps_sorted_rows_outcomes_and_batch_digest_bound_together()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-sorted-outcomes")?;
    let missing_target_trace = [0x81; 16];
    let missing_target_span = [0x82; 8];
    let matched_trace = [0x83; 16];
    let matched_span = [0x84; 8];
    let ambiguous_trace = [0x85; 16];
    let ambiguous_span = [0x86; 8];
    fixture.kernel.append_log("missing-log-id", 20, 1)?;
    fixture.kernel.append_log_with_trace(
        "missing-target",
        21,
        missing_target_trace,
        missing_target_span,
        2,
    )?;
    fixture
        .kernel
        .append_trace(matched_trace, matched_span, 22, 3)?;
    fixture
        .kernel
        .append_log_with_trace("matched", 22, matched_trace, matched_span, 4)?;
    fixture
        .kernel
        .append_trace(ambiguous_trace, ambiguous_span, 23, 5)?;
    fixture
        .kernel
        .append_trace(ambiguous_trace, ambiguous_span, 24, 6)?;
    fixture
        .kernel
        .append_log_with_trace("ambiguous", 23, ambiguous_trace, ambiguous_span, 7)?;
    let service = fixture.correlation_service(16)?;
    let source = "SELECT body FROM logs CORRELATE TRACE WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time DESC, commit_position DESC LIMIT 4";
    let first = service
        .execute(service.plan_sql(fixture.context, source, super::budget())?)?
        .collect::<Vec<_>>();
    let batch = first
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.clone()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("sorted correlation batch missing")?;
    assert_eq!(
        batch
            .records()
            .iter()
            .map(|record| record.body_text())
            .collect::<Vec<_>>(),
        [
            Some("ambiguous"),
            Some("matched"),
            Some("missing-target"),
            Some("missing-log-id"),
        ]
    );
    assert_eq!(
        (0..batch.records().len())
            .map(|index| batch.correlation_outcome(index))
            .collect::<Vec<_>>(),
        vec![
            Some(CorrelationOutcome::Ambiguous {
                trace_id: ambiguous_trace,
                span_id: Some(ambiguous_span),
            }),
            Some(CorrelationOutcome::Matched {
                trace_id: matched_trace,
                span_id: Some(matched_span),
            }),
            Some(CorrelationOutcome::MissingTraceTarget {
                trace_id: missing_target_trace,
                span_id: Some(missing_target_span),
            }),
            Some(CorrelationOutcome::MissingLogTraceId),
        ]
    );

    fixture
        .kernel
        .append_trace(missing_target_trace, missing_target_span, 25, 8)?;
    let changed = service
        .execute(service.plan_sql(fixture.context, source, super::budget())?)?
        .collect::<Vec<_>>();
    let changed_batch = changed
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("changed correlation batch missing")?;
    assert_eq!(
        changed_batch.correlation_outcome(2),
        Some(CorrelationOutcome::Matched {
            trace_id: missing_target_trace,
            span_id: Some(missing_target_span),
        })
    );
    assert_ne!(changed_batch.digest(), batch.digest());
    Ok(())
}
