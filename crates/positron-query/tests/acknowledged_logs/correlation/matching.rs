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
