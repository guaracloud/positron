use std::error::Error;

use positron_query::{QueryEvent, QueryFailureCode, QueryTerminal};

use super::super::terminal_and_bounds::QueryFixture;

use std::sync::Arc;

use super::super::support::{CancellingOperatorCallMeter, MergeWorkMeter, TestClock};
use positron_kernel::WorkClass;
use positron_query::{QueryBudget, QueryBudgetDimension, QueryService};

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
fn correlation_target_scan_bytes_exhaustion_frames_one_incomplete_terminal()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-target-scan-bytes-exhaustion")?;
    let trace_id = [0x9d; 16];
    let span_id = [0x9e; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, span_id, 2)?;
    let service = fixture.correlation_service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
        QueryBudget::new(1, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_))),
        "target scan byte exhaustion must not expose a log-only prefix: {events:?}"
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget() == Some(QueryBudgetDimension::ScannedBytes)
    ));
    Ok(())
}

#[test]
fn correlation_target_scan_cancellation_frames_one_terminal_and_releases_both_leases()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("correlation-target-scan-cancellation")?;
    let trace_id = [0x9f; 16];
    let span_id = [0xa0; 8];
    fixture.kernel.append_trace(trace_id, span_id, 20, 1)?;
    fixture
        .kernel
        .append_log_with_trace("accepted", 20, trace_id, span_id, 2)?;
    let meter = CancellingOperatorCallMeter::shared_for_stage(
        positron_query::QueryWorkStage::ScanDecode,
        1,
    );
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    )
    .with_trace_ledger(fixture.kernel.trace_ledger()?);
    let baseline = fixture.kernel.authority.governor().inspect()?;
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
            .any(|event| matches!(event, QueryEvent::Batch(_))),
        "target scan cancellation must not expose a log-only prefix: {events:?}"
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
    ));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, QueryEvent::Terminal(_)))
            .count(),
        1
    );
    assert_eq!(fixture.kernel.authority.governor().inspect()?, baseline);
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
