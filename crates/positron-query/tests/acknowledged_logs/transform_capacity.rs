use std::error::Error;

use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryTerminal};

use super::support::zero_work_service;
use super::terminal_and_bounds::QueryFixture;

#[test]
fn parser_scratch_and_retained_output_have_exact_memory_boundaries() -> Result<(), Box<dyn Error>> {
    let json_fixture = QueryFixture::new("query-json-transform-memory-boundary")?;
    let json_source = format!(
        "{{{}}}",
        (0..1_024)
            .map(|index| format!(r#""k{index}":"{}""#, "value".repeat(8)))
            .collect::<Vec<_>>()
            .join(",")
    );
    json_fixture.kernel.append_log(&json_source, 20, 1)?;
    let json_service = zero_work_service(
        json_fixture.kernel.authority.governor(),
        json_fixture.kernel.ledger()?,
        16,
    );
    let json_query = |memory| {
        let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, memory, 60)
            .and_then(|budget| budget.with_cpu_work_units(1_024))?;
        json_service.plan_pipeline(
            json_fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
            budget,
        )
    };
    let json_events = json_service
        .execute(json_query(1_048_576)?)?
        .collect::<Vec<_>>();
    let json_peak = json_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Complete(stats)) => Some(stats.memory_peak_bytes()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("JSON boundary query did not complete")?;
    let json_under = json_service
        .execute(json_query(
            json_peak.checked_sub(1).ok_or("JSON peak was zero")?,
        )?)?
        .collect::<Vec<_>>();
    assert!(matches!(
        json_under.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::MemoryBytes)
    ));

    let logfmt_fixture = QueryFixture::new("query-logfmt-transform-memory-boundary")?;
    let logfmt_source = (0..1_024)
        .map(|index| format!("k{index}=\"{}\"", "value".repeat(8)))
        .collect::<Vec<_>>()
        .join(" ");
    logfmt_fixture.kernel.append_log(&logfmt_source, 20, 1)?;
    let logfmt_service = zero_work_service(
        logfmt_fixture.kernel.authority.governor(),
        logfmt_fixture.kernel.ledger()?,
        16,
    );
    let logfmt_query = |memory| {
        let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, memory, 60)
            .and_then(|budget| budget.with_cpu_work_units(1_024))?;
        logfmt_service.plan_pipeline(
            logfmt_fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | logfmt | limit 1",
            budget,
        )
    };
    let logfmt_events = logfmt_service
        .execute(logfmt_query(1_048_576)?)?
        .collect::<Vec<_>>();
    let logfmt_peak = logfmt_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Complete(stats)) => Some(stats.memory_peak_bytes()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("logfmt boundary query did not complete")?;
    let logfmt_under = logfmt_service
        .execute(logfmt_query(
            logfmt_peak.checked_sub(1).ok_or("logfmt peak was zero")?,
        )?)?
        .collect::<Vec<_>>();
    assert!(matches!(
        logfmt_under.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::MemoryBytes)
    ));
    Ok(())
}

#[test]
fn json_validation_charges_candidate_and_canonical_capacity_at_exact_boundary()
-> Result<(), Box<dyn Error>> {
    const ENTRIES: u64 = 1_024;
    const PARSER_ENTRY_BYTES: u64 = 96;
    const ARRAY_VALUE_SLOT_BYTES: u64 = 64;
    // The query's fixed page/digest working set is retained by both runs; the
    // transform adds the source scratch and its transfer bookkeeping.
    const TRANSFORM_WORKING_BYTES: u64 = 320;

    let fixture = QueryFixture::new("query-json-array-simultaneous-capacity")?;
    let source = format!("[{}]", vec!["0"; usize::try_from(ENTRIES)?].join(","));
    fixture.kernel.append_log(&source, 20, 1)?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let budget = |memory| {
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, memory, 60)
            .and_then(|budget| budget.with_cpu_work_units(1_024))
    };
    let baseline = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        budget(4_194_304)?,
    )?;
    let baseline_peak = service
        .execute(baseline)?
        .collect::<Vec<_>>()
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Complete(stats)) => Some(stats.memory_peak_bytes()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("JSON array baseline did not complete")?;
    let parser_bytes = ENTRIES
        .checked_mul(PARSER_ENTRY_BYTES)
        .ok_or("parser capacity overflowed")?;
    let output_bytes = ENTRIES
        .checked_mul(ARRAY_VALUE_SLOT_BYTES)
        .ok_or("validated capacity overflowed")?;
    let expected_peak = baseline_peak
        .checked_add(parser_bytes)
        .and_then(|bytes| bytes.checked_add(output_bytes))
        .and_then(|bytes| bytes.checked_add(u64::try_from(source.len()).ok()?))
        .and_then(|bytes| bytes.checked_add(TRANSFORM_WORKING_BYTES))
        .ok_or("transform capacity floor overflowed")?;

    let under = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        budget(expected_peak.checked_sub(1).ok_or("boundary underflowed")?)?,
    )?;
    let under_events = service.execute(under)?.collect::<Vec<_>>();
    assert!(matches!(
        under_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::MemoryBytes)
    ));

    let exact = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        budget(expected_peak)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    let exact_stats = exact_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Complete(stats)) => Some(stats),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("JSON array exact query did not complete")?;
    assert!(exact_stats.memory_peak_bytes() <= expected_peak);
    assert_eq!(exact_stats.records(), 1);
    Ok(())
}

#[test]
fn nested_json_parser_allocations_are_admitted_before_the_final_value() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("query-json-nested-parser-memory-boundary")?;
    let leaf = format!("[{}]", vec!["0"; 256].join(","));
    let source = format!("[{}]", vec![leaf; 32].join(","));
    let parser_entries = 32_usize
        .checked_mul(256)
        .and_then(|entries| entries.checked_add(32))
        .ok_or("parser entry fixture overflowed")?;
    let parser_memory = u64::try_from(parser_entries)
        .ok()
        .and_then(|entries| entries.checked_mul(96))
        .ok_or("parser memory fixture overflowed")?;
    fixture.kernel.append_log(&source, 20, 1)?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, parser_memory, 60)?
        .with_cpu_work_units(1_024)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        budget,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::MemoryBytes)
    ));

    let permissive = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4_194_304, 60)?
            .with_cpu_work_units(1_024)?,
    )?;
    let permissive_events = service.execute(permissive)?.collect::<Vec<_>>();
    let peak = permissive_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Complete(stats)) => Some(stats.memory_peak_bytes()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("nested JSON peak query did not complete")?;
    let exact_boundary = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        QueryBudget::new(
            1_048_576,
            16,
            16,
            1_048_576,
            peak.checked_sub(1).ok_or("nested JSON peak was zero")?,
            60,
        )?
        .with_cpu_work_units(1_024)?,
    )?;
    let exact_events = service.execute(exact_boundary)?.collect::<Vec<_>>();
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::MemoryBytes)
    ));
    Ok(())
}

#[test]
fn cast_string_peak_uses_retained_capacity_for_1024_records() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-cast-string-capacity-boundary")?;
    fixture.kernel.append_log_bodies(
        (0..1_024)
            .map(|_| Some(positron_domain::value::CandidateAttributeValue::signed_integer(7)))
            .collect(),
        20,
        1,
    )?;
    let service = zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1_024,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | cast body as string | limit 1024",
        QueryBudget::new(1_048_576, 1_024, 1_024, 1_048_576, 4_194_304, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let peak = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Complete(stats)) => Some(stats.memory_peak_bytes()),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("cast capacity query did not complete")?;
    let expected_capacity_floor = 1_024_u64
        .checked_mul(192)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or("capacity floor overflowed")?;
    assert!(peak >= expected_capacity_floor);

    let under = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | cast body as string | limit 1024",
        QueryBudget::new(
            1_048_576,
            1_024,
            1_024,
            1_048_576,
            peak.checked_sub(1).ok_or("cast peak was zero")?,
            60,
        )?,
    )?;
    let under_events = service.execute(under)?.collect::<Vec<_>>();
    assert!(matches!(
        under_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::MemoryBytes)
    ));
    Ok(())
}
