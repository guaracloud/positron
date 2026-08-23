use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{ResourceAmounts, ResourceDimension, WorkClaim, WorkKind};
use positron_query::{
    QueryBudget, QueryBudgetDimension, QueryCursor, QueryEvent, QueryFailureCode, QueryService,
    QueryTerminal,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::support::{
    KernelFixture, SequenceClock, TemporaryRoots, TestClock, zero_work_clock_service,
};

#[test]
fn cancellation_replaces_unsent_events_with_one_non_complete_terminal() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("cancel")?;
    fixture.kernel.append_log("accepted", 20, 1)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    let mut stream = service.execute(query)?;
    assert!(matches!(stream.next(), Some(QueryEvent::Header(_))));

    stream.cancel()?;
    let remaining = stream.collect::<Vec<_>>();
    assert!(matches!(
        remaining.as_slice(),
        [QueryEvent::Terminal(QueryTerminal::Incomplete(failure))]
            if failure.code() == QueryFailureCode::Cancelled
    ));

    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    let mut disconnected = service.execute(query)?;
    assert!(matches!(disconnected.next(), Some(QueryEvent::Header(_))));
    drop(disconnected);
    Ok(())
}

#[test]
fn malformed_acknowledged_data_is_one_typed_terminal_not_a_partial_success()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("malformed")?;
    fixture.kernel.append_malformed_log_block(1)?;
    let service = fixture.service(16)?;
    let query = service.plan_sql(fixture.context, "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1", budget())?;
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
    assert_eq!(terminal_count(&events), 1);
    Ok(())
}

#[test]
fn empty_snapshot_completes_once_without_a_batch_and_terminal_cancel_is_idempotent()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("empty")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    let mut stream = service.execute(query)?;
    assert!(matches!(stream.next(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        stream.next(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    stream.cancel()?;
    assert!(stream.next().is_none());
    Ok(())
}

#[test]
fn response_header_exposes_every_effective_query_budget_limit() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("header-budget")?;
    let service = fixture.service(1)?;
    let expected = QueryBudget::new(101, 7, 5, 103, 512, 109)?
        .with_cpu_work_units(11)?
        .with_maximum_time_range_nanoseconds(113)?;
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time 0 100 | limit 1",
        expected,
    )?;
    let mut stream = service.execute(query)?;
    let actual = match stream.next() {
        Some(QueryEvent::Header(header)) => header.budget(),
        _ => return Err("query header missing".into()),
    };

    assert_eq!(actual.scanned_bytes(), 101);
    assert_eq!(actual.decoded_records(), 7);
    assert_eq!(actual.output_rows(), 5);
    assert_eq!(actual.output_bytes(), 103);
    assert_eq!(actual.memory_bytes(), 512);
    assert_eq!(actual.cpu_work_units(), 11);
    assert_eq!(actual.wall_seconds(), 109);
    assert_eq!(actual.maximum_time_range_nanoseconds(), 113);
    Ok(())
}

#[test]
fn paged_execution_rejects_zero_batch_and_expiry_overflow_before_work() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("page-bounds")?;
    let service = fixture.service(0)?;
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    assert_eq!(
        service
            .execute_page(query)
            .expect_err("zero batch limit")
            .code(),
        QueryFailureCode::InvalidBudget
    );

    let service = super::support::zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(u64::MAX),
        fixture.kernel.identity()?,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    assert_eq!(
        service
            .execute_page(query)
            .expect_err("lease expiry overflow")
            .code(),
        QueryFailureCode::InvalidBudget
    );
    Ok(())
}

#[test]
fn paged_execution_classifies_elapsed_deadlines_before_snapshot_mutation()
-> Result<(), Box<dyn Error>> {
    for (label, execute_at) in [("page-exact-deadline", 101), ("page-past-deadline", 102)] {
        let fixture = QueryFixture::new(label)?;
        let service = zero_work_clock_service(
            fixture.kernel.authority.governor(),
            fixture.kernel.ledger()?,
            1,
            SequenceClock::shared([100, 100, execute_at]),
            fixture.kernel.identity()?,
        );
        let before_resources = fixture.kernel.authority.governor().inspect()?;
        let before_snapshot = fixture.kernel.ledger()?.snapshot()?;
        let before_catalog = (
            before_snapshot.catalog_identity(),
            before_snapshot.catalog_generation(),
        );
        drop(before_snapshot);
        let query = service.plan_pipeline(
            fixture.context,
            "logs | range query_time -100 100 | limit 1",
            deadline_budget(),
        )?;

        let failure = service
            .execute_page(query)
            .expect_err("elapsed page deadline must fail before snapshot lease creation");
        assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
        assert_eq!(
            failure.limiting_budget(),
            Some(QueryBudgetDimension::WallSeconds)
        );
        assert_eq!(
            fixture.kernel.authority.governor().inspect()?,
            before_resources
        );
        let after_snapshot = fixture.kernel.ledger()?.snapshot()?;
        assert_eq!(
            (
                after_snapshot.catalog_identity(),
                after_snapshot.catalog_generation(),
            ),
            before_catalog
        );
    }

    let fixture = QueryFixture::new("page-within-deadline")?;
    let service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
        fixture.kernel.identity()?,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        deadline_budget(),
    )?;
    let events = service.execute_page(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn scan_capacity_refusal_is_one_typed_non_complete_terminal() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("scan-capacity")?;
    fixture.kernel.append_log("accepted", 20, 1)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    let tenant = fixture
        .context
        .tenant_attribution()
        .ok_or("query attribution missing")?
        .tenant_id();
    let held = fixture
        .kernel
        .authority
        .governor()
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 6_850_000)?,
        )?)?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    drop(held);
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::ResourceAdmissionRefused
    ));
    assert_eq!(terminal_count(&events), 1);
    Ok(())
}

#[test]
fn parsers_budgets_keys_and_cursor_bytes_enforce_exact_public_bounds() -> Result<(), Box<dyn Error>>
{
    assert_ne!(
        QueryFailureCode::ResourceExhausted,
        QueryFailureCode::BudgetExhausted
    );
    assert_eq!(
        QueryBudget::new(1, 1_025, 1, 1, 1, 1)
            .expect_err("decoded record bound")
            .code(),
        QueryFailureCode::InvalidBudget
    );
    assert_eq!(
        QueryBudget::new(1, 1, 1_025, 1, 1, 1)
            .expect_err("output row bound")
            .code(),
        QueryFailureCode::InvalidBudget
    );
    assert_eq!(
        QueryBudget::new(1, 1, 1, 1, 1, 1)?
            .with_cpu_work_units(0)
            .expect_err("zero cpu budget")
            .code(),
        QueryFailureCode::InvalidBudget
    );
    assert_eq!(
        QueryBudget::new(1, 1, 1, 1, 1, 1)?
            .with_maximum_time_range_nanoseconds(0)
            .expect_err("zero temporal bound")
            .code(),
        QueryFailureCode::InvalidBudget
    );
    assert_eq!(
        QueryBudget::new(1, 1, 1, 1, 1, 3_600)?.wall_seconds(),
        3_600
    );
    let overlong_wall = QueryBudget::new(1, 1, 1, 1, 1, 3_601)
        .expect_err("wall budget above the Release-1 lease ceiling");
    assert_eq!(overlong_wall.code(), QueryFailureCode::InvalidBudget);
    assert_eq!(
        overlong_wall.limiting_budget(),
        Some(QueryBudgetDimension::WallSeconds)
    );
    assert!(QueryCursor::from_bytes(&[0; 340]).is_err());
    assert!(QueryCursor::from_bytes(&[0; 341]).is_ok());
    assert!(QueryCursor::from_bytes(&[0; 342]).is_err());
    assert!(QueryCursor::from_bytes(&[0; 373]).is_ok());
    assert!(QueryCursor::from_bytes(&[0; 382]).is_err());
    // The old POSQCR01 4,481-byte representation was an ambiguous pre-v4
    // source-bearing cursor. Only the genuinely legacy v1/v3 shapes remain
    // accepted; current cursors have an explicit version/domain marker.
    assert!(QueryCursor::from_bytes(&[0; 4481]).is_err());
    assert!(QueryCursor::from_bytes(&[0; 4482]).is_err());
    assert_eq!(
        format!("{:?}", QueryCursor::from_bytes(&[0; 341])?),
        "QueryCursor { <opaque> }"
    );
    assert_eq!(
        QueryBudget::new(0, 1, 1, 1, 1, 1)
            .expect_err("zero budget")
            .to_string(),
        "query request failed"
    );

    let fixture = QueryFixture::new("bounds")?;
    let service = fixture.service(16)?;
    let pipeline = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1024",
        budget(),
    )?;
    let sql = service.plan_sql(
        fixture.context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1024",
        budget(),
    )?;
    assert_eq!(pipeline.logical_plan(), sql.logical_plan());
    drop((pipeline, sql));
    for source in [
        "logs | range query_time -100 100 | limit 0",
        "logs | range query_time -100 100 | limit 1025",
        "logs | range query_time -100 100 | limit 01",
        "logs | range query_time -100 100 | limit 1 trailing",
    ] {
        assert_eq!(
            failure_code(service.plan_pipeline(fixture.context, source, budget()))?,
            if source.ends_with(" 0") || source.ends_with("1025") {
                QueryFailureCode::InvalidBudget
            } else {
                QueryFailureCode::UnsupportedQuery
            }
        );
    }
    for source in [
        "logs | range unsupported -100 100 | limit 1",
        "logs | range query_time +1 100 | limit 1",
        "logs | range query_time 01 100 | limit 1",
        "logs | range query_time -01 100 | limit 1",
    ] {
        assert_eq!(
            failure_code(service.plan_pipeline(fixture.context, source, budget()))?,
            QueryFailureCode::UnsupportedQuery
        );
    }
    assert_eq!(
        failure_code(service.plan_sql(fixture.context, "SELECT * FROM logs LIMIT 1", budget()))?,
        QueryFailureCode::UnsupportedQuery
    );
    assert_eq!(
        failure_code(service.plan_pipeline(fixture.administrator, "malformed", budget()))?,
        QueryFailureCode::Unauthorized
    );
    assert_eq!(
        failure_code(service.plan_pipeline(
            fixture.context,
            "malformed",
            QueryBudget::new(1, 1, 1, 1, 9_000_000, 1)?,
        ))?,
        QueryFailureCode::ResourceAdmissionRefused
    );
    for source in [
        "pipeline:v1 logs | range query_time -100 100 | limit 1 | filter body == \"late\"",
        "pipeline:v1 logs | filter body == \"late\" | range query_time -100 100 | limit 1",
    ] {
        assert_eq!(
            failure_code(service.plan_pipeline(fixture.context, source, budget()))?,
            QueryFailureCode::UnsupportedQuery
        );
    }
    Ok(())
}

#[test]
fn every_query_frontend_rejects_source_bytes_beyond_the_public_bound_before_parsing()
-> Result<(), Box<dyn Error>> {
    const MAX_QUERY_SOURCE_BYTES: usize = 4_096;
    let fixture = QueryFixture::new("source-byte-bound")?;
    let service = fixture.service(16)?;
    let shorthand = padded_source(
        "logs | range query_time -100 100 | limit 1",
        MAX_QUERY_SOURCE_BYTES,
    )?;
    let sql = padded_source(
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        MAX_QUERY_SOURCE_BYTES,
    )?;

    drop(service.plan_pipeline(fixture.context, &shorthand, budget())?);
    drop(service.plan_sql(fixture.context, &sql, budget())?);

    assert_eq!(
        failure_code(service.plan_pipeline(fixture.context, &format!("{shorthand} "), budget(),))?,
        QueryFailureCode::UnsupportedQuery
    );
    assert_eq!(
        failure_code(service.plan_sql(fixture.context, &format!("{sql} "), budget()))?,
        QueryFailureCode::UnsupportedQuery
    );
    Ok(())
}

#[test]
fn planning_memory_is_admitted_before_sql_and_pipeline_allocations() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("planning-memory-admission")?;
    let service = fixture.service(16)?;
    let too_small = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1, 60)?;
    for source in [
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body, query_time, event_time, ingest_time, commit_position FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND record[\"items\"] any = array(string(\"a\"), string(\"b\")) ORDER BY query_time, commit_position LIMIT 1",
    ] {
        let failure = match service.plan_sql(fixture.context, source, too_small) {
            Ok(_) => return Err("SQL planning unexpectedly succeeded".into()),
            Err(failure) => failure,
        };
        assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
        assert_eq!(
            failure.limiting_budget(),
            Some(QueryBudgetDimension::MemoryBytes)
        );
    }
    let pipeline_failure = match service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        too_small,
    ) {
        Ok(_) => return Err("pipeline planning unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(pipeline_failure.code(), QueryFailureCode::BudgetExhausted);
    assert_eq!(
        pipeline_failure.limiting_budget(),
        Some(QueryBudgetDimension::MemoryBytes)
    );
    let retained_failure = match service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | project body, query_time, event_time, ingest_time, commit_position | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 384, 60)?,
    ) {
        Ok(_) => return Err("retained plan allocation unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(retained_failure.code(), QueryFailureCode::BudgetExhausted);

    let search_failure = match service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | search body =~ "needle" | limit 1"#,
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 43_000, 60)?,
    ) {
        Ok(_) => return Err("search plan unexpectedly succeeded below its memory charge".into()),
        Err(failure) => failure,
    };
    assert_eq!(search_failure.code(), QueryFailureCode::InvalidBudget);

    let normal = budget();
    service.plan_sql(
        fixture.context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        normal,
    )?;
    service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        normal,
    )?;
    Ok(())
}

#[test]
fn equivalent_sql_and_pipeline_fit_their_shared_minimum_planning_budget()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("sql-incremental-token-memory")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 2_048, 60)?;
    let pipeline = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget,
    )?;
    let sql = service.plan_sql(
        fixture.context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        budget,
    )?;
    assert_eq!(pipeline.logical_plan(), sql.logical_plan());
    Ok(())
}

#[test]
fn native_literal_peak_memory_is_admitted_before_validation_output() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("native-literal-peak-memory")?;
    let service = fixture.service(16)?;
    let values = (0..180)
        .map(|_| r#"string("x")"#)
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND record[\"items\"] any = array({values}) ORDER BY query_time, commit_position LIMIT 1"
    );
    let exact_memory = 30_697_u64
        .checked_add(u64::try_from(source.len())?)
        .ok_or("native literal source bound overflowed")?;
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, exact_memory, 60)?;
    drop(
        service
            .plan_sql(fixture.context, &source, budget)
            .map_err(|failure| format!("exact native literal planning failed: {failure:?}"))?,
    );
    let under_budget = QueryBudget::new(
        1_048_576,
        16,
        16,
        1_048_576,
        exact_memory.checked_sub(1).ok_or("memory underflowed")?,
        60,
    )?;
    let failure = match service.plan_sql(fixture.context, &source, under_budget) {
        Ok(_) => return Err("one byte below native literal peak unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
    assert_eq!(
        failure.limiting_budget(),
        Some(QueryBudgetDimension::MemoryBytes)
    );
    Ok(())
}

#[test]
fn bounded_path_segments_transfer_exact_capacity() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("path-segment-capacity")?;
    let service = fixture.service(16)?;
    let path = (0..16)
        .map(|index| format!(r#"["s{index}"]"#))
        .collect::<String>();
    let source = format!(
        "SELECT record{path} FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1"
    );
    let exact_memory = 3_974_u64
        .checked_add(u64::try_from(source.len())?)
        .ok_or("path source bound overflowed")?;
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, exact_memory, 60)?;
    drop(service.plan_sql(fixture.context, &source, budget)?);
    let under_budget = QueryBudget::new(
        1_048_576,
        16,
        16,
        1_048_576,
        exact_memory.checked_sub(1).ok_or("memory underflowed")?,
        60,
    )?;
    let failure = match service.plan_sql(fixture.context, &source, under_budget) {
        Ok(_) => return Err("one byte below path capacity unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
    assert_eq!(
        failure.limiting_budget(),
        Some(QueryBudgetDimension::MemoryBytes)
    );
    Ok(())
}

#[test]
fn sql_index_selector_transfers_both_owned_reservations() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("index-selector-capacity")?;
    let service = fixture.service(16)?;
    let before = fixture.kernel.authority.governor().inspect()?;
    let source = "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND record[\"payload\"] INDEX(123) = string(\"x\") ORDER BY query_time, commit_position LIMIT 1";
    let exact_memory = 3_944_u64
        .checked_add(u64::try_from(source.len())?)
        .ok_or("index source bound overflowed")?;
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, exact_memory, 60)?;
    drop(service.plan_sql(fixture.context, source, budget)?);
    let failure = match service.plan_sql(
        fixture.context,
        source,
        QueryBudget::new(
            1_048_576,
            16,
            16,
            1_048_576,
            exact_memory.checked_sub(1).ok_or("memory underflowed")?,
            60,
        )?,
    ) {
        Ok(_) => {
            return Err("one byte below index selector capacity unexpectedly succeeded".into());
        },
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
    assert_eq!(
        failure.limiting_budget(),
        Some(QueryBudgetDimension::MemoryBytes)
    );
    assert_eq!(fixture.kernel.authority.governor().inspect()?, before);
    Ok(())
}

#[test]
fn sql_parenthesis_bound_is_explicitly_shallower_than_native_values() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("sql-parenthesis-bound")?;
    let service = fixture.service(16)?;
    let literal = |depth| {
        let mut value = String::from("null");
        for _ in 0..depth {
            value = format!("array({value})");
        }
        value
    };
    let source = |depth| {
        format!(
            "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND record[\"nested\"] any = {} ORDER BY query_time, commit_position LIMIT 1",
            literal(depth)
        )
    };
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?;
    drop(service.plan_sql(fixture.context, &source(16), budget)?);
    let failure = match service.plan_sql(fixture.context, &source(17), budget) {
        Ok(_) => return Err("SQL nesting beyond the documented lexer bound succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::UnsupportedQuery);
    Ok(())
}

#[test]
fn rejected_search_transfer_releases_parser_and_copy_reservations() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("search-transfer-rollback")?;
    let service = fixture.service(16)?;
    let before = fixture.kernel.authority.governor().inspect()?;
    let literal = "x".repeat(1_025);
    let pipeline = format!(
        "pipeline:v1 logs | range query_time -100 100 | search body contains \"{literal}\" | limit 1"
    );
    let sql = format!(
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body CONTAINS \"{literal}\" ORDER BY query_time, commit_position LIMIT 1"
    );
    for source in [pipeline, sql] {
        let failure = if source.starts_with("pipeline:") {
            match service.plan_pipeline(fixture.context, &source, budget()) {
                Ok(_) => return Err("oversized search source unexpectedly succeeded".into()),
                Err(failure) => failure,
            }
        } else {
            match service.plan_sql(fixture.context, &source, budget()) {
                Ok(_) => return Err("oversized search source unexpectedly succeeded".into()),
                Err(failure) => failure,
            }
        };
        assert_eq!(failure.code(), QueryFailureCode::UnsupportedQuery);
    }
    assert_eq!(fixture.kernel.authority.governor().inspect()?, before);
    Ok(())
}

#[test]
fn native_quoted_and_bytes_boundaries_share_closed_parser_errors() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("native-parser-boundaries")?;
    let service = fixture.service(16)?;
    for source in [
        r#"pipeline:v1 logs | range query_time -100 100 | filter record["bad\q"] any == null | limit 1"#,
        r#"pipeline:v1 logs | range query_time -100 100 | filter record["unterminated] any == null | limit 1"#,
        "pipeline:v1 logs | range query_time -100 100 | json | logfmt | limit 1",
    ] {
        assert_eq!(
            failure_code(service.plan_pipeline(fixture.context, source, budget()))?,
            QueryFailureCode::UnsupportedQuery
        );
    }
    let valid = r#"pipeline:v1 logs | range query_time -100 100 | filter record["payload"] any == bytes(0x00) | limit 1"#;
    assert!(
        service
            .plan_pipeline(fixture.context, valid, budget())
            .is_ok()
    );
    let unknown_operator = r#"SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body LIKE "x" ORDER BY query_time, commit_position LIMIT 1"#;
    assert_eq!(
        failure_code(service.plan_sql(fixture.context, unknown_operator, budget()))?,
        QueryFailureCode::UnsupportedQuery
    );
    Ok(())
}

#[test]
fn native_scalar_queries_transfer_exact_string_and_bytes_capacity() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("native-scalar-boundaries")?;
    let service = fixture.service(16)?;
    let governor_before = fixture.kernel.authority.governor().inspect()?;
    let literal = "x".repeat(512);
    let pipeline_string = format!(
        "pipeline:v1 logs | range query_time -100 100 | filter record[\"payload\"] any == string(\"{literal}\") | limit 1"
    );
    let sql_string = format!(
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND record[\"payload\"] any = string(\"{literal}\") ORDER BY query_time, commit_position LIMIT 1"
    );
    let bytes = "ab".repeat(256);
    let pipeline_bytes = format!(
        "pipeline:v1 logs | range query_time -100 100 | filter record[\"payload\"] any == bytes(0x{bytes}) | limit 1"
    );
    let sql_bytes = format!(
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND record[\"payload\"] any = bytes(0x{bytes}) ORDER BY query_time, commit_position LIMIT 1"
    );
    let pipeline_float = "pipeline:v1 logs | range query_time -100 100 | filter record[\"payload\"] any == float_bits(0x3ff0000000000000) | limit 1";
    let sql_float = "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND record[\"payload\"] any = float_bits(0x3ff0000000000000) ORDER BY query_time, commit_position LIMIT 1";
    let budget = |memory| QueryBudget::new(1_048_576, 16, 16, 1_048_576, memory, 60);

    let pipeline_string_plan = service.plan_pipeline(
        fixture.context,
        &pipeline_string,
        budget(4_159 + u64::try_from(pipeline_string.len())?)?,
    )?;
    let sql_string_plan = service.plan_sql(
        fixture.context,
        &sql_string,
        budget(4_813 + u64::try_from(sql_string.len())?)?,
    )?;
    assert_eq!(
        pipeline_string_plan.logical_plan(),
        sql_string_plan.logical_plan()
    );
    let pipeline_bytes_plan = service.plan_pipeline(
        fixture.context,
        &pipeline_bytes,
        budget(3_903 + u64::try_from(pipeline_bytes.len())?)?,
    )?;
    let sql_bytes_plan = service.plan_sql(
        fixture.context,
        &sql_bytes,
        budget(4_556 + u64::try_from(sql_bytes.len())?)?,
    )?;
    assert_eq!(
        pipeline_bytes_plan.logical_plan(),
        sql_bytes_plan.logical_plan()
    );
    let pipeline_float_plan = service.plan_pipeline(
        fixture.context,
        pipeline_float,
        budget(8_192 + u64::try_from(pipeline_float.len())?)?,
    )?;
    let sql_float_plan = service.plan_sql(
        fixture.context,
        sql_float,
        budget(8_192 + u64::try_from(sql_float.len())?)?,
    )?;
    assert_eq!(
        pipeline_float_plan.logical_plan(),
        sql_float_plan.logical_plan()
    );
    drop((
        pipeline_string_plan,
        sql_string_plan,
        pipeline_bytes_plan,
        sql_bytes_plan,
        pipeline_float_plan,
        sql_float_plan,
    ));

    for (source, memory, sql) in [
        (&pipeline_string, 4_158, false),
        (&sql_string, 4_812, true),
        (&pipeline_bytes, 3_902, false),
        (&sql_bytes, 4_555, true),
    ] {
        let failure = if sql {
            match service.plan_sql(fixture.context, source, budget(memory)?) {
                Ok(_) => {
                    return Err(
                        "scalar query under its exact capacity unexpectedly succeeded".into(),
                    );
                },
                Err(failure) => failure,
            }
        } else {
            match service.plan_pipeline(fixture.context, source, budget(memory)?) {
                Ok(_) => {
                    return Err(
                        "scalar query under its exact capacity unexpectedly succeeded".into(),
                    );
                },
                Err(failure) => failure,
            }
        };
        assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
        assert_eq!(
            failure.limiting_budget(),
            Some(QueryBudgetDimension::MemoryBytes)
        );
    }
    assert_eq!(
        fixture.kernel.authority.governor().inspect()?,
        governor_before
    );
    Ok(())
}

#[test]
fn pipeline_token_scratch_is_charged_before_collecting_bounded_input() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("pipeline-token-memory")?;
    let service = fixture.service(16)?;
    let noisy_stage = "x ".repeat(1_900);
    let source = format!("pipeline:v1 logs | range {noisy_stage}| limit 1");
    assert!(source.len() <= 4_096);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4_096, 60)?;
    let failure = match service.plan_pipeline(fixture.context, &source, budget) {
        Ok(_) => return Err("oversized pipeline token scratch unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
    assert_eq!(
        failure.limiting_budget(),
        Some(QueryBudgetDimension::MemoryBytes)
    );
    Ok(())
}

pub(crate) struct QueryFixture {
    _roots: TemporaryRoots,
    pub(crate) kernel: KernelFixture,
    pub(crate) context: positron_governance::AuthorizedContext,
    administrator: positron_governance::AuthorizedContext,
}

impl QueryFixture {
    pub(crate) fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let roots = TemporaryRoots::new(label)?;
        let paths = BootstrapPaths::new(
            &roots.data(),
            &roots.secrets(),
            positron_kernel::MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let claim = InstanceBootstrap::claim(&paths)?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let context = instance.attribute(
            PresentedCredential::parse(claim.query_secret().ok_or("query secret missing")?)?,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        )?;
        let administrator = instance.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?;
        let governance = instance.governance_fixture_for_test()?;
        let kernel =
            KernelFixture::new_with_identity(instance.default_tenant_id(), label, &governance)?;
        Ok(Self {
            _roots: roots,
            kernel,
            context,
            administrator,
        })
    }

    pub(crate) fn service(
        &self,
        batch_limit: u16,
    ) -> Result<QueryService<'static, 'static, '_>, Box<dyn Error>> {
        Ok(super::support::zero_work_service(
            self.kernel.authority.governor(),
            self.kernel.ledger()?,
            batch_limit,
            self.kernel.identity()?,
        ))
    }
}

fn budget() -> QueryBudget {
    QueryBudget::new(1_048_576, 1_024, 1_024, 1_048_576, 1_048_576, 60).expect("fixture budget")
}

fn deadline_budget() -> QueryBudget {
    QueryBudget::new(1_048_576, 1_024, 1_024, 1_048_576, 1_048_576, 1)
        .expect("deadline fixture budget")
}

fn terminal_count(events: &[QueryEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, QueryEvent::Terminal(_)))
        .count()
}

fn failure_code<T>(
    result: Result<T, positron_query::QueryFailure>,
) -> Result<QueryFailureCode, Box<dyn Error>> {
    match result {
        Ok(_) => Err("query unexpectedly planned".into()),
        Err(failure) => Ok(failure.code()),
    }
}

fn padded_source(source: &str, bytes: usize) -> Result<String, Box<dyn Error>> {
    let padding = bytes
        .checked_sub(source.len())
        .ok_or("query fixture exceeds its intended byte bound")?;
    Ok(format!("{source}{:padding$}", ""))
}
