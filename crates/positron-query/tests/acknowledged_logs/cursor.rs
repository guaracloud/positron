use std::error::Error;
use std::sync::Arc;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{
    QueryBudget, QueryCursor, QueryEvent, QueryFailureCode, QueryService, QueryTerminal,
};
use positron_runtime::GovernanceTestFixture;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::support::{
    FailAfterArmClock, FailAfterArmOutputMeter, KernelFixture, TemporaryRoots, TestClock,
};

#[path = "cursor/event_time.rs"]
mod event_time;

#[test]
fn authenticated_cursor_resumes_the_same_snapshot_and_repeats_deterministically()
-> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("cursor")?;
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
    let governance = instance.governance_fixture_for_test()?;
    let fixture = KernelFixture::new_with_identity(
        instance.default_tenant_id(),
        "cursor-kernel",
        &governance,
    )?;
    fixture.append_log("first", 20, 1)?;
    fixture.append_log("second", 21, 2)?;
    let clock = TestClock::shared(100);
    let service = super::support::zero_work_clock_service(
        fixture.authority.governor(),
        fixture.ledger()?,
        1,
        clock.clone(),
    );
    let plan = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?.with_cpu_work_units(16)?,
    )?;
    let first = service.execute_page(plan)?.collect::<Vec<_>>();
    let cursor = continuation(&first)?.clone();
    let first_batch = batch_identity(&first)?;

    fixture.append_log("future", 22, 3)?;
    clock.set(101);
    let mut resumed = super::support::zero_work_clock_service(
        fixture.authority.governor(),
        fixture.ledger()?,
        1,
        clock.clone(),
    )
    .resume(context, &cursor)?;
    let resumed_events = resumed.by_ref().take(2).collect::<Vec<_>>();
    drop(resumed);
    let repeated = service.resume(context, &cursor)?;
    assert_eq!(bodies(&resumed_events), ["second"]);
    let repeated = repeated.collect::<Vec<_>>();
    assert!(matches!(
        repeated.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    assert_eq!(batch_identity(&resumed_events)?, batch_identity(&repeated)?);
    assert_ne!(first_batch, batch_identity(&resumed_events)?);
    Ok(())
}

#[test]
fn result_envelope_identifies_snapshot_schema_budget_order_lease_and_digest_chain()
-> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let first = fixture
        .service()
        .resume(fixture.context, &fixture.cursor)?
        .collect::<Vec<_>>();
    let header = match first.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("result header missing".into()),
    };
    assert_eq!(header.schema().columns(), ["body"]);
    assert_eq!(header.snapshot().frontier(), 2);
    assert_ne!(header.snapshot().identity(), [0; 32]);
    assert!(header.snapshot().generation() > 0);
    assert_eq!(
        header.ordering().columns(),
        ["query_time", "commit_position", "record_ordinal"]
    );
    assert_eq!(header.budget().output_rows(), 16);
    assert_ne!(header.lease().identity(), [0; 16]);
    assert!(header.lease().expiry() > 0);
    assert!(header.initial_cursor().is_some());

    let batch = first
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("result batch missing")?;
    assert_ne!(batch.prior_digest(), [0; 32]);
    assert_ne!(batch.digest(), batch.prior_digest());
    let terminal = first.last().ok_or("terminal missing")?;
    assert!(matches!(
        terminal,
        QueryEvent::Terminal(QueryTerminal::Complete(stats))
            if stats.result_digest() == batch.digest()
    ));
    Ok(())
}

#[test]
fn equivalent_pipeline_and_sql_pages_share_one_authenticated_plan_digest()
-> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?;
    let pipeline = fixture.service().plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 2",
        budget,
    )?;
    let sql = fixture.service().plan_sql(
        fixture.context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 2",
        budget,
    )?;
    let pipeline_events = fixture
        .service()
        .execute_page(pipeline)?
        .collect::<Vec<_>>();
    let sql_events = fixture.service().execute_page(sql)?.collect::<Vec<_>>();
    let pipeline_cursor = continuation(&pipeline_events)?;
    let sql_cursor = continuation(&sql_events)?;
    assert_eq!(
        pipeline_cursor.as_bytes().get(123..155),
        sql_cursor.as_bytes().get(123..155)
    );
    Ok(())
}

#[test]
fn resume_admits_before_reconstructing_the_authenticated_plan() -> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let held = fixture
        .kernel
        .authority
        .governor()
        .reserve(positron_kernel::WorkClaim::tenant(
            fixture
                .context
                .tenant_attribution()
                .ok_or("query tenant missing")?
                .tenant_id(),
            positron_kernel::WorkKind::InteractiveQueryTail,
            positron_kernel::ResourceAmounts::only(
                positron_kernel::ResourceDimension::MemoryBytes,
                7_500_000,
            )?,
        )?)?;
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        fixture.clock.clone(),
        std::sync::Arc::new(super::support::FailingStageWorkMeter(
            positron_query::QueryWorkStage::Parse,
        )),
    );
    let failure = match service.resume(fixture.context, &fixture.cursor) {
        Err(failure) => failure,
        Ok(_) => return Err("admission unexpectedly succeeded".into()),
    };
    assert_eq!(failure.code(), QueryFailureCode::ResourceAdmissionRefused);
    let before_drop = fixture
        .kernel
        .authority
        .governor()
        .inspect()?
        .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
    drop(held);
    let after_drop = fixture
        .kernel
        .authority
        .governor()
        .inspect()?
        .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
    assert_eq!(after_drop + 1, before_drop);
    Ok(())
}

#[test]
fn terminal_stats_report_cumulative_resume_and_repeat_state() -> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let service = super::support::stage_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        fixture.clock.clone(),
    );
    let mut first = service.resume(fixture.context, &fixture.cursor)?;
    assert!(matches!(first.next(), Some(QueryEvent::Header(_))));
    assert!(matches!(first.next(), Some(QueryEvent::Batch(_))));
    drop(first);

    let mut repeated = service.resume(fixture.context, &fixture.cursor)?;
    assert!(matches!(repeated.next(), Some(QueryEvent::Header(_))));
    assert!(matches!(repeated.next(), Some(QueryEvent::Batch(_))));
    drop(repeated);

    let completed = service
        .resume(fixture.context, &fixture.cursor)?
        .collect::<Vec<_>>();
    let repeated_stats = match completed.last() {
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats))) => *stats,
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete))) => incomplete.stats(),
        _ => return Err("repeated resumed terminal missing".into()),
    };
    assert_eq!(repeated_stats.resume_count(), 3);
    assert_eq!(repeated_stats.repeated_batch_count(), 2);
    assert_eq!(repeated_stats.cumulative_budget().decoded_records(), 16);
    Ok(())
}

#[test]
fn resumable_delivery_matrix_preserves_page_bytes_and_cumulative_stats()
-> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let service = fixture.service();
    let plan = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?.with_cpu_work_units(32)?,
    )?;
    let first = service.execute_page(plan)?.collect::<Vec<_>>();
    let cursor = continuation(&first)?.clone();

    let mut first_retry = super::support::stage_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        fixture.clock.clone(),
    )
    .resume(fixture.context, &cursor)?;
    let first_retry_header = first_retry.next().ok_or("retry header missing")?;
    let first_retry_batch = first_retry.next().ok_or("retry batch missing")?;
    let first_retry_identity = match &first_retry_batch {
        QueryEvent::Batch(batch) => (batch.sequence(), batch.digest()),
        _ => return Err("retry batch has the wrong event type".into()),
    };
    drop(first_retry);
    let mut second_retry = super::support::stage_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        fixture.clock.clone(),
    )
    .resume(fixture.context, &cursor)?;
    assert_eq!(second_retry.next(), Some(first_retry_header));
    assert_eq!(second_retry.next(), Some(first_retry_batch));
    drop(second_retry);

    let terminal = super::support::stage_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        fixture.clock.clone(),
    )
    .resume(fixture.context, &cursor)?
    .collect::<Vec<_>>();
    let stats = match terminal.last() {
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats))) => *stats,
        _ => return Err("final retry terminal missing".into()),
    };
    assert_eq!(batch_identity(&terminal)?, first_retry_identity);
    assert_eq!(bodies(&terminal), ["second"]);
    assert_eq!(stats.records(), 2);
    assert!(stats.scanned_bytes() > 0);
    assert!(stats.decoded_records() >= 2);
    assert!(stats.output_bytes() > 0);
    assert!(stats.memory_peak_bytes() > 0);
    assert!(stats.cpu_work_units() > 0);
    assert_eq!(stats.cumulative_budget().scanned_bytes(), 1_048_576);
    assert_eq!(stats.cumulative_budget().decoded_records(), 16);
    assert_eq!(stats.cumulative_budget().output_rows(), 16);
    assert_eq!(stats.cumulative_budget().output_bytes(), 1_048_576);
    assert_eq!(stats.resume_count(), 3);
    assert_eq!(stats.repeated_batch_count(), 2);
    Ok(())
}

#[test]
fn resumable_reconnect_survives_query_service_and_ledger_reopen() -> Result<(), Box<dyn Error>> {
    let mut fixture = CursorFixture::new()?;
    let cursor = fixture.cursor.clone();
    let mut first = fixture.service().resume(fixture.context, &cursor)?;
    assert!(matches!(first.next(), Some(QueryEvent::Header(_))));
    assert!(matches!(first.next(), Some(QueryEvent::Batch(_))));
    drop(first);
    fixture.kernel.reopen_ledger()?;
    let resumed = fixture
        .service()
        .resume(fixture.context, &cursor)?
        .collect::<Vec<_>>();
    assert_eq!(bodies(&resumed), ["second"]);
    assert!(matches!(
        resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn resume_rejects_cumulative_counter_underflow_before_additional_work() -> Result<(), Box<dyn Error>>
{
    let fixture = CursorFixture::new()?;
    let decoded_underflow = rewritten_cursor(
        &fixture,
        |bytes| {
            bytes[227..235].copy_from_slice(&1_u64.to_be_bytes());
            bytes[291..299].copy_from_slice(&2_u64.to_be_bytes());
        },
        b"query-cursor-v4",
    )?;
    let decoded_events = fixture
        .service()
        .resume(fixture.context, &decoded_underflow)?
        .collect::<Vec<_>>();
    assert!(
        decoded_events
            .iter()
            .all(|event| !matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        decoded_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::BudgetExhausted
                && failure.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::DecodedRecords)
    ));

    let fixture = CursorFixture::new()?;
    let scanned_underflow = rewritten_cursor(
        &fixture,
        |bytes| {
            bytes[219..227].copy_from_slice(&1_u64.to_be_bytes());
            bytes[283..291].copy_from_slice(&2_u64.to_be_bytes());
        },
        b"query-cursor-v4",
    )?;
    let scanned_events = fixture
        .service()
        .resume(fixture.context, &scanned_underflow)?
        .collect::<Vec<_>>();
    assert!(matches!(
        scanned_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::BudgetExhausted
                && failure.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::ScannedBytes)
    ));

    let fixture = CursorFixture::new()?;
    let output_underflow = rewritten_cursor(
        &fixture,
        |bytes| {
            bytes[299..307].copy_from_slice(&3_u64.to_be_bytes());
            bytes[235..243].copy_from_slice(&2_u64.to_be_bytes());
        },
        b"query-cursor-v4",
    )?;
    let output_events = fixture
        .service()
        .resume(fixture.context, &output_underflow)?
        .collect::<Vec<_>>();
    assert!(matches!(
        output_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::BudgetExhausted
                && failure.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::OutputRows)
    ));
    Ok(())
}

#[test]
fn legacy_numeric_cursor_is_rejected_without_resuming_any_temporal_axis()
-> Result<(), Box<dyn Error>> {
    for _axis in [2_u8, 3_u8] {
        let fixture = CursorFixture::new()?;
        let legacy = legacy_cursor(&fixture)?;
        assert_eq!(
            fixture
                .service()
                .resume(fixture.context, &legacy)
                .expect_err("legacy numeric cursor must never resume")
                .code(),
            QueryFailureCode::InvalidCursor
        );
    }
    Ok(())
}

#[test]
fn resume_rejects_a_reconstructed_plan_that_cannot_fit_its_memory_budget()
-> Result<(), Box<dyn Error>> {
    let mut fixture = CursorFixture::new()?;
    let plan = fixture.service().plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | search body =~ "s.*" | limit 2"#,
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let first = fixture.service().execute_page(plan)?.collect::<Vec<_>>();
    fixture.cursor = continuation(&first)?.clone();
    let constrained = rewritten_cursor(
        &fixture,
        |bytes| bytes[251..259].copy_from_slice(&100_000_u64.to_be_bytes()),
        b"query-cursor-v4",
    )?;
    let failure = fixture
        .service()
        .resume(fixture.context, &constrained)
        .expect_err("reconstruction must enforce the authenticated memory ceiling");
    assert_eq!(failure.code(), QueryFailureCode::InvalidBudget);
    assert_eq!(
        failure.limiting_budget(),
        Some(positron_query::QueryBudgetDimension::MemoryBytes)
    );
    Ok(())
}

#[test]
fn advanced_resume_preserves_peak_and_pruning_stats_after_ledger_reopen()
-> Result<(), Box<dyn Error>> {
    let mut fixture = CursorFixture::new()?;
    let plan = fixture
        .service()
        .plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | search body contains \"s\" | limit 2",
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
        )
        .map_err(|failure| format!("plan: {failure:?}"))?;
    let first = fixture
        .service()
        .execute_page(plan)
        .map_err(|failure| format!("first: {failure:?}"))?
        .collect::<Vec<_>>();
    let cursor = continuation(&first)
        .map_err(|failure| format!("continuation: {failure}"))?
        .clone();
    fixture.kernel.reopen_ledger()?;
    let resumed = fixture
        .service()
        .resume(fixture.context, &cursor)
        .map_err(|failure| format!("resume: {failure:?}"))?
        .collect::<Vec<_>>();
    let stats = match resumed.last() {
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats))) => *stats,
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete))) => incomplete.stats(),
        _ => return Err("resumed terminal missing".into()),
    };
    assert!(stats.memory_peak_bytes() > 0);
    assert!(stats.reduced_pruning());
    Ok(())
}

#[test]
fn sql_resume_reconstructs_filter_and_projection_from_the_authenticated_source()
-> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let plan = fixture.service().plan_sql(
        fixture.context,
        "SELECT body, query_time FROM logs WHERE query_time >= -100 AND query_time < 100 AND body CONTAINS \"s\" ORDER BY query_time, commit_position LIMIT 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let first = fixture.service().execute_page(plan)?.collect::<Vec<_>>();
    let cursor = continuation(&first)?.clone();
    let resumed = fixture
        .service()
        .resume(fixture.context, &cursor)?
        .collect::<Vec<_>>();
    assert_eq!(bodies(&resumed), ["second"]);
    let header = resumed
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("resumed SQL header missing")?;
    assert_eq!(header.schema().columns(), ["body", "query_time"]);
    Ok(())
}

#[test]
fn aggregate_resume_reconstructs_grouping_from_the_authenticated_source()
-> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let plan = fixture.service().plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let first = fixture.service().execute_page(plan)?.collect::<Vec<_>>();
    let cursor = continuation(&first)?.clone();
    let resumed = fixture
        .service()
        .resume(fixture.context, &cursor)?
        .collect::<Vec<_>>();
    assert!(matches!(
        resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn aggregate_resume_reports_digest_work_failure_before_delivering_rows()
-> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let meter = FailAfterArmOutputMeter::shared(0);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        fixture.clock.clone(),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let plan = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let first = service.execute_page(plan)?.collect::<Vec<_>>();
    let cursor = continuation(&first)?.clone();
    meter.arm();

    let resumed = service
        .resume(fixture.context, &cursor)?
        .collect::<Vec<_>>();
    assert!(
        resumed
            .iter()
            .all(|event| !matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::Internal
                && failure.stats().records() == 1
                && failure.stats().output_bytes() > 0
    ));

    let fixture = CursorFixture::new()?;
    let meter = FailAfterArmOutputMeter::shared(2);
    meter.arm();
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        fixture.clock.clone(),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let plan = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let initial_failure = service.execute_page(plan)?.collect::<Vec<_>>();
    assert!(matches!(
        initial_failure.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::Internal
    ));
    Ok(())
}

#[test]
fn post_digest_clock_failure_persists_physical_output_without_delivery()
-> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let clock = FailAfterArmClock::shared(5);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        Arc::clone(&clock) as Arc<dyn positron_query::QueryClock>,
        Arc::new(super::support::ConstantWorkMeter(0)),
    );
    let plan = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let first = service.execute_page(plan)?.collect::<Vec<_>>();
    let cursor = continuation(&first)?.clone();
    clock.arm();

    let resumed = service
        .resume(fixture.context, &cursor)?
        .collect::<Vec<_>>();
    assert!(
        resumed
            .iter()
            .all(|event| !matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::Internal
                && failure.stats().records() == 1
                && failure.stats().output_bytes() == 23
    ));
    Ok(())
}

#[test]
fn result_resume_key_corruption_or_missing_frontier_fails_closed() -> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let plan = fixture.service().plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let first = fixture.service().execute_page(plan)?.collect::<Vec<_>>();
    let cursor = continuation(&first)?.clone();

    let malformed = rewritten_existing_cursor(
        &fixture,
        &cursor,
        |bytes| bytes[4_447] = 9,
        b"query-cursor-v4",
    )?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &malformed)
            .expect_err("unknown resume-key tag must fail closed")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    let missing = rewritten_existing_cursor(
        &fixture,
        &cursor,
        |bytes| bytes[4_448] ^= 1,
        b"query-cursor-v4",
    )?;
    let missing_events = fixture
        .service()
        .resume(fixture.context, &missing)?
        .collect::<Vec<_>>();
    assert!(matches!(
        missing_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::InvalidCursor
    ));

    let empty_key = rewritten_existing_cursor(
        &fixture,
        &cursor,
        |bytes| {
            bytes[4_447] = 0;
            bytes[4_448] = 1;
        },
        b"query-cursor-v4",
    )?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &empty_key)
            .expect_err("nonzero bytes in an empty resume key must fail closed")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    let reserved_key = rewritten_existing_cursor(
        &fixture,
        &cursor,
        |bytes| bytes[4_447 + 51] = 1,
        b"query-cursor-v4",
    )?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &reserved_key)
            .expect_err("nonzero resume-key padding must fail closed")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    let principal_mismatch = rewritten_existing_cursor(
        &fixture,
        &cursor,
        |bytes| bytes[16] ^= 1,
        b"query-cursor-v4",
    )?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &principal_mismatch)
            .expect_err("cursor principal binding must be enforced")
            .code(),
        QueryFailureCode::Unauthorized
    );
    Ok(())
}

#[test]
fn regex_resume_reconstructs_compilation_and_repeats_the_bounded_page() -> Result<(), Box<dyn Error>>
{
    let fixture = CursorFixture::new()?;
    fixture.kernel.append_log("start", 22, 3)?;
    let plan = fixture.service().plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | search body =~ "s.*" | limit 2"#,
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let first = fixture.service().execute_page(plan)?.collect::<Vec<_>>();
    let cursor = continuation(&first)?.clone();
    let resumed = fixture
        .service()
        .resume(fixture.context, &cursor)?
        .collect::<Vec<_>>();
    assert_eq!(bodies(&resumed), ["second"]);
    assert!(matches!(
        resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    Ok(())
}

#[test]
fn advanced_resume_revalidates_authenticated_source_limits() -> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let plan = fixture.service().plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | search body contains \"s\" | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let first = fixture.service().execute_page(plan)?.collect::<Vec<_>>();
    let cursor = continuation(&first)?.clone();
    let rewritten = rewritten_source_cursor(
        &fixture,
        &cursor,
        "pipeline:v1 logs | range query_time -100 100 | search body contains \"s\" | limit 1025",
    )?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &rewritten)
            .expect_err("reconstructed limit must remain bounded")
            .code(),
        QueryFailureCode::InvalidBudget
    );

    let malformed =
        rewritten_source_cursor(&fixture, &cursor, "pipeline:v1 logs | definitely_not_valid")?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &malformed)
            .expect_err("reconstructed parser failures must be preserved")
            .code(),
        QueryFailureCode::UnsupportedQuery
    );
    Ok(())
}

#[test]
fn cursor_tampering_expiry_and_wrong_authority_fail_before_resume_work()
-> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let mut bytes = fixture.cursor.as_bytes().to_vec();
    let byte = bytes
        .get_mut(8)
        .ok_or("bounded cursor is unexpectedly short")?;
    *byte ^= 1;
    let tampered = positron_query::QueryCursor::from_bytes(&bytes)?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &tampered)
            .expect_err("tampering must fail closed")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    fixture.clock.set(161);
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &fixture.cursor)
            .expect_err("expired cursor must fail closed")
            .code(),
        QueryFailureCode::SnapshotExpired
    );
    fixture.clock.set(101);
    assert_eq!(
        fixture
            .service()
            .resume(fixture.administrator, &fixture.cursor)
            .expect_err("system administrator cannot resume tenant data")
            .code(),
        QueryFailureCode::Unauthorized
    );
    let governance = fixture.governance.clone();
    let empty = KernelFixture::new_with_identity(
        fixture
            .context
            .tenant_attribution()
            .ok_or("query attribution missing")?
            .tenant_id(),
        "cursor-frontier-regression",
        &governance,
    )?;
    let behind = super::support::zero_work_service(empty.authority.governor(), empty.ledger()?, 1);
    assert_eq!(
        behind
            .resume(fixture.context, &fixture.cursor)
            .expect_err("snapshot frontier cannot move backwards")
            .code(),
        QueryFailureCode::SnapshotExpired
    );

    let catalog_mismatch = rewritten_cursor(&fixture, |bytes| bytes[88] ^= 1, b"query-cursor-v4")?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &catalog_mismatch)
            .expect_err("cursor catalog binding must be checked after lease admission")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    Ok(())
}

#[test]
fn cancelled_planned_query_is_rejected_before_snapshot_admission() -> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let plan = fixture.service().plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    plan.cancellation().cancel();
    assert_eq!(
        fixture
            .service()
            .execute_page(plan)
            .expect_err("cancelled query must not admit a snapshot")
            .code(),
        QueryFailureCode::Cancelled
    );
    Ok(())
}

#[test]
fn resume_clock_failure_is_reported_before_lease_reacquisition() -> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let service = super::support::zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        std::sync::Arc::new(super::support::FailingClock),
    );
    assert_eq!(
        service
            .resume(fixture.context, &fixture.cursor)
            .expect_err("clock failures must not admit a resumed lease")
            .code(),
        QueryFailureCode::Internal
    );
    Ok(())
}

#[test]
fn authenticated_cursor_semantics_versions_and_domain_are_fail_closed() -> Result<(), Box<dyn Error>>
{
    let fixture = CursorFixture::new()?;
    assert_eq!(fixture.cursor.as_bytes().len(), 4545);
    for (label, rewrite) in [
        (
            "magic",
            (|bytes: &mut Vec<u8>| bytes[0] ^= 1) as fn(&mut Vec<u8>),
        ),
        ("axis", |bytes: &mut Vec<u8>| bytes[104] = u8::MAX),
        ("plan digest", |bytes: &mut Vec<u8>| bytes[123] ^= 1),
        ("zero lease", |bytes: &mut Vec<u8>| bytes[195..211].fill(0)),
        ("zero cpu budget", |bytes: &mut Vec<u8>| {
            bytes[259..267].fill(0)
        }),
        ("overlong wall budget", |bytes: &mut Vec<u8>| {
            bytes[267..275].copy_from_slice(&3_601_u64.to_be_bytes())
        }),
        ("invalid pruning flag", |bytes: &mut Vec<u8>| {
            bytes[347] = 2;
        }),
        ("invalid plan language", |bytes: &mut Vec<u8>| {
            bytes[348] = 3;
        }),
        ("legacy source length", |bytes: &mut Vec<u8>| {
            bytes[348] = 0;
            bytes[349..351].copy_from_slice(&1_u16.to_be_bytes());
        }),
        ("source padding", |bytes: &mut Vec<u8>| {
            bytes[4446] = 1;
        }),
        ("overlong source length", |bytes: &mut Vec<u8>| {
            bytes[349..351].copy_from_slice(&4_097_u16.to_be_bytes());
        }),
    ] {
        if label == "magic" {
            assert!(rewritten_cursor(&fixture, rewrite, b"query-cursor-v4").is_err());
            continue;
        }
        let cursor = rewritten_cursor(&fixture, rewrite, b"query-cursor-v4")?;
        assert_eq!(
            fixture
                .service()
                .resume(fixture.context, &cursor)
                .expect_err(label)
                .code(),
            QueryFailureCode::InvalidCursor
        );
    }
    let source_free = rewritten_cursor(
        &fixture,
        |bytes| {
            bytes[348] = 0;
            bytes[349..351].fill(0);
        },
        b"query-cursor-v4",
    )?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &source_free)
            .expect_err("source-free v4 cursor must not reuse an advanced digest")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    let source_fixture =
        CursorFixture::new().map_err(|error| format!("source fixture failed: {error:?}"))?;
    let mut basic_encoding = Vec::with_capacity(19);
    basic_encoding.push(1);
    basic_encoding.extend_from_slice(&(-100_i64).to_be_bytes());
    basic_encoding.extend_from_slice(&100_i64.to_be_bytes());
    basic_encoding.extend_from_slice(&2_u16.to_be_bytes());
    let basic_digest = source_fixture
        .kernel
        .ledger()?
        .control_tokens()
        .digest(b"query-plan-v1", &basic_encoding)?;
    let source_free_basic = rewritten_cursor(
        &source_fixture,
        |bytes| {
            bytes[123..155].copy_from_slice(&basic_digest);
            bytes[348] = 0;
            bytes[349..351].fill(0);
            bytes[351..4447].fill(0);
        },
        b"query-cursor-v4",
    )?;
    assert_eq!(
        source_fixture
            .service()
            .resume(source_fixture.context, &source_free_basic)
            .expect_err("source-free current cursors must be rejected")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    for axis in [2_u8, 3_u8] {
        let axis_fixture =
            CursorFixture::new().map_err(|error| format!("axis fixture failed: {error:?}"))?;
        let mut axis_encoding = Vec::with_capacity(19);
        axis_encoding.push(axis);
        axis_encoding.extend_from_slice(&(-100_i64).to_be_bytes());
        axis_encoding.extend_from_slice(&100_i64.to_be_bytes());
        axis_encoding.extend_from_slice(&2_u16.to_be_bytes());
        let axis_digest = axis_fixture
            .kernel
            .ledger()?
            .control_tokens()
            .digest(b"query-plan-v1", &axis_encoding)?;
        let axis_cursor = rewritten_cursor(
            &axis_fixture,
            |bytes| {
                bytes[104] = axis;
                bytes[123..155].copy_from_slice(&axis_digest);
                bytes[348] = 0;
                bytes[349..351].fill(0);
                bytes[351..4447].fill(0);
            },
            b"query-cursor-v4",
        )?;
        assert_eq!(
            axis_fixture
                .service()
                .resume(axis_fixture.context, &axis_cursor)
                .expect_err("source-free current cursors must be rejected")
                .code(),
            QueryFailureCode::InvalidCursor
        );
    }
    let wrong_domain = rewritten_cursor(&fixture, |_| {}, b"query-result-batch-v1")?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &wrong_domain)
            .expect_err("control token purpose is part of authentication")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    for (label, rewrite) in [
        (
            "output rows budget",
            (|bytes: &mut Vec<u8>| {
                bytes[235..243].copy_from_slice(&1_u64.to_be_bytes());
            }) as fn(&mut Vec<u8>),
        ),
        (
            "maximum range budget",
            (|bytes: &mut Vec<u8>| {
                bytes[275..283].copy_from_slice(&1_u64.to_be_bytes());
            }) as fn(&mut Vec<u8>),
        ),
        (
            "memory budget",
            (|bytes: &mut Vec<u8>| {
                bytes[251..259].copy_from_slice(&1_u64.to_be_bytes());
            }) as fn(&mut Vec<u8>),
        ),
    ] {
        let cursor = rewritten_cursor(&fixture, rewrite, b"query-cursor-v4")?;
        let expected = if label == "memory budget" {
            QueryFailureCode::BudgetExhausted
        } else {
            QueryFailureCode::InvalidBudget
        };
        assert_eq!(
            fixture
                .service()
                .resume(fixture.context, &cursor)
                .expect_err(label)
                .code(),
            expected
        );
    }

    let legacy = legacy_cursor(&fixture)?;
    assert_eq!(legacy.as_bytes().len(), 341);
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &legacy)
            .expect_err("legacy cursor is not a resumable wire")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &legacy)
            .expect_err("legacy numeric cursor must never resume")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    let truncated = fixture
        .cursor
        .as_bytes()
        .get(..4542)
        .ok_or("cursor too short")?;
    assert_eq!(
        QueryCursor::from_bytes(truncated)
            .expect_err("truncated cursor must be rejected")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    let mut unknown_version = fixture.cursor.as_bytes().to_vec();
    unknown_version.extend_from_slice(&[0; 32]);
    assert_eq!(
        QueryCursor::from_bytes(&unknown_version)
            .expect_err("unknown cursor wire length must be rejected")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    Ok(())
}

fn rewritten_cursor(
    fixture: &CursorFixture,
    rewrite: impl FnOnce(&mut Vec<u8>),
    purpose: &[u8],
) -> Result<QueryCursor, Box<dyn Error>> {
    rewritten_existing_cursor(fixture, &fixture.cursor, rewrite, purpose)
}

fn rewritten_existing_cursor(
    fixture: &CursorFixture,
    cursor: &QueryCursor,
    rewrite: impl FnOnce(&mut Vec<u8>),
    purpose: &[u8],
) -> Result<QueryCursor, Box<dyn Error>> {
    let purpose = if purpose == b"query-cursor-v4" {
        b"query-cursor-v5".as_slice()
    } else {
        purpose
    };
    let mut payload = cursor.as_bytes()[..cursor.as_bytes().len() - 32].to_vec();
    rewrite(&mut payload);
    let protector = fixture.kernel.ledger()?.control_tokens();
    let initial = protector.authenticate_query_cursor(purpose, &payload)?;
    payload[8..16].copy_from_slice(&initial.epoch().to_be_bytes());
    let authentication = protector.authenticate_query_cursor(purpose, &payload)?;
    payload.extend_from_slice(&authentication.tag());
    Ok(QueryCursor::from_bytes(&payload)?)
}

fn legacy_cursor(fixture: &CursorFixture) -> Result<QueryCursor, Box<dyn Error>> {
    let mut payload = vec![0_u8; 309];
    payload[..8].copy_from_slice(b"POSQCR01");
    let protector = fixture.kernel.ledger()?.control_tokens();
    let initial = protector.authenticate_query_cursor(b"query-cursor-v1", &payload)?;
    payload[8..16].copy_from_slice(&initial.epoch().to_be_bytes());
    let authentication = protector.authenticate_query_cursor(b"query-cursor-v1", &payload)?;
    payload.extend_from_slice(&authentication.tag());
    Ok(QueryCursor::from_bytes(&payload)?)
}

#[test]
fn authenticated_cursor_rejects_unknown_api_and_language_versions() -> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let payload_len = fixture
        .cursor
        .as_bytes()
        .len()
        .checked_sub(32)
        .ok_or("cursor omitted its authentication tag")?;
    let version_start = payload_len
        .checked_sub(2)
        .ok_or("cursor omitted versions")?;
    for offset in version_start..payload_len {
        let cursor = rewritten_cursor(&fixture, |bytes| bytes[offset] = 2, b"query-cursor-v4")?;
        assert_eq!(
            fixture
                .service()
                .resume(fixture.context, &cursor)
                .expect_err("unknown authenticated cursor version must fail closed")
                .code(),
            QueryFailureCode::InvalidCursor
        );
    }
    Ok(())
}

#[test]
fn previous_current_cursor_wire_is_rejected_without_downgrade() -> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let payload_len = fixture
        .cursor
        .as_bytes()
        .len()
        .checked_sub(32)
        .ok_or("cursor omitted its authentication tag")?;
    let mut payload = fixture.cursor.as_bytes()[..payload_len].to_vec();
    payload[..8].copy_from_slice(b"POSQCR04");
    let protector = fixture.kernel.ledger()?.control_tokens();
    let initial = protector.authenticate_query_cursor(b"query-cursor-v4", &payload)?;
    payload[8..16].copy_from_slice(&initial.epoch().to_be_bytes());
    let authentication = protector.authenticate_query_cursor(b"query-cursor-v4", &payload)?;
    payload.extend_from_slice(&authentication.tag());
    assert_eq!(
        QueryCursor::from_bytes(&payload)
            .expect_err("the superseded current wire must not downgrade")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    Ok(())
}

fn rewritten_source_cursor(
    fixture: &CursorFixture,
    cursor: &QueryCursor,
    source: &str,
) -> Result<QueryCursor, Box<dyn Error>> {
    let mut payload = cursor.as_bytes()[..cursor.as_bytes().len() - 32].to_vec();
    let source_bytes = source.as_bytes();
    let source_length = u16::try_from(source_bytes.len())?;
    payload[349..351].copy_from_slice(&source_length.to_be_bytes());
    payload[351..4447].fill(0);
    payload[351..351 + source_bytes.len()].copy_from_slice(source_bytes);
    let mut encoding = Vec::with_capacity(1 + 2 + source_bytes.len());
    encoding.push(1);
    encoding.extend_from_slice(&source_length.to_be_bytes());
    encoding.extend_from_slice(source_bytes);
    let digest = fixture
        .kernel
        .ledger()?
        .control_tokens()
        .digest_query_cursor(b"query-plan-source-v1", &encoding)?;
    payload[123..155].copy_from_slice(&digest);
    let protector = fixture.kernel.ledger()?.control_tokens();
    let initial = protector.authenticate_query_cursor(b"query-cursor-v5", &payload)?;
    payload[8..16].copy_from_slice(&initial.epoch().to_be_bytes());
    let authentication = protector.authenticate_query_cursor(b"query-cursor-v5", &payload)?;
    payload.extend_from_slice(&authentication.tag());
    Ok(QueryCursor::from_bytes(&payload)?)
}

struct CursorFixture {
    _roots: TemporaryRoots,
    kernel: KernelFixture,
    context: positron_governance::AuthorizedContext,
    administrator: positron_governance::AuthorizedContext,
    cursor: positron_query::QueryCursor,
    clock: std::sync::Arc<TestClock>,
    governance: GovernanceTestFixture,
}

impl CursorFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let roots = TemporaryRoots::new("cursor-failures")?;
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
        let kernel = KernelFixture::new_with_identity(
            instance.default_tenant_id(),
            "cursor-failure-kernel",
            &governance,
        )?;
        kernel.append_log("first", 20, 1)?;
        kernel.append_log("second", 21, 2)?;
        let clock = TestClock::shared(100);
        let service = super::support::zero_work_clock_service(
            kernel.authority.governor(),
            kernel.ledger()?,
            1,
            clock.clone(),
        );
        let plan = service.plan_pipeline(
            context,
            "logs | range query_time -100 100 | limit 2",
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
                .with_cpu_work_units(16)?,
        )?;
        let events = service.execute_page(plan)?.collect::<Vec<_>>();
        let cursor = continuation(&events)?.clone();
        clock.set(101);
        Ok(Self {
            _roots: roots,
            kernel,
            context,
            administrator,
            cursor,
            clock,
            governance,
        })
    }

    fn service(&self) -> QueryService<'static, 'static, '_> {
        super::support::zero_work_clock_service(
            self.kernel.authority.governor(),
            self.kernel.ledger().expect("fixture ledger"),
            1,
            self.clock.clone(),
        )
    }
}

fn continuation(events: &[QueryEvent]) -> Result<&positron_query::QueryCursor, Box<dyn Error>> {
    match events.last() {
        Some(QueryEvent::Terminal(QueryTerminal::Continued(cursor))) => Ok(cursor),
        _ => Err("continuation cursor missing".into()),
    }
}

fn batch_identity(events: &[QueryEvent]) -> Result<(u64, [u8; 32]), Box<dyn Error>> {
    events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some((batch.sequence(), batch.digest())),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or_else(|| "result batch missing".into())
}

fn bodies(events: &[QueryEvent]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .filter_map(|record| record.body_text())
        .collect()
}
