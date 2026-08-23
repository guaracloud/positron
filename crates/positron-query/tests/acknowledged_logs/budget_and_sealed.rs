use std::error::Error;
use std::sync::Arc;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{
    QueryBudget, QueryBudgetDimension, QueryEvent, QueryFailureCode, QueryService, QueryTerminal,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use positron_kernel::{ResourceDimension, WorkClass};

use super::support::{
    CancellingStageWorkMeter, KernelFixture, StageCountingWorkMeter, StepClock, TemporaryRoots,
    TestClock, TestWorkMeter,
};

#[path = "budget_and_sealed/runtime_boundaries.rs"]
mod runtime_boundaries;

#[test]
fn default_cpu_budget_completes_one_normal_fitting_record() -> Result<(), Box<dyn Error>> {
    let (_roots, paths) = bootstrap_paths("default-fitting-cpu")?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query secret missing")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let fixture = KernelFixture::new_with_identity(
        instance.default_tenant_id(),
        "default-fitting-cpu-kernel",
        &instance.governance_object_for_test()?,
    )?;
    fixture.append_log("normal", 20, 1)?;
    let meter = StageCountingWorkMeter::shared();
    let service = QueryService::with_runtime(
        fixture.authority.governor(),
        fixture.ledger()?,
        1,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let budget = QueryBudget::new(1_048_576, 1, 1, 64, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 1",
        budget,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert_eq!(meter.calls(positron_query::QueryWorkStage::Parse), 1);
    assert_eq!(meter.calls(positron_query::QueryWorkStage::ScanDecode), 3);
    assert_eq!(meter.calls(positron_query::QueryWorkStage::Operators), 0);
    assert_eq!(meter.calls(positron_query::QueryWorkStage::Output), 2);
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 1
                && stats.cpu_work_units() <= budget.cpu_work_units()
    ));
    Ok(())
}

#[test]
fn finite_budget_exhaustion_is_one_typed_incomplete_terminal() -> Result<(), Box<dyn Error>> {
    let (roots, paths) = bootstrap_paths("budget")?;
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query secret missing")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let fixture = KernelFixture::new_with_identity(
        instance.default_tenant_id(),
        "budget-kernel",
        &instance.governance_object_for_test()?,
    )?;
    fixture.append_log("larger-than-the-scan-budget", 20, 1)?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 100);
    let planned = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(planned)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::BudgetExhausted
                && failure.stats().limiting_budget()
                    == Some(QueryBudgetDimension::ScannedBytes)
                && !failure.stats().reduced_pruning()
    ));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, QueryEvent::Terminal(_)))
            .count(),
        1
    );
    drop((roots, instance));
    Ok(())
}

#[test]
fn decoded_budget_never_reports_a_partial_store_block_as_decoded() -> Result<(), Box<dyn Error>> {
    use positron_domain::value::CandidateAttributeValue;

    let (_roots, paths) = bootstrap_paths("atomic-decoded-budget")?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query secret missing")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let fixture = KernelFixture::new_with_identity(
        instance.default_tenant_id(),
        "atomic-decoded-kernel",
        &instance.governance_object_for_test()?,
    )?;
    fixture.append_logs(
        vec![
            (
                Some(20),
                Some(CandidateAttributeValue::string("one".to_owned())),
            ),
            (
                Some(21),
                Some(CandidateAttributeValue::string("two".to_owned())),
            ),
        ],
        1,
    )?;
    let service = QueryService::with_runtime(
        fixture.authority.governor(),
        fixture.ledger()?,
        16,
        TestClock::shared(100),
        std::sync::Arc::new(super::support::ConstantWorkMeter(1)),
    );
    let query = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 64, 1_048_576, 60)?.with_cpu_work_units(1_024)?,
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
                && incomplete.stats().decoded_records() == 1
                && incomplete.stats().limiting_budget()
                    == Some(QueryBudgetDimension::DecodedRecords)
    ));

    let observed_cpu = events
        .last()
        .and_then(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)) => {
                Some(incomplete.stats().cpu_work_units())
            },
            QueryEvent::Header(_)
            | QueryEvent::Batch(_)
            | QueryEvent::Terminal(QueryTerminal::Complete(_))
            | QueryEvent::Terminal(QueryTerminal::Continued(_)) => None,
        })
        .ok_or("atomic preflight terminal omitted its work statistics")?;
    assert!(
        observed_cpu > 2,
        "validate-only traversal must add work beyond parsing"
    );
    let preflight_exhaustion = QueryBudget::new(1_048_576, 1, 1, 64, 1_048_576, 60)?
        .with_cpu_work_units(
            observed_cpu
                .checked_sub(2)
                .ok_or("atomic preflight did not account parser and scan work")?,
        )?;
    let exhausted = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 1",
        preflight_exhaustion,
    )?;
    let exhausted_events = service.execute(exhausted)?.collect::<Vec<_>>();
    assert!(matches!(
        exhausted_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().decoded_records() == 0
                && incomplete.stats().scanned_bytes() == 0
                && incomplete.stats().cpu_work_units() > preflight_exhaustion.cpu_work_units()
                && incomplete.stats().limiting_budget()
                    == Some(QueryBudgetDimension::CpuWorkUnits)
    ));

    let meter = CancellingStageWorkMeter::shared(positron_query::QueryWorkStage::ScanDecode);
    let cancelling_service = QueryService::with_runtime(
        fixture.authority.governor(),
        fixture.ledger()?,
        16,
        TestClock::shared(2_000_000_000),
        std::sync::Arc::clone(&meter) as std::sync::Arc<dyn positron_query::QueryWorkMeter>,
    );
    let cancelling = cancelling_service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 64, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    meter.bind(cancelling.cancellation())?;
    let cancelled_events = cancelling_service
        .execute(cancelling)
        .expect("mid-preflight cancellation must remain a framed query result")
        .collect::<Vec<_>>();
    assert!(matches!(
        cancelled_events.first(),
        Some(QueryEvent::Header(_))
    ));
    assert!(matches!(
        cancelled_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
                && incomplete.stats().decoded_records() == 0
                && incomplete.stats().scanned_bytes() == 0
    ));
    Ok(())
}

#[test]
fn wall_and_cpu_budgets_are_runtime_enforced_and_reserved_as_query_work()
-> Result<(), Box<dyn Error>> {
    let (_roots, paths) = bootstrap_paths("runtime-budget")?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query secret missing")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let fixture = KernelFixture::new_with_identity(
        instance.default_tenant_id(),
        "runtime-budget-kernel",
        &instance.governance_object_for_test()?,
    )?;
    fixture.append_log("bounded", 20, 1)?;
    let cpu_budget =
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(1)?;
    let clock = TestClock::shared(100);
    let service = QueryService::with_runtime(
        fixture.authority.governor(),
        fixture.ledger()?,
        16,
        clock,
        std::sync::Arc::new(TestWorkMeter),
    );
    let before = fixture.authority.governor().inspect()?;
    let planned = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 1",
        cpu_budget,
    )?;
    let admitted = fixture.authority.governor().inspect()?;
    assert_eq!(admitted.outstanding_for(WorkClass::InteractiveQueryTail), 1);
    assert_eq!(
        admitted.usage(ResourceDimension::CpuWorkUnits),
        before.usage(ResourceDimension::CpuWorkUnits) + 1
    );
    let events = service.execute(planned)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().cpu_work_units() == 2
                && incomplete.stats().limiting_budget()
                    == Some(QueryBudgetDimension::CpuWorkUnits)
    ));

    let wall_service = super::support::zero_work_clock_service(
        fixture.authority.governor(),
        fixture.ledger()?,
        16,
        StepClock::shared(200),
    );
    let planned = wall_service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 4)?,
    )?;
    let events = wall_service.execute(planned)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().wall_seconds() == 4
                && incomplete.stats().limiting_budget()
                    == Some(QueryBudgetDimension::WallSeconds)
    ));
    Ok(())
}

#[test]
fn resume_enforces_the_original_cumulative_cpu_and_wall_budget() -> Result<(), Box<dyn Error>> {
    let (_roots, paths) = bootstrap_paths("cumulative-budget")?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query secret missing")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let fixture = KernelFixture::new_with_identity(
        instance.default_tenant_id(),
        "cumulative-budget-kernel",
        &instance.governance_object_for_test()?,
    )?;
    fixture.append_log("one", 20, 1)?;
    fixture.append_log("two", 21, 2)?;
    let clock = TestClock::shared(100);
    let service = super::support::stage_work_clock_service(
        fixture.authority.governor(),
        fixture.ledger()?,
        1,
        clock.clone(),
    );
    let planned = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 10)?.with_cpu_work_units(4)?,
    )?;
    let first = service.execute_page(planned)?.collect::<Vec<_>>();
    let cursor = match first.last() {
        Some(QueryEvent::Terminal(QueryTerminal::Continued(cursor))) => cursor,
        _ => return Err("continuation missing".into()),
    };
    clock.set(102);
    let resumed = service.resume(context, cursor)?.collect::<Vec<_>>();
    assert!(matches!(
        resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 1
                && incomplete.stats().cpu_work_units() == 5
                && incomplete.stats().wall_seconds() == 2
                && incomplete.stats().last_sequence() == Some(0)
                && incomplete.stats().result_digest() != [0; 32]
    ));
    clock.set(99);
    assert_eq!(
        service
            .resume(context, cursor)
            .expect_err("resume clock regression")
            .code(),
        QueryFailureCode::Internal
    );
    Ok(())
}

#[test]
fn resume_uses_the_remaining_decoded_record_budget_before_scanning() -> Result<(), Box<dyn Error>> {
    let (_roots, paths) = bootstrap_paths("cumulative-decoded-budget")?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query secret missing")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let fixture = KernelFixture::new_with_identity(
        instance.default_tenant_id(),
        "cumulative-decoded-kernel",
        &instance.governance_object_for_test()?,
    )?;
    fixture.append_log("one", 20, 1)?;
    fixture.append_log("two", 21, 2)?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 1);
    let planned = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 2",
        QueryBudget::new(1_048_576, 2, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let first = service.execute_page(planned)?.collect::<Vec<_>>();
    let cursor = match first.last() {
        Some(QueryEvent::Terminal(QueryTerminal::Continued(cursor))) => cursor,
        _ => return Err("continuation missing".into()),
    };
    let resumed = service.resume(context, cursor)?.collect::<Vec<_>>();
    assert!(
        resumed
            .iter()
            .all(|event| !matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().limiting_budget()
                    == Some(QueryBudgetDimension::DecodedRecords)
                && incomplete.stats().decoded_records() == 2
    ));
    Ok(())
}

#[test]
fn sealed_and_successor_active_logs_share_one_ordered_query_result() -> Result<(), Box<dyn Error>> {
    let (_roots, paths) = bootstrap_paths("sealed")?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query secret missing")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let mut fixture = KernelFixture::new_with_identity(
        instance.default_tenant_id(),
        "sealed-kernel",
        &instance.governance_object_for_test()?,
    )?;
    fixture.append_log("sealed", 20, 1)?;
    fixture.seal_and_reopen()?;
    fixture.append_log("active", 21, 2)?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 100);
    let query = service.plan_sql(
        context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let first = service
        .execute(query)?
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(
                batch
                    .records()
                    .iter()
                    .filter_map(|record| record.body_text())
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            ),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(first, ["sealed", "active"]);

    fixture.seal_and_reopen()?;
    let restarted =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 100);
    let query = restarted.plan_sql(
        context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let after_restart = restarted
        .execute(query)?
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(
                batch
                    .records()
                    .iter()
                    .filter_map(|record| record.body_text())
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            ),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(after_restart, first);
    Ok(())
}

#[test]
fn full_text_search_keeps_active_and_sealed_results_equivalent() -> Result<(), Box<dyn Error>> {
    let (_roots, paths) = bootstrap_paths("sealed-search")?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query secret missing")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let mut fixture = KernelFixture::new_with_identity(
        instance.default_tenant_id(),
        "sealed-search-kernel",
        &instance.governance_object_for_test()?,
    )?;
    fixture.append_log("sealed timeout", 20, 1)?;
    fixture.seal_and_reopen()?;
    fixture.append_log("active timeout", 21, 2)?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let source = "pipeline:v1 logs | range query_time -100 100 | search body contains \"timeout\" | limit 16";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?;
    let first = service
        .execute(service.plan_pipeline(context, source, budget)?)?
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(
                batch
                    .records()
                    .iter()
                    .filter_map(|record| record.body_text())
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            ),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(first, ["sealed timeout", "active timeout"]);

    fixture.seal_and_reopen()?;
    let restarted =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let after_restart = restarted
        .execute(restarted.plan_pipeline(context, source, budget)?)?
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(
                batch
                    .records()
                    .iter()
                    .filter_map(|record| record.body_text())
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            ),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(after_restart, first);
    Ok(())
}

fn bootstrap_paths(label: &str) -> Result<(TemporaryRoots, BootstrapPaths), Box<dyn Error>> {
    let roots = TemporaryRoots::new(label)?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        positron_kernel::MountQualification::LocalHost,
    )?;
    Ok((roots, paths))
}
