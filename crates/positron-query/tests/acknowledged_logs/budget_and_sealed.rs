use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryService, QueryTerminal};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use positron_kernel::{ResourceDimension, WorkClass};

use super::support::{KernelFixture, StepClock, TemporaryRoots, TestClock, TestWorkMeter};

#[path = "budget_and_sealed/runtime_boundaries.rs"]
mod runtime_boundaries;

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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "budget-kernel")?;
    fixture.append_log("larger-than-the-scan-budget", 20, 1)?;
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 100);
    let planned = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1, 16, 16, 1_048_576, 4, 60)?,
    )?;
    let events = service.execute(planned)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::BudgetExhausted
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "runtime-budget-kernel")?;
    fixture.append_log("bounded", 20, 1)?;
    let cpu_budget =
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?.with_cpu_work_units(2)?;
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
        before.usage(ResourceDimension::CpuWorkUnits) + 2
    );
    let events = service.execute(planned)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().cpu_work_units() == 3
    ));

    let wall_service = QueryService::with_clock(
        fixture.authority.governor(),
        fixture.ledger()?,
        16,
        StepClock::shared(200),
    );
    let planned = wall_service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 4)?,
    )?;
    let events = wall_service.execute(planned)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().wall_seconds() == 4
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "cumulative-budget-kernel")?;
    fixture.append_log("one", 20, 1)?;
    fixture.append_log("two", 21, 2)?;
    let clock = TestClock::shared(100);
    let service = QueryService::with_clock(
        fixture.authority.governor(),
        fixture.ledger()?,
        1,
        clock.clone(),
    );
    let planned = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 10)?.with_cpu_work_units(3)?,
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
                && incomplete.stats().cpu_work_units() == 4
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
    let mut fixture = KernelFixture::new(instance.default_tenant_id(), "sealed-kernel")?;
    fixture.append_log("sealed", 20, 1)?;
    fixture.seal_and_reopen()?;
    fixture.append_log("active", 21, 2)?;
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 100);
    let query = service.plan_sql(
        context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
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
    let restarted = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 100);
    let query = restarted.plan_sql(
        context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
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

fn bootstrap_paths(label: &str) -> Result<(TemporaryRoots, BootstrapPaths), Box<dyn Error>> {
    let roots = TemporaryRoots::new(label)?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        positron_kernel::MountQualification::LocalHost,
    )?;
    Ok((roots, paths))
}
