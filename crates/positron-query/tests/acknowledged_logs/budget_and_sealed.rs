use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{
    CursorKey, QueryBudget, QueryEvent, QueryFailureCode, QueryService, QueryTerminal,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::support::{KernelFixture, TemporaryRoots};

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
    let service = QueryService::new(
        fixture.authority.governor(),
        fixture.ledger()?,
        CursorKey::new(1, [0x81; 32])?,
        100,
    );
    let planned = service.plan_pipeline(
        context,
        "logs | limit 1",
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
    let service = QueryService::new(
        fixture.authority.governor(),
        fixture.ledger()?,
        CursorKey::new(1, [0x82; 32])?,
        100,
    );
    let query = service.plan_sql(
        context,
        "SELECT body FROM logs ORDER BY query_time, commit_position LIMIT 2",
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
    let restarted = QueryService::new(
        fixture.authority.governor(),
        fixture.ledger()?,
        CursorKey::new(1, [0x82; 32])?,
        100,
    );
    let query = restarted.plan_sql(
        context,
        "SELECT body FROM logs LIMIT 2",
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
