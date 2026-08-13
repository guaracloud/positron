use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{QueryBudget, QueryEvent, QueryService, QueryTerminal};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::support::{KernelFixture, TemporaryRoots};

#[test]
fn pipeline_and_sql_share_one_plan_and_read_acknowledged_active_logs() -> Result<(), Box<dyn Error>>
{
    let roots = TemporaryRoots::new("parity")?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        positron_kernel::MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(
            claim
                .query_secret()
                .ok_or("fresh bootstrap omitted the Query credential")?,
        )?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let fixture = KernelFixture::new(instance.default_tenant_id(), "parity-kernel")?;
    fixture.append_log("acknowledged", 20, 1)?;

    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 100);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?;
    let pipeline = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 16",
        budget,
    )?;
    let sql = service.plan_sql(
        context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 16",
        budget,
    )?;
    assert_eq!(pipeline.logical_plan(), sql.logical_plan());
    drop(sql);

    let events = service.execute(pipeline)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    let bodies = events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["acknowledged"]);
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
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

#[test]
fn pipeline_and_sql_require_the_same_explicit_bounded_temporal_range() -> Result<(), Box<dyn Error>>
{
    let roots = TemporaryRoots::new("temporal-parity")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "temporal-parity-kernel")?;
    fixture.append_log("inclusive-start", 10, 1)?;
    fixture.append_log("inside", 20, 2)?;
    fixture.append_log("exclusive-end", 30, 3)?;
    fixture.append_log("outside", 40, 4)?;
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 100);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?;
    let pipeline =
        service.plan_pipeline(context, "logs | range event_time 10 30 | limit 16", budget)?;
    let sql = service.plan_sql(
        context,
        "SELECT body FROM logs WHERE event_time >= 10 AND event_time < 30 ORDER BY event_time, commit_position LIMIT 16",
        budget,
    )?;
    assert_eq!(pipeline.logical_plan(), sql.logical_plan());
    drop(sql);
    let events = service.execute(pipeline)?.collect::<Vec<_>>();
    let bodies = events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["inclusive-start", "inside"]);

    assert_eq!(
        service
            .plan_pipeline(context, "logs | limit 16", budget)
            .err()
            .ok_or("missing time range was accepted")?
            .code(),
        positron_query::QueryFailureCode::UnsupportedQuery
    );
    for source in [
        "logs | range query_time 30 10 | limit 16",
        "logs | range query_time 10 10 | limit 16",
    ] {
        assert_eq!(
            service
                .plan_pipeline(context, source, budget)
                .err()
                .ok_or("invalid time range was accepted")?
                .code(),
            positron_query::QueryFailureCode::InvalidBudget
        );
    }
    let short_budget = budget.with_maximum_time_range_nanoseconds(19)?;
    assert_eq!(
        service
            .plan_pipeline(
                context,
                "logs | range query_time 10 30 | limit 16",
                short_budget,
            )
            .err()
            .ok_or("over-budget temporal range was accepted")?
            .code(),
        positron_query::QueryFailureCode::InvalidBudget
    );
    Ok(())
}
