use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{CursorKey, QueryBudget, QueryEvent, QueryService, QueryTerminal};
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

    let service = QueryService::new(
        fixture.authority.governor(),
        fixture.ledger()?,
        CursorKey::new(1, [0x91; 32])?,
        100,
    );
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?;
    let pipeline = service.plan_pipeline(context, "logs | limit 16", budget)?;
    let sql = service.plan_sql(
        context,
        "SELECT body FROM logs ORDER BY query_time, commit_position LIMIT 16",
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
