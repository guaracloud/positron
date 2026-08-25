use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{QueryBudget, QueryEvent, QueryService};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::super::support::{KernelFixture, TemporaryRoots, TestClock};

#[test]
fn event_time_cursor_preserves_its_temporal_axis_across_resume() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixtureForAxis::new("event_time")?;
    let first = fixture
        .service
        .execute_page(fixture.plan)?
        .collect::<Vec<_>>();
    let resumed = fixture
        .service
        .resume(fixture.context, super::continuation(&first)?)?
        .collect::<Vec<_>>();
    let header = match resumed.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("resumed result header missing".into()),
    };
    assert_eq!(
        header.ordering().columns(),
        ["event_time", "commit_position", "record_ordinal"]
    );
    assert_eq!(super::bodies(&resumed), ["second"]);
    Ok(())
}

#[test]
fn ingest_time_cursor_preserves_its_temporal_axis_across_resume() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixtureForAxis::new("ingest_time")?;
    let first = fixture
        .service
        .execute_page(fixture.plan)?
        .collect::<Vec<_>>();
    let resumed = fixture
        .service
        .resume(fixture.context, super::continuation(&first)?)?
        .collect::<Vec<_>>();
    let header = match resumed.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("resumed result header missing".into()),
    };
    assert_eq!(
        header.ordering().columns(),
        ["ingest_time", "commit_position", "record_ordinal"]
    );
    assert_eq!(super::bodies(&resumed), ["second"]);
    Ok(())
}

struct QueryFixtureForAxis {
    _roots: TemporaryRoots,
    context: positron_governance::AuthorizedContext,
    service: QueryService<'static, 'static, 'static>,
    plan: positron_query::PlannedQuery<'static>,
}

impl QueryFixtureForAxis {
    fn new(axis: &str) -> Result<Self, Box<dyn Error>> {
        let roots = TemporaryRoots::new("event-time-cursor")?;
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
        let kernel = Box::leak(Box::new(KernelFixture::new_with_identity(
            instance.default_tenant_id(),
            "event-time-cursor-kernel",
            &governance,
        )?));
        kernel.append_log("first", 20, 1)?;
        kernel.append_log("second", 21, 2)?;
        let service = super::super::support::zero_work_clock_service(
            kernel.authority.governor(),
            kernel.ledger()?,
            1,
            TestClock::shared(100),
        );
        let source = format!("logs | range {axis} -100 100 | limit 2");
        let plan = service.plan_pipeline(
            context,
            &source,
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
                .with_cpu_work_units(16)?,
        )?;
        Ok(Self {
            _roots: roots,
            context,
            service,
            plan,
        })
    }
}
