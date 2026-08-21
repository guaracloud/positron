use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{QueryBudget, QueryEvent, QueryService};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::super::support::{KernelFixture, TemporaryRoots, TestClock};

#[test]
fn event_time_cursor_preserves_its_temporal_axis_across_resume() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixtureForAxis::new()?;
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
        ["event_time", "commit_position"]
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
    fn new() -> Result<Self, Box<dyn Error>> {
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
        let kernel = Box::leak(Box::new(KernelFixture::new(
            instance.default_tenant_id(),
            "event-time-cursor-kernel",
        )?));
        kernel.append_log("first", 20, 1)?;
        kernel.append_log("second", 21, 2)?;
        let service = QueryService::with_clock(
            kernel.authority.governor(),
            kernel.ledger()?,
            1,
            TestClock::shared(100),
        );
        let plan = service.plan_pipeline(
            context,
            "logs | range event_time -100 100 | limit 2",
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
