use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryService, QueryTerminal};
use positron_runtime::{InitializationPlan, InstanceBootstrap};

use super::super::support::{
    ConstantWorkMeter, FailingClock, FailingStageWorkMeter, FailingWorkMeter, KernelFixture,
    SequenceClock, TestClock, TestWorkMeter,
};
use super::super::terminal_and_bounds::QueryFixture;

#[test]
fn runtime_meter_failures_and_clock_regression_fail_closed() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        positron_query::QueryClockFailure.to_string(),
        "query clock unavailable"
    );
    assert_eq!(
        positron_query::QueryWorkFailure.to_string(),
        "query work meter unavailable"
    );
    let (_roots, paths) = super::bootstrap_paths("runtime-failure")?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query secret missing")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let fixture = KernelFixture::new(instance.default_tenant_id(), "runtime-failure-kernel")?;
    let service = QueryService::with_runtime(
        fixture.authority.governor(),
        fixture.ledger()?,
        1,
        std::sync::Arc::new(FailingClock),
        std::sync::Arc::new(TestWorkMeter),
    );
    assert_eq!(
        failure_code(service.plan_pipeline(
            context,
            "logs | range query_time -100 100 | limit 1",
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
        ))?,
        QueryFailureCode::Internal
    );
    let service = QueryService::with_runtime(
        fixture.authority.governor(),
        fixture.ledger()?,
        1,
        TestClock::shared(100),
        std::sync::Arc::new(FailingWorkMeter),
    );
    assert_eq!(
        failure_code(service.plan_pipeline(
            context,
            "logs | range query_time -100 100 | limit 1",
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
        ))?,
        QueryFailureCode::Internal
    );
    Ok(())
}

#[test]
fn runtime_boundaries_fail_closed_before_or_between_query_stages() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("runtime-boundaries")?;
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        SequenceClock::shared([100, 104]),
        std::sync::Arc::new(TestWorkMeter),
    );
    assert_eq!(
        failure_code(service.plan_pipeline(
            fixture.context,
            "logs | range query_time -100 100 | limit 1",
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 4)?,
        ))?,
        QueryFailureCode::BudgetExhausted
    );

    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
        std::sync::Arc::new(ConstantWorkMeter(2)),
    );
    assert_eq!(
        failure_code(
            service.plan_pipeline(
                fixture.context,
                "logs | range query_time -100 100 | limit 1",
                QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
                    .with_cpu_work_units(1)?,
            )
        )?,
        QueryFailureCode::BudgetExhausted
    );

    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        SequenceClock::shared([100, 100, 99]),
    );
    let planned = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    assert_eq!(
        service
            .execute(planned)
            .expect_err("execution clock regression")
            .code(),
        QueryFailureCode::Internal
    );

    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        SequenceClock::shared([100, 100, 160]),
    );
    let planned = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    assert_eq!(
        service
            .execute(planned)
            .expect_err("execution starts at the wall bound")
            .code(),
        QueryFailureCode::BudgetExhausted
    );
    Ok(())
}

#[test]
fn runtime_observations_cover_scan_output_and_pre_delivery_boundaries() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("runtime-stages")?;
    fixture.kernel.append_log("long", 20, 1)?;
    let budget = || QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60);
    for stage in [
        positron_query::QueryWorkStage::ScanDecode,
        positron_query::QueryWorkStage::Output,
    ] {
        let service = QueryService::with_runtime(
            fixture.kernel.authority.governor(),
            fixture.kernel.ledger()?,
            1,
            TestClock::shared(100),
            std::sync::Arc::new(FailingStageWorkMeter(stage)),
        );
        let planned = service.plan_pipeline(
            fixture.context,
            "logs | range query_time -100 100 | limit 1",
            budget()?,
        )?;
        let events = service.execute(planned)?.collect::<Vec<_>>();
        assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
        assert!(matches!(
            events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::Internal
        ));
    }

    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
        std::sync::Arc::new(FailingStageWorkMeter(
            positron_query::QueryWorkStage::Operators,
        )),
    );
    let planned = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | project query_time | limit 1",
        budget()?,
    )?;
    let events = service.execute(planned)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Internal
    ));

    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        SequenceClock::shared([100, 100, 100, 160]),
    );
    let planned = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget()?,
    )?;
    let events = service.execute(planned)?.collect::<Vec<_>>();
    assert!(matches!(
        events.as_slice(),
        [QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete))]
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().wall_seconds() == 60
    ));

    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        SequenceClock::shared([100, 100, 100, 100, 100, 100, 160]),
    );
    let planned = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget()?,
    )?;
    let events = service.execute(planned)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
                && incomplete.stats().result_digest() == [0; 32]
    ));

    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(200),
    );
    let planned = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1, 1_048_576, 60)?,
    )?;
    let events = service.execute(planned)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
                && incomplete.stats().result_digest() == [0; 32]
    ));
    Ok(())
}

fn failure_code<T>(
    result: Result<T, positron_query::QueryFailure>,
) -> Result<QueryFailureCode, Box<dyn Error>> {
    match result {
        Ok(_) => Err("query unexpectedly planned".into()),
        Err(failure) => Ok(failure.code()),
    }
}
