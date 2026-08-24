use std::error::Error;

use positron_kernel::{LedgerFailureCode, with_catalog_publication_hook_after};
use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryService, QueryTerminal};

use super::support::{LifecycleTransitionClock, publish_lifecycle_at_catalog_for_test};
use super::terminal_and_bounds::QueryFixture;

#[test]
fn planned_query_revalidates_durable_lifecycle_before_snapshot_lease_admission()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-lifecycle-admission")?;
    let service = fixture.service(1)?;
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 1_024, 1_024, 1_048_576, 1_048_576, 60)?
            .with_cpu_work_units(1_024)?,
    )?;

    fixture.kernel.publish_lifecycle_for_test(3, 0xd4)?;

    let failure = service
        .execute_page(query)
        .expect_err("stale query context must not admit a snapshot lease");
    assert_eq!(failure.code(), QueryFailureCode::Unauthorized);
    Ok(())
}

#[test]
fn snapshot_lease_admission_rejects_a_catalog_generation_changed_after_validation()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-catalog-generation-admission")?;
    let validated = fixture.kernel.ledger()?.current_catalog_snapshot()?;

    fixture.kernel.publish_lifecycle_for_test(3, 0xd5)?;

    let failure = fixture
        .kernel
        .ledger()?
        .create_snapshot_lease_at_catalog(100, 160, validated.identity())
        .expect_err("lease admission must reject a changed Catalog basis");
    assert_eq!(failure.code(), LedgerFailureCode::StaleGeneration);
    Ok(())
}

#[test]
fn resume_rejects_a_lifecycle_transition_at_marker_admission() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("resume-lifecycle-admission")?;
    fixture.kernel.append_log("first", 20, 1)?;
    fixture.kernel.append_log("second", 21, 2)?;
    let initial = fixture.service(1)?;
    let planned = initial.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let cursor = initial
        .execute_page(planned)?
        .collect::<Vec<_>>()
        .into_iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("initial query omitted its continuation cursor")?;
    let clock = LifecycleTransitionClock::shared(fixture.kernel.catalog_for_test(), 3, 0xd6);
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        clock,
    );

    let failure = service
        .resume(fixture.context, &cursor)
        .expect_err("resume must not admit a marker after lifecycle revocation");
    assert_eq!(failure.code(), QueryFailureCode::AuthorizationChanged);
    Ok(())
}

#[test]
fn resume_rejects_a_lifecycle_transition_during_marker_publication() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("resume-lifecycle-publication")?;
    fixture.kernel.append_log("first", 20, 1)?;
    fixture.kernel.append_log("second", 21, 2)?;
    let service = fixture.service(1)?;
    let planned = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let cursor = service
        .execute_page(planned)?
        .collect::<Vec<_>>()
        .into_iter()
        .find_map(|event| match event {
            QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => Some(cursor),
            QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("initial query omitted its continuation cursor")?;

    let failure = with_catalog_publication_hook_after(
        0,
        |catalog| {
            publish_lifecycle_at_catalog_for_test(catalog, 3, 0xd7).expect("lifecycle transition");
        },
        || service.resume(fixture.context, &cursor),
    )
    .expect_err("resume must fence a lifecycle transition at marker publication");
    assert_eq!(failure.code(), QueryFailureCode::AuthorizationChanged);
    Ok(())
}
