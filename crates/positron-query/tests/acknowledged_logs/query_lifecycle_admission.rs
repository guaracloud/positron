use std::error::Error;

use positron_kernel::LedgerFailureCode;
use positron_query::{QueryBudget, QueryFailureCode};

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
