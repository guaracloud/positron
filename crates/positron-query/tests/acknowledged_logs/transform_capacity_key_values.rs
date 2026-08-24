use std::error::Error;

use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryTerminal};

use super::support::zero_work_service;
use super::terminal_and_bounds::QueryFixture;

#[test]
fn key_value_transforms_charge_candidate_and_canonical_capacity_at_exact_boundary()
-> Result<(), Box<dyn Error>> {
    const ENTRIES: u64 = 1_024;
    const PARSER_ENTRY_BYTES: u64 = 96;
    const KEY_CAPACITY_BYTES: u64 = 1;
    const KEY_VALUE_SLOT_BYTES: u64 = 96;
    const BASE_TRANSFORM_WORKING_BYTES: u64 = 381;

    for (name, body, transform) in [
        (
            "query-json-object-simultaneous-capacity",
            format!("{{{}}}", vec![r#""k":0"#; 1_024].join(",")),
            "json",
        ),
        (
            "query-logfmt-object-simultaneous-capacity",
            vec!["k=0"; 1_024].join(" "),
            "logfmt",
        ),
    ] {
        let fixture = QueryFixture::new(name)?;
        fixture.kernel.append_log(&body, 20, 1)?;
        let service = zero_work_service(
            fixture.kernel.authority.governor(),
            fixture.kernel.ledger()?,
            16,
        );
        let budget = |memory| {
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, memory, 60)
                .and_then(|budget| budget.with_cpu_work_units(1_024))
        };
        let baseline = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | limit 1",
            budget(4_194_304)?,
        )?;
        let baseline_peak = service
            .execute(baseline)?
            .collect::<Vec<_>>()
            .iter()
            .find_map(|event| match event {
                QueryEvent::Terminal(QueryTerminal::Complete(stats)) => {
                    Some(stats.memory_peak_bytes())
                },
                QueryEvent::Header(_) | QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
            })
            .ok_or("key/value baseline did not complete")?;
        let candidate_bytes = ENTRIES
            .checked_mul(PARSER_ENTRY_BYTES + KEY_CAPACITY_BYTES)
            .ok_or("candidate capacity overflowed")?;
        let output_bytes = ENTRIES
            .checked_mul(KEY_VALUE_SLOT_BYTES)
            .ok_or("validated capacity overflowed")?;
        let source =
            format!("pipeline:v1 logs | range query_time -100 100 | {transform} | limit 1");
        // The existing JSON transform/page working set is 381 bytes. Longer
        // operator names retain their extra source bytes in the plan.
        let fixed_working_bytes = BASE_TRANSFORM_WORKING_BYTES
            .checked_add(u64::try_from(
                transform
                    .len()
                    .checked_sub("json".len())
                    .ok_or("transform name shorter than JSON")?,
            )?)
            .ok_or("fixed working capacity overflowed")?;
        let expected_peak = baseline_peak
            .checked_add(candidate_bytes)
            .and_then(|bytes| bytes.checked_add(output_bytes))
            .and_then(|bytes| bytes.checked_add(u64::try_from(body.len()).ok()?))
            .and_then(|bytes| bytes.checked_add(fixed_working_bytes))
            .ok_or("key/value peak overflowed")?;
        let minimum_peak = baseline_peak
            .checked_add(candidate_bytes)
            .and_then(|bytes| bytes.checked_add(output_bytes))
            .and_then(|bytes| bytes.checked_add(u64::try_from(body.len()).ok()?))
            .ok_or("key/value capacity floor overflowed")?;
        assert!(
            expected_peak >= minimum_peak,
            "{name} peak did not include candidate and canonical capacities"
        );
        let under = service.plan_pipeline(fixture.context, &source, budget(expected_peak - 1)?)?;
        let under_events = service.execute(under)?.collect::<Vec<_>>();
        assert!(matches!(
            under_events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::BudgetExhausted
                    && incomplete.stats().limiting_budget()
                        == Some(positron_query::QueryBudgetDimension::MemoryBytes)
        ));
        let exact = service.plan_pipeline(fixture.context, &source, budget(expected_peak)?)?;
        let exact_events = service.execute(exact)?.collect::<Vec<_>>();
        assert!(matches!(
            exact_events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
        ));
    }
    Ok(())
}
