use std::error::Error;

use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryTerminal};
use positron_signals::{LogRetentionPolicy, LogScan, LogStore, ScanLimit};

use super::terminal_and_bounds::QueryFixture;

#[test]
fn public_queries_are_equivalent_before_after_and_after_restart() -> Result<(), Box<dyn Error>> {
    let mut fixture = QueryFixture::new_compaction("compaction-public-query-equivalence")?;
    fixture.kernel.append_log("error-42", 20, 1)?;
    fixture.kernel.seal_and_reopen()?;
    fixture.kernel.append_log("error-43", 21, 2)?;
    fixture.kernel.seal_and_reopen()?;
    fixture.kernel.append_log("info-7", 22, 3)?;

    let scalar =
        r#"pipeline:v1 logs | range query_time -100 100 | filter body == "error-42" | limit 16"#;
    let contains =
        r#"pipeline:v1 logs | range query_time -100 100 | search body contains "error" | limit 16"#;
    let regex = r#"pipeline:v1 logs | range query_time -100 100 | search body =~ "^error-[0-9]+$" | limit 16"#;
    let malformed =
        r#"pipeline:v1 logs | range query_time -100 100 | search body =~ "[" | limit 16"#;

    let before_scalar =
        query(&fixture, scalar).map_err(|error| format!("before scalar: {error}"))?;
    let before_contains =
        query(&fixture, contains).map_err(|error| format!("before contains: {error}"))?;
    let before_regex = query(&fixture, regex).map_err(|error| format!("before regex: {error}"))?;
    let malformed_before = malformed_code(&fixture, malformed)
        .map_err(|error| format!("before malformed: {error}"))?;

    let store = LogStore::new();
    let ledger = fixture.kernel.ledger()?;
    let tenant = ledger.scope().tenant_id();
    let snapshot = ledger.snapshot()?;
    let before_scan = store
        .scan(
            fixture.kernel.authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(16)?),
        )
        .map_err(|error| format!("before scan: {error}"))?;
    let policy = LogRetentionPolicy::from_catalog(&fixture.kernel.catalog_for_test().pin()?)
        .map_err(|error| format!("policy: {error}"))?;
    let bucket = policy
        .bucket(
            tenant,
            before_scan
                .records()
                .first()
                .ok_or("compaction fixture has no records")?
                .ingest_time(),
        )
        .map_err(|error| format!("bucket: {error}"))?;
    let outcome = store
        .compact(ledger, tenant, policy, bucket)
        .map_err(|error| format!("compact: {error}"))?;
    assert_eq!(outcome.input_segments(), 2);
    assert_eq!(outcome.output_segments(), 1);

    let after_scalar = query(&fixture, scalar).map_err(|error| format!("after scalar: {error}"))?;
    let after_contains =
        query(&fixture, contains).map_err(|error| format!("after contains: {error}"))?;
    let after_regex = query(&fixture, regex).map_err(|error| format!("after regex: {error}"))?;
    let malformed_after =
        malformed_code(&fixture, malformed).map_err(|error| format!("after malformed: {error}"))?;
    assert_eq!(after_scalar, before_scalar);
    assert_eq!(after_contains, before_contains);
    assert_eq!(after_regex, before_regex);
    assert_eq!(malformed_after, malformed_before);

    drop(snapshot);
    drop(before_scan);
    fixture.kernel.reopen_ledger()?;
    assert_eq!(
        query(&fixture, scalar).map_err(|error| format!("restart scalar: {error}"))?,
        before_scalar
    );
    assert_eq!(
        query(&fixture, contains).map_err(|error| format!("restart contains: {error}"))?,
        before_contains
    );
    assert_eq!(
        query(&fixture, regex).map_err(|error| format!("restart regex: {error}"))?,
        before_regex
    );
    Ok(())
}

fn query(fixture: &QueryFixture, source: &str) -> Result<(Vec<String>, bool), Box<dyn Error>> {
    let service = fixture.service(16)?;
    let plan = service.plan_pipeline(fixture.context, source, query_budget())?;
    let events = service.execute(plan)?.collect::<Vec<_>>();
    let mut bodies = Vec::new();
    for event in &events {
        if let QueryEvent::Batch(batch) = event {
            for record in batch.records() {
                if let Some(body) = record.body_text() {
                    bodies.push(body.to_owned());
                }
            }
        }
    }
    let reduced_pruning = events.iter().any(|event| {
        matches!(
            event,
            QueryEvent::Terminal(QueryTerminal::Complete(stats)) if stats.reduced_pruning()
        )
    });
    Ok((bodies, reduced_pruning))
}

fn malformed_code(
    fixture: &QueryFixture,
    source: &str,
) -> Result<QueryFailureCode, Box<dyn Error>> {
    let service = fixture.service(16)?;
    match service.plan_pipeline(fixture.context, source, query_budget()) {
        Ok(_) => Err("malformed query unexpectedly planned".into()),
        Err(failure) => Ok(failure.code()),
    }
}

fn query_budget() -> QueryBudget {
    QueryBudget::new(1_048_576, 64, 64, 1_048_576, 1_048_576, 60)
        .expect("compaction equivalence budget is valid")
}
