use std::error::Error;

use positron_domain::value::AttributeNamespace;
use positron_policy::NativeLogAttribute;
use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryTerminal};
use positron_signals::{LogRetentionPolicy, LogScan, LogStore, ScanLimit, SchemaPath};

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

#[test]
fn schema_pruning_and_representations_survive_compaction_and_restart() -> Result<(), Box<dyn Error>>
{
    let mut fixture = QueryFixture::new_compaction("compaction-schema-query-equivalence")?;
    let path = SchemaPath::root(AttributeNamespace::Record, "priority".to_owned())?;
    let mut schema = fixture
        .kernel
        .append_indexed_attribute_logs(
            vec![(
                Some(20),
                vec![
                    NativeLogAttribute::new(
                        AttributeNamespace::Record,
                        "priority".to_owned(),
                        vec![positron_domain::value::CandidateAttributeValue::signed_integer(7)],
                    ),
                    NativeLogAttribute::new(
                        AttributeNamespace::Record,
                        "filler-0".to_owned(),
                        vec![positron_domain::value::CandidateAttributeValue::string(
                            "generic".to_owned(),
                        )],
                    ),
                    NativeLogAttribute::new(
                        AttributeNamespace::Record,
                        "filler-1".to_owned(),
                        vec![positron_domain::value::CandidateAttributeValue::string(
                            "generic".to_owned(),
                        )],
                    ),
                    NativeLogAttribute::new(
                        AttributeNamespace::Record,
                        "filler-2".to_owned(),
                        vec![positron_domain::value::CandidateAttributeValue::string(
                            "generic".to_owned(),
                        )],
                    ),
                    NativeLogAttribute::new(
                        AttributeNamespace::Record,
                        "filler-3".to_owned(),
                        vec![positron_domain::value::CandidateAttributeValue::string(
                            "generic".to_owned(),
                        )],
                    ),
                    NativeLogAttribute::new(
                        AttributeNamespace::Record,
                        "filler-4".to_owned(),
                        vec![positron_domain::value::CandidateAttributeValue::string(
                            "generic".to_owned(),
                        )],
                    ),
                    NativeLogAttribute::new(
                        AttributeNamespace::Record,
                        "filler-5".to_owned(),
                        vec![positron_domain::value::CandidateAttributeValue::string(
                            "generic".to_owned(),
                        )],
                    ),
                    NativeLogAttribute::new(
                        AttributeNamespace::Record,
                        "filler-6".to_owned(),
                        vec![positron_domain::value::CandidateAttributeValue::string(
                            "generic".to_owned(),
                        )],
                    ),
                    NativeLogAttribute::new(
                        AttributeNamespace::Record,
                        "filler-7".to_owned(),
                        vec![positron_domain::value::CandidateAttributeValue::string(
                            "overflow".to_owned(),
                        )],
                    ),
                ],
            )],
            1,
            &path,
        )
        .map_err(|error| format!("initial indexed append: {error:?}"))?;
    let promoted = schema
        .catalog()
        .entry(&path)
        .ok_or("priority schema entry")?;
    assert!(promoted.promoted());
    assert!(schema.catalog().overflow_record_count() > 0);

    fixture
        .kernel
        .seal_and_reopen()
        .map_err(|error| format!("seal initial schema block: {error}"))?;
    let snapshot = fixture.kernel.ledger()?.snapshot()?;
    let first_block = snapshot.blocks().first().ok_or("schema block")?;
    let mut demotion = schema.stage_query_update()?;
    demotion.remove_query_evidence(&path)?;
    schema.commit_query_update(demotion)?;
    assert!(
        !schema
            .catalog()
            .entry(&path)
            .ok_or("demoted entry")?
            .promoted()
    );
    let mut promotion = schema.stage_query_update()?;
    promotion.record_query_use(&path)?;
    promotion.index_replayed_query_path(
        fixture.kernel.ledger()?.scope().tenant_id(),
        &snapshot,
        first_block,
        &path,
    )?;
    schema.commit_query_update(promotion)?;
    assert!(
        schema
            .catalog()
            .entry(&path)
            .ok_or("promoted entry")?
            .promoted()
    );
    drop(snapshot);

    fixture
        .kernel
        .append_attribute_logs_with_schema(
            &mut schema,
            vec![(
                Some(21),
                vec![NativeLogAttribute::new(
                    AttributeNamespace::Record,
                    "priority".to_owned(),
                    vec![positron_domain::value::CandidateAttributeValue::string(
                        "eight".to_owned(),
                    )],
                )],
            )],
            2,
        )
        .map_err(|error| format!("second indexed append: {error:?}"))?;
    assert!(
        schema
            .catalog()
            .entry(&path)
            .is_some_and(|entry| entry.variants().len() >= 2)
    );
    fixture
        .kernel
        .seal_and_reopen()
        .map_err(|error| format!("seal second schema block: {error}"))?;
    fixture
        .kernel
        .append_log("error-typed-42", 22, 3)
        .map_err(|error| format!("error body append: {error}"))?;
    fixture
        .kernel
        .seal_and_reopen()
        .map_err(|error| format!("seal error body block: {error}"))?;
    fixture
        .kernel
        .append_log("info-typed-7", 23, 4)
        .map_err(|error| format!("info body append: {error}"))?;

    let scalar = r#"pipeline:v1 logs | range query_time -100 100 | filter record["priority"] any == int(7) | limit 16"#;
    let promoted_scalar = r#"pipeline:v1 logs | range query_time -100 100 | filter record["priority"] any == string("eight") | limit 16"#;
    let absent = r#"pipeline:v1 logs | range query_time -100 100 | filter record["priority"] any == int(99) | limit 16"#;
    let contains = r#"pipeline:v1 logs | range query_time -100 100 | search body contains "error-typed" | limit 16"#;
    let regex = r#"pipeline:v1 logs | range query_time -100 100 | search body =~ "^error-typed-[0-9]+$" | limit 16"#;
    let before = [
        query_with_schema(&fixture, schema.catalog(), scalar)?,
        query_with_schema(&fixture, schema.catalog(), promoted_scalar)?,
        query_with_schema(&fixture, schema.catalog(), absent)?,
        query_with_schema(&fixture, schema.catalog(), contains)?,
        query_with_schema(&fixture, schema.catalog(), regex)?,
    ];
    assert_eq!(
        before[2].0, 0,
        "schema predicate must reject the absent value"
    );
    let schema_encoding = schema.catalog().encode_catalog_object()?;
    positron_signals::SchemaCatalog::decode_catalog_object(&schema_encoding)
        .map_err(|error| format!("schema catalog pre-compaction decode: {error:?}"))?;

    let store = LogStore::new();
    let ledger = fixture.kernel.ledger()?;
    let tenant = ledger.scope().tenant_id();
    let snapshot = ledger.snapshot()?;
    let scan = store.scan(
        fixture.kernel.authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(16)?),
    )?;
    let policy = LogRetentionPolicy::from_catalog(&fixture.kernel.catalog_for_test().pin()?)?;
    let bucket = policy.bucket(
        tenant,
        scan.records().first().ok_or("query records")?.ingest_time(),
    )?;
    let outcome = store.compact(ledger, tenant, policy, bucket)?;
    assert_eq!(outcome.input_segments(), 3);
    assert_eq!(outcome.output_segments(), 1);
    drop(scan);
    drop(snapshot);

    let after = [
        query_with_schema(&fixture, schema.catalog(), scalar)?,
        query_with_schema(&fixture, schema.catalog(), promoted_scalar)?,
        query_with_schema(&fixture, schema.catalog(), absent)?,
        query_with_schema(&fixture, schema.catalog(), contains)?,
        query_with_schema(&fixture, schema.catalog(), regex)?,
    ];
    assert_eq!(after.map(|result| result.0), before.map(|result| result.0));
    assert!(
        after[2].1,
        "compacted stale schema index must use generic fallback"
    );
    assert_eq!(schema.catalog().encode_catalog_object()?, schema_encoding);

    drop(schema);
    fixture.kernel.reopen_ledger()?;
    let reopened_schema = positron_signals::SchemaCatalog::decode_catalog_object(&schema_encoding)
        .map_err(|error| format!("schema catalog restart decode: {error:?}"))?;
    assert_eq!(reopened_schema.encode_catalog_object()?, schema_encoding);
    let restarted = [
        query_with_schema(&fixture, &reopened_schema, scalar)?,
        query_with_schema(&fixture, &reopened_schema, promoted_scalar)?,
        query_with_schema(&fixture, &reopened_schema, absent)?,
        query_with_schema(&fixture, &reopened_schema, contains)?,
        query_with_schema(&fixture, &reopened_schema, regex)?,
    ];
    assert_eq!(
        restarted.map(|result| result.0),
        before.map(|result| result.0)
    );
    assert!(restarted[2].1);
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

fn query_with_schema(
    fixture: &QueryFixture,
    schema: &positron_signals::SchemaCatalog,
    source: &str,
) -> Result<(usize, bool), Box<dyn Error>> {
    let service = fixture.service(16)?;
    let plan = service.plan_pipeline(fixture.context, source, query_budget())?;
    let events = service
        .execute_with_schema(plan, schema)?
        .collect::<Vec<_>>();
    let records = events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records().len()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .sum();
    let reduced_pruning = events.iter().any(|event| {
        matches!(
            event,
            QueryEvent::Terminal(QueryTerminal::Complete(stats)) if stats.reduced_pruning()
        )
    });
    Ok((records, reduced_pruning))
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
