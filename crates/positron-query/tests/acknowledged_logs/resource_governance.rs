use std::error::Error;

use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_kernel::{PrincipalQuota, ResourceAmounts};
use positron_policy::NativeLogAttribute;
use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryTerminal};
use positron_signals::SchemaPath;

use super::terminal_and_bounds::QueryFixture;

fn quota() -> Result<PrincipalQuota, Box<dyn Error>> {
    let per_operation = ResourceAmounts::new([70_000, 0, 0, 0, 0, 1, 0, 0, 2_000_000, 0, 0]);
    let aggregate = ResourceAmounts::new([120_000, 0, 0, 0, 0, 2, 0, 0, 4_000_000, 0, 0]);
    Ok(PrincipalQuota::new(8, per_operation, aggregate)?)
}

fn budget() -> Result<QueryBudget, Box<dyn Error>> {
    Ok(QueryBudget::new(1_048_576, 16, 1, 1_048_576, 65_536, 60)?)
}

fn assert_operation_refusal(events: &[QueryEvent]) -> Result<(), Box<dyn Error>> {
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_))),
        "operation quota refusal exposed a partial result: {events:?}"
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::ResourceAdmissionRefused
    ));
    Ok(())
}

#[test]
fn log_scan_cannot_bypass_its_planned_operation_ceiling() -> Result<(), Box<dyn Error>> {
    QueryFixture::scoped_with_principal_quota("query-operation-log-scan", quota()?, |fixture| {
        fixture.kernel.append_log(&"x".repeat(20_000), 1, 1)?;
        let service = fixture.service(16)?;
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | limit 1",
            budget()?,
        )?;
        assert_operation_refusal(&service.execute(query)?.collect::<Vec<_>>())
    })
}

#[test]
fn text_scan_cannot_bypass_its_planned_operation_ceiling() -> Result<(), Box<dyn Error>> {
    QueryFixture::scoped_with_principal_quota("query-operation-text-scan", quota()?, |fixture| {
        let body = "needle ".repeat(3_000);
        let schema = fixture.kernel.append_indexed_text_logs(vec![&body], 1)?;
        let service = fixture.service(16)?;
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | search body contains \"needle\" | limit 1",
            budget()?,
        )?;
        assert_operation_refusal(
            &service
                .execute_with_schema(query, schema.catalog())?
                .collect::<Vec<_>>(),
        )
    })
}

#[test]
fn schema_scan_cannot_bypass_its_planned_operation_ceiling() -> Result<(), Box<dyn Error>> {
    QueryFixture::scoped_with_principal_quota("query-operation-schema-scan", quota()?, |fixture| {
        let path = SchemaPath::root(AttributeNamespace::Record, "indexed".to_owned())?;
        let schema = fixture.kernel.append_indexed_attribute_logs(
            vec![(
                Some(1),
                vec![NativeLogAttribute::new(
                    AttributeNamespace::Record,
                    "indexed".to_owned(),
                    vec![CandidateAttributeValue::string("x".repeat(20_000))],
                )],
            )],
            1,
            &path,
        )?;
        let service = fixture.service(16)?;
        let query = service.plan_pipeline(
            fixture.context,
            r#"pipeline:v1 logs | range query_time -100 100 | filter record["indexed"] any == string("x") | limit 1"#,
            budget()?,
        )?;
        assert_operation_refusal(
            &service
                .execute_with_schema(query, schema.catalog())?
                .collect::<Vec<_>>(),
        )
    })
}

#[test]
fn correlation_scans_cannot_bypass_its_planned_operation_ceiling() -> Result<(), Box<dyn Error>> {
    QueryFixture::scoped_with_principal_quota(
        "query-operation-correlation-scan",
        quota()?,
        |fixture| {
            let trace = [0x41; 16];
            let span = [0x42; 8];
            fixture.kernel.append_trace(trace, span, 1, 1)?;
            fixture
                .kernel
                .append_log_with_trace(&"x".repeat(20_000), 1, trace, span, 2)?;
            let service = fixture.correlation_service(16)?;
            let query = service.plan_pipeline(
                fixture.context,
                "pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1",
                budget()?,
            )?;
            assert_operation_refusal(&service.execute(query)?.collect::<Vec<_>>())
        },
    )
}
