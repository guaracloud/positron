use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{QueryBudget, QueryEvent, QueryTerminal};
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

    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 100);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?;
    let pipeline = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 16",
        budget,
    )?;
    let sql = service.plan_sql(
        context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 16",
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

#[test]
fn pipeline_and_sql_require_the_same_explicit_bounded_temporal_range() -> Result<(), Box<dyn Error>>
{
    let roots = TemporaryRoots::new("temporal-parity")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "temporal-parity-kernel")?;
    fixture.append_log("inclusive-start", 10, 1)?;
    fixture.append_log("inside", 20, 2)?;
    fixture.append_log("exclusive-end", 30, 3)?;
    fixture.append_log("outside", 40, 4)?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 100);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?;
    let pipeline =
        service.plan_pipeline(context, "logs | range event_time 10 30 | limit 16", budget)?;
    let sql = service.plan_sql(
        context,
        "SELECT body FROM logs WHERE event_time >= 10 AND event_time < 30 ORDER BY event_time, commit_position LIMIT 16",
        budget,
    )?;
    assert_eq!(pipeline.logical_plan(), sql.logical_plan());
    drop(sql);
    let events = service.execute(pipeline)?.collect::<Vec<_>>();
    let bodies = events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["inclusive-start", "inside"]);

    assert_eq!(
        service
            .plan_pipeline(context, "logs | limit 16", budget)
            .err()
            .ok_or("missing time range was accepted")?
            .code(),
        positron_query::QueryFailureCode::UnsupportedQuery
    );
    for source in [
        "logs | range query_time 30 10 | limit 16",
        "logs | range query_time 10 10 | limit 16",
    ] {
        assert_eq!(
            service
                .plan_pipeline(context, source, budget)
                .err()
                .ok_or("invalid time range was accepted")?
                .code(),
            positron_query::QueryFailureCode::InvalidBudget
        );
    }
    let short_budget = budget.with_maximum_time_range_nanoseconds(19)?;
    assert_eq!(
        service
            .plan_pipeline(
                context,
                "logs | range query_time 10 30 | limit 16",
                short_budget,
            )
            .err()
            .ok_or("over-budget temporal range was accepted")?
            .code(),
        positron_query::QueryFailureCode::InvalidBudget
    );
    Ok(())
}

#[test]
fn sql_compiles_typed_projection_and_body_filter_to_the_pipeline_plan() -> Result<(), Box<dyn Error>>
{
    let roots = TemporaryRoots::new("sql-typed-parity")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "sql-typed-parity-kernel")?;
    fixture.append_log("keep", 20, 1)?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?;

    let pipeline = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"keep\" | project query_time, commit_position | limit 16",
        budget,
    )?;
    let sql = service.plan_sql(
        context,
        "SELECT query_time, commit_position FROM logs WHERE query_time >= -100 AND query_time < 100 AND body = \"keep\" ORDER BY query_time ASC, commit_position ASC LIMIT 16",
        budget,
    )?;
    assert_eq!(pipeline.logical_plan(), sql.logical_plan());

    let pipeline = service.plan_pipeline(
        context,
        r#"pipeline:v1 logs | range query_time -100 100 | filter record["service"] any == string("api") | project record["service"], query_time | limit 16"#,
        budget,
    )?;
    let sql = service.plan_sql(
        context,
        r#"SELECT record["service"], query_time FROM logs WHERE query_time >= -100 AND query_time < 100 AND record["service"] any = string("api") ORDER BY query_time, commit_position LIMIT 16"#,
        budget,
    )?;
    assert_eq!(pipeline.logical_plan(), sql.logical_plan());
    Ok(())
}

#[test]
fn sql_compiles_search_and_grouped_count_to_the_same_typed_plan() -> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("sql-operators-parity")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "sql-operators-parity-kernel")?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?;

    let pipeline = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | search body contains \"Keep\" | limit 16",
        budget,
    )?;
    let sql = service.plan_sql(
        context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body CONTAINS \"Keep\" ORDER BY query_time, commit_position LIMIT 16",
        budget,
    )?;
    assert_eq!(pipeline.logical_plan(), sql.logical_plan());

    let pipeline = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 16",
        budget,
    )?;
    let sql = service.plan_sql(
        context,
        "SELECT body, COUNT(*) FROM logs WHERE query_time >= -100 AND query_time < 100 GROUP BY body ORDER BY query_time, commit_position LIMIT 16",
        budget,
    )?;
    assert_eq!(pipeline.logical_plan(), sql.logical_plan());

    let pipeline = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count | limit 1",
        budget,
    )?;
    let sql = service.plan_sql(
        context,
        "SELECT COUNT(*) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        budget,
    )?;
    assert_eq!(pipeline.logical_plan(), sql.logical_plan());
    Ok(())
}

#[test]
fn sql_rejects_mutation_joins_and_unbounded_or_ambiguous_forms() -> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("sql-rejections")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "sql-rejections-kernel")?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?;
    for source in [
        "SELECT * FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 LIMIT 1",
        "SELECT body FROM logs LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position",
        "SELECT body FROM logs JOIN spans ON logs.trace_id = spans.trace_id WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "UPDATE logs SET body = \"x\"",
        "DELETE FROM logs",
        "CREATE TABLE logs (body string)",
        "BEGIN; SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body = \"unterminated ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 01",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body CONTAINS \"Keep\" ORDER BY query_time, commit_position LIMIT 1 trailing",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body = \"Keep\" extra ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND record[\"service\"] none = string(\"api\") ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND record[\"service\"] any != string(\"api\") ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND record[\"service\"] index(01) = string(\"api\") ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY event_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, body LIMIT 1",
        "SELECT body, body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body, query_time, event_time, ingest_time, commit_position, record[\"x\"] FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT COUNT(*), COUNT(*) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT JSON(body), LOGFMT(body) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT CAST(body AS bytes) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT CAST(body) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT JSON(record[\"body\"]) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 GROUP BY * ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 GROUP BY body, query_time ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body, COUNT(*) FROM logs WHERE query_time >= -100 AND query_time < 100 GROUP BY query_time ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position DESC extra LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1;",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body = \"bad\\n\" ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body = \"bad\\\" ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND (((((((((((((((((body = \"x\")))))))))))))))))) ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time = -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND event_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY 123, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body LIKE \"x\" ORDER BY query_time, commit_position LIMIT 1",
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1)",
        "SELECT foo(body) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        "",
    ] {
        let failure = match service.plan_sql(context, source, budget) {
            Ok(_) => return Err(format!("unsupported SQL form was accepted: {source}").into()),
            Err(failure) => failure,
        };
        assert_eq!(
            failure.code(),
            positron_query::QueryFailureCode::UnsupportedQuery
        );
    }
    let many_tokens = (0..129).map(|_| "body").collect::<Vec<_>>().join(" ");
    let source = format!(
        "SELECT {many_tokens} FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1"
    );
    let failure = match service.plan_sql(context, &source, budget) {
        Ok(_) => return Err("token bound must reject before parsing".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.code(),
        positron_query::QueryFailureCode::UnsupportedQuery
    );
    Ok(())
}

#[test]
fn sql_body_expressions_preserve_bounded_transform_parity() -> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("sql-transform-parity")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "sql-transform-parity-kernel")?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60);
    let budget = budget?;
    for (pipeline, sql) in [
        (
            "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
            "SELECT JSON(body) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        ),
        (
            "pipeline:v1 logs | range query_time -100 100 | logfmt | limit 1",
            "SELECT LOGFMT(body) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        ),
        (
            "pipeline:v1 logs | range query_time -100 100 | cast body as int | limit 1",
            "SELECT CAST(body AS int) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        ),
    ] {
        let pipeline = service
            .plan_pipeline(context, pipeline, budget)
            .map_err(|error| format!("pipeline {pipeline}: {error:?}"))?;
        let sql = service
            .plan_sql(context, sql, budget)
            .map_err(|error| format!("sql {sql}: {error:?}"))?;
        assert_eq!(pipeline.logical_plan(), sql.logical_plan());
    }

    for (pipeline, sql) in [
        (
            r#"pipeline:v1 logs | range event_time -100 100 | filter record["service"] all == string("api") | project event_time, ingest_time | order by event_time desc, commit_position desc | limit 1"#,
            r#"SELECT EVENT_TIME, INGEST_TIME FROM logs WHERE EVENT_TIME >= -100 AND event_time < 100 AND record["service"] ALL = string("api") ORDER BY EVENT_TIME DESC, COMMIT_POSITION DESC LIMIT 1"#,
        ),
        (
            r#"pipeline:v1 logs | range ingest_time -100 100 | filter record["service"] index(0) == string("api") | project body | order by ingest_time desc, commit_position asc | limit 1"#,
            r#"SELECT body FROM logs WHERE ingest_time >= -100 AND INGEST_TIME < 100 AND record["service"] INDEX(0) = string("api") ORDER BY ingest_time DESC, commit_position ASC LIMIT 1"#,
        ),
        (
            "pipeline:v1 logs | range query_time -100 100 | search body =~ \"Keep\" | order by query_time desc, commit_position desc | limit 1",
            "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body REGEXP \"Keep\" ORDER BY query_time DESC, commit_position DESC LIMIT 1",
        ),
        (
            "pipeline:v1 logs | range query_time -100 100 | cast body as float | limit 1",
            "SELECT CAST(body AS float) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        ),
        (
            "pipeline:v1 logs | range query_time -100 100 | cast body as bool | limit 1",
            "SELECT CAST(body AS bool) FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        ),
    ] {
        let pipeline = service
            .plan_pipeline(context, pipeline, budget)
            .map_err(|error| format!("pipeline {pipeline}: {error:?}"))?;
        let sql = service
            .plan_sql(context, sql, budget)
            .map_err(|error| format!("sql {sql}: {error:?}"))?;
        assert_eq!(pipeline.logical_plan(), sql.logical_plan());
    }
    Ok(())
}

#[test]
fn versioned_native_pipeline_executes_through_the_typed_plan() -> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("versioned-pipeline")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "versioned-pipeline-kernel")?;
    fixture.append_log("versioned", 20, 1)?;
    let service =
        super::support::stage_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(15)?,
    )?;
    assert_eq!(query.logical_plan().version(), 1);
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    Ok(())
}

#[test]
fn versioned_pipeline_filters_on_an_intrinsic_body_literal() -> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("pipeline-filter")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "pipeline-filter-kernel")?;
    fixture.append_log("keep", 20, 1)?;
    fixture.append_log("discard", 21, 2)?;
    let service =
        super::support::stage_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"keep\" | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(15)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let bodies = events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["keep"]);
    Ok(())
}

#[test]
fn versioned_pipeline_projects_bounded_intrinsic_columns() -> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("pipeline-project")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "pipeline-project-kernel")?;
    fixture.append_log("projected", 20, 1)?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | project query_time, commit_position | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = match events.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("query header missing".into()),
    };
    assert_eq!(header.schema().columns(), ["query_time", "commit_position"]);
    let record = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().first(),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("projected record missing")?;
    assert_eq!(record.query_time().value(), 20);
    assert_eq!(record.commit_position().value(), 1);
    assert_eq!(record.body_text(), None);
    Ok(())
}

#[test]
fn versioned_pipeline_supports_bounded_exact_body_search() -> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("pipeline-search")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "pipeline-search-kernel")?;
    fixture.append_log("exact match", 20, 1)?;
    fixture.append_log("other", 21, 2)?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | search body == \"exact match\" | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let bodies = events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["exact match"]);
    let regex = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | search body =~ \"exact\" | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let regex_events = service.execute(regex)?.collect::<Vec<_>>();
    let regex_bodies = regex_events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(regex_bodies, ["exact match"]);
    Ok(())
}

#[test]
fn versioned_pipeline_rejects_unimplemented_or_malformed_stages() -> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("pipeline-rejections")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "pipeline-rejections-kernel")?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?;

    for source in [
        "pipeline:v1 logs",
        "pipeline:v1 logs | limit 1 | range query_time 0 1",
        "pipeline:v1 logs | range query_time 0 1 2 | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | range query_time 0 1 | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | filter body == \"a\" | filter body == \"b\" | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | search body == \"a\" | search body == \"b\" | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | project body | project body | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | aggregate count | aggregate count | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | order by query_time asc, commit_position asc | order by query_time asc, commit_position asc | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | unknown stage | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | filter body == bare | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | project body query_time | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | project body, unknown | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | project body, body | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | order by query_time asc, commit_position | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | order by event_time asc, commit_position asc | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | order by query_time sideways, commit_position asc | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | order by query_time asc,, commit_position asc | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | order by query_time asc, commit_position, asc | limit 1",
        "pipeline:v1 logs | range nope 0 1 | limit 1",
        "pipeline:v1 logs | range query_time +1 2 | limit 1",
        "pipeline:v1 logs | range query_time 01 2 | limit 1",
        "pipeline:v1 logs | range query_time -01 2 | limit 1",
        "pipeline:v1 logs | range query_time 1 nope | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | limit 01",
        "pipeline:v1 logs | range query_time 0 1 | limit nope",
        "pipeline:v1 logs | range query_time 0 1 | filter body == \"unterminated | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | filter body == \"invalid\\n-escape\" | limit 1",
        "pipeline:v2 logs | range query_time 0 1 | limit 1",
    ] {
        let failure = service
            .plan_pipeline(context, source, budget)
            .err()
            .ok_or("malformed or unimplemented pipeline was accepted")?;
        assert_eq!(
            failure.code(),
            positron_query::QueryFailureCode::UnsupportedQuery,
            "unexpected failure for {source:?}"
        );
    }

    let overlong = format!(
        "pipeline:v1 logs | range query_time 0 1 | {}",
        "x".repeat(4_080)
    );
    let failure = service
        .plan_pipeline(context, &overlong, budget)
        .err()
        .ok_or("overlong pipeline was accepted")?;
    assert_eq!(
        failure.code(),
        positron_query::QueryFailureCode::UnsupportedQuery
    );
    Ok(())
}

#[test]
fn advanced_native_page_execution_stays_with_the_pagination_authority() -> Result<(), Box<dyn Error>>
{
    let roots = TemporaryRoots::new("pipeline-page-authority")?;
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
    let fixture = KernelFixture::new(
        instance.default_tenant_id(),
        "pipeline-page-authority-kernel",
    )?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time 0 1 | filter body == \"bounded\" | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    let failure = service
        .execute_page(query)
        .err()
        .ok_or("advanced native page execution was accepted")?;
    assert_eq!(
        failure.code(),
        positron_query::QueryFailureCode::UnsupportedQuery
    );
    Ok(())
}

#[test]
fn versioned_pipeline_counts_filtered_records_with_a_typed_aggregate() -> Result<(), Box<dyn Error>>
{
    let roots = TemporaryRoots::new("pipeline-count")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "pipeline-count-kernel")?;
    fixture.append_log("keep", 20, 1)?;
    fixture.append_log("keep", 21, 2)?;
    fixture.append_log("discard", 22, 3)?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"keep\" | aggregate count | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = match events.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("query header missing".into()),
    };
    assert_eq!(header.schema().columns(), ["count"]);
    let record = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().first(),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("aggregate record missing")?;
    assert_eq!(record.count(), Some(2));
    Ok(())
}

#[test]
fn versioned_pipeline_orders_by_intrinsic_time_with_commit_tie_breaking()
-> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("pipeline-order")?;
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
    let mut fixture = KernelFixture::new(instance.default_tenant_id(), "pipeline-order-kernel")?;
    fixture.append_log("later", 20, 1)?;
    fixture.seal_and_reopen()?;
    fixture.append_log("earlier", 10, 2)?;
    fixture.append_log("same-time", 20, 3)?;
    let service =
        super::support::zero_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | order by query_time desc, commit_position asc | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let bodies = events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .filter_map(|record| record.body_text())
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["later", "same-time", "earlier"]);
    Ok(())
}

#[test]
fn native_operator_work_consumes_the_cumulative_query_budget() -> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("pipeline-operator-budget")?;
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
    let fixture = KernelFixture::new(
        instance.default_tenant_id(),
        "pipeline-operator-budget-kernel",
    )?;
    fixture.append_log("keep", 20, 1)?;
    let service =
        super::support::stage_work_service(fixture.authority.governor(), fixture.ledger()?, 16);
    let budget =
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(2)?;
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"keep\" | limit 16",
        budget,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == positron_query::QueryFailureCode::BudgetExhausted
    ));
    Ok(())
}
