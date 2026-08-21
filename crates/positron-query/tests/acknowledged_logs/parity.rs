use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{QueryBudget, QueryEvent, QueryService, QueryTerminal};
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

    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 100);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?;
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
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 100);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?;
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
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
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
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"keep\" | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
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
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | project query_time, commit_position | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
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
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | search body == \"exact match\" | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
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
    let unsupported = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | search body =~ \"exact\" | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
    );
    assert!(matches!(
        unsupported,
        Err(failure) if failure.code() == positron_query::QueryFailureCode::UnsupportedQuery
    ));
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
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 16);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?;

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
        "pipeline:v1 logs | range query_time 0 1 | json | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | logfmt | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | cast body as string | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | filter body == bare | limit 1",
        "pipeline:v1 logs | range query_time 0 1 | filter body == \"\" | limit 1",
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
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time 0 1 | filter body == \"bounded\" | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
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
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"keep\" | aggregate count | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
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
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 16);
    let query = service.plan_pipeline(
        context,
        "pipeline:v1 logs | range query_time -100 100 | order by query_time desc, commit_position asc | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
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
    let service = QueryService::new(fixture.authority.governor(), fixture.ledger()?, 16);
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?.with_cpu_work_units(3)?;
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
