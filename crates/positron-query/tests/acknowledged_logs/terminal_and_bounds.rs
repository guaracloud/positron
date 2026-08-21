use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{ResourceAmounts, ResourceDimension, WorkClaim, WorkKind};
use positron_query::{
    QueryBudget, QueryBudgetDimension, QueryCursor, QueryEvent, QueryFailureCode, QueryService,
    QueryTerminal,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::support::{KernelFixture, TemporaryRoots, TestClock};

#[test]
fn cancellation_replaces_unsent_events_with_one_non_complete_terminal() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("cancel")?;
    fixture.kernel.append_log("accepted", 20, 1)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    let mut stream = service.execute(query)?;
    assert!(matches!(stream.next(), Some(QueryEvent::Header(_))));

    stream.cancel()?;
    let remaining = stream.collect::<Vec<_>>();
    assert!(matches!(
        remaining.as_slice(),
        [QueryEvent::Terminal(QueryTerminal::Incomplete(failure))]
            if failure.code() == QueryFailureCode::Cancelled
    ));

    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    let mut disconnected = service.execute(query)?;
    assert!(matches!(disconnected.next(), Some(QueryEvent::Header(_))));
    drop(disconnected);
    Ok(())
}

#[test]
fn malformed_acknowledged_data_is_one_typed_terminal_not_a_partial_success()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("malformed")?;
    fixture.kernel.append_malformed_log_block(1)?;
    let service = fixture.service(16)?;
    let query = service.plan_sql(fixture.context, "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1", budget())?;
    let events = service.execute(query)?.collect::<Vec<_>>();

    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::MalformedPersistentData
    ));
    assert_eq!(terminal_count(&events), 1);
    Ok(())
}

#[test]
fn empty_snapshot_completes_once_without_a_batch_and_terminal_cancel_is_idempotent()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("empty")?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    let mut stream = service.execute(query)?;
    assert!(matches!(stream.next(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        stream.next(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    stream.cancel()?;
    assert!(stream.next().is_none());
    Ok(())
}

#[test]
fn response_header_exposes_every_effective_query_budget_limit() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("header-budget")?;
    let service = fixture.service(1)?;
    let expected = QueryBudget::new(101, 7, 5, 103, 107, 109)?
        .with_cpu_work_units(11)?
        .with_maximum_time_range_nanoseconds(113)?;
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time 0 100 | limit 1",
        expected,
    )?;
    let mut stream = service.execute(query)?;
    let actual = match stream.next() {
        Some(QueryEvent::Header(header)) => header.budget(),
        _ => return Err("query header missing".into()),
    };

    assert_eq!(actual.scanned_bytes(), 101);
    assert_eq!(actual.decoded_records(), 7);
    assert_eq!(actual.output_rows(), 5);
    assert_eq!(actual.output_bytes(), 103);
    assert_eq!(actual.memory_bytes(), 107);
    assert_eq!(actual.cpu_work_units(), 11);
    assert_eq!(actual.wall_seconds(), 109);
    assert_eq!(actual.maximum_time_range_nanoseconds(), 113);
    Ok(())
}

#[test]
fn paged_execution_rejects_zero_batch_and_expiry_overflow_before_work() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("page-bounds")?;
    let service = fixture.service(0)?;
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    assert_eq!(
        service
            .execute_page(query)
            .expect_err("zero batch limit")
            .code(),
        QueryFailureCode::InvalidBudget
    );

    let service = super::support::zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(u64::MAX),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    assert_eq!(
        service
            .execute_page(query)
            .expect_err("lease expiry overflow")
            .code(),
        QueryFailureCode::InvalidBudget
    );
    Ok(())
}

#[test]
fn scan_capacity_refusal_is_one_typed_non_complete_terminal() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("scan-capacity")?;
    fixture.kernel.append_log("accepted", 20, 1)?;
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        budget(),
    )?;
    let tenant = fixture
        .context
        .tenant_attribution()
        .ok_or("query attribution missing")?
        .tenant_id();
    let held = fixture
        .kernel
        .authority
        .governor()
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 6_850_000)?,
        )?)?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    drop(held);
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::ResourceAdmissionRefused
    ));
    assert_eq!(terminal_count(&events), 1);
    Ok(())
}

#[test]
fn parsers_budgets_keys_and_cursor_bytes_enforce_exact_public_bounds() -> Result<(), Box<dyn Error>>
{
    assert_ne!(
        QueryFailureCode::ResourceExhausted,
        QueryFailureCode::BudgetExhausted
    );
    assert_eq!(
        QueryBudget::new(1, 1_025, 1, 1, 1, 1)
            .expect_err("decoded record bound")
            .code(),
        QueryFailureCode::InvalidBudget
    );
    assert_eq!(
        QueryBudget::new(1, 1, 1_025, 1, 1, 1)
            .expect_err("output row bound")
            .code(),
        QueryFailureCode::InvalidBudget
    );
    assert_eq!(
        QueryBudget::new(1, 1, 1, 1, 1, 1)?
            .with_cpu_work_units(0)
            .expect_err("zero cpu budget")
            .code(),
        QueryFailureCode::InvalidBudget
    );
    assert_eq!(
        QueryBudget::new(1, 1, 1, 1, 1, 1)?
            .with_maximum_time_range_nanoseconds(0)
            .expect_err("zero temporal bound")
            .code(),
        QueryFailureCode::InvalidBudget
    );
    assert_eq!(
        QueryBudget::new(1, 1, 1, 1, 1, 3_600)?.wall_seconds(),
        3_600
    );
    let overlong_wall = QueryBudget::new(1, 1, 1, 1, 1, 3_601)
        .expect_err("wall budget above the Release-1 lease ceiling");
    assert_eq!(overlong_wall.code(), QueryFailureCode::InvalidBudget);
    assert_eq!(
        overlong_wall.limiting_budget(),
        Some(QueryBudgetDimension::WallSeconds)
    );
    assert!(QueryCursor::from_bytes(&[0; 340]).is_err());
    assert!(QueryCursor::from_bytes(&[0; 341]).is_ok());
    assert!(QueryCursor::from_bytes(&[0; 342]).is_err());
    assert_eq!(
        format!("{:?}", QueryCursor::from_bytes(&[0; 341])?),
        "QueryCursor { <opaque> }"
    );
    assert_eq!(
        QueryBudget::new(0, 1, 1, 1, 1, 1)
            .expect_err("zero budget")
            .to_string(),
        "query request failed"
    );

    let fixture = QueryFixture::new("bounds")?;
    let service = fixture.service(16)?;
    let pipeline = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 1024",
        budget(),
    )?;
    let sql = service.plan_sql(
        fixture.context,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1024",
        budget(),
    )?;
    assert_eq!(pipeline.logical_plan(), sql.logical_plan());
    drop((pipeline, sql));
    for source in [
        "logs | range query_time -100 100 | limit 0",
        "logs | range query_time -100 100 | limit 1025",
        "logs | range query_time -100 100 | limit 01",
        "logs | range query_time -100 100 | limit 1 trailing",
    ] {
        assert_eq!(
            failure_code(service.plan_pipeline(fixture.context, source, budget()))?,
            if source.ends_with(" 0") || source.ends_with("1025") {
                QueryFailureCode::InvalidBudget
            } else {
                QueryFailureCode::UnsupportedQuery
            }
        );
    }
    for source in [
        "logs | range unsupported -100 100 | limit 1",
        "logs | range query_time +1 100 | limit 1",
        "logs | range query_time 01 100 | limit 1",
        "logs | range query_time -01 100 | limit 1",
    ] {
        assert_eq!(
            failure_code(service.plan_pipeline(fixture.context, source, budget()))?,
            QueryFailureCode::UnsupportedQuery
        );
    }
    assert_eq!(
        failure_code(service.plan_sql(fixture.context, "SELECT * FROM logs LIMIT 1", budget()))?,
        QueryFailureCode::UnsupportedQuery
    );
    assert_eq!(
        failure_code(service.plan_pipeline(fixture.administrator, "malformed", budget()))?,
        QueryFailureCode::Unauthorized
    );
    assert_eq!(
        failure_code(service.plan_pipeline(
            fixture.context,
            "malformed",
            QueryBudget::new(1, 1, 1, 1, 9_000_000, 1)?,
        ))?,
        QueryFailureCode::ResourceAdmissionRefused
    );
    for source in [
        "pipeline:v1 logs | range query_time -100 100 | limit 1 | filter body == \"late\"",
        "pipeline:v1 logs | filter body == \"late\" | range query_time -100 100 | limit 1",
    ] {
        assert_eq!(
            failure_code(service.plan_pipeline(fixture.context, source, budget()))?,
            QueryFailureCode::UnsupportedQuery
        );
    }
    Ok(())
}

#[test]
fn every_query_frontend_rejects_source_bytes_beyond_the_public_bound_before_parsing()
-> Result<(), Box<dyn Error>> {
    const MAX_QUERY_SOURCE_BYTES: usize = 4_096;
    let fixture = QueryFixture::new("source-byte-bound")?;
    let service = fixture.service(16)?;
    let shorthand = padded_source(
        "logs | range query_time -100 100 | limit 1",
        MAX_QUERY_SOURCE_BYTES,
    )?;
    let sql = padded_source(
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 1",
        MAX_QUERY_SOURCE_BYTES,
    )?;

    drop(service.plan_pipeline(fixture.context, &shorthand, budget())?);
    drop(service.plan_sql(fixture.context, &sql, budget())?);

    assert_eq!(
        failure_code(service.plan_pipeline(fixture.context, &format!("{shorthand} "), budget(),))?,
        QueryFailureCode::UnsupportedQuery
    );
    assert_eq!(
        failure_code(service.plan_sql(fixture.context, &format!("{sql} "), budget()))?,
        QueryFailureCode::UnsupportedQuery
    );
    Ok(())
}

pub(crate) struct QueryFixture {
    _roots: TemporaryRoots,
    pub(crate) kernel: KernelFixture,
    pub(crate) context: positron_governance::AuthorizedContext,
    administrator: positron_governance::AuthorizedContext,
}

impl QueryFixture {
    pub(crate) fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let roots = TemporaryRoots::new(label)?;
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
        let administrator = instance.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?;
        let kernel = KernelFixture::new(instance.default_tenant_id(), label)?;
        Ok(Self {
            _roots: roots,
            kernel,
            context,
            administrator,
        })
    }

    fn service(
        &self,
        batch_limit: u16,
    ) -> Result<QueryService<'static, 'static, '_>, Box<dyn Error>> {
        Ok(super::support::zero_work_service(
            self.kernel.authority.governor(),
            self.kernel.ledger()?,
            batch_limit,
        ))
    }
}

fn budget() -> QueryBudget {
    QueryBudget::new(1_048_576, 1_024, 1_024, 1_048_576, 1_048_576, 60).expect("fixture budget")
}

fn terminal_count(events: &[QueryEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, QueryEvent::Terminal(_)))
        .count()
}

fn failure_code<T>(
    result: Result<T, positron_query::QueryFailure>,
) -> Result<QueryFailureCode, Box<dyn Error>> {
    match result {
        Ok(_) => Err("query unexpectedly planned".into()),
        Err(failure) => Ok(failure.code()),
    }
}

fn padded_source(source: &str, bytes: usize) -> Result<String, Box<dyn Error>> {
    let padding = bytes
        .checked_sub(source.len())
        .ok_or("query fixture exceeds its intended byte bound")?;
    Ok(format!("{source}{:padding$}", ""))
}
