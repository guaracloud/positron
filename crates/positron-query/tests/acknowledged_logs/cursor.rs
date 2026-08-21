use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_query::{
    QueryBudget, QueryCursor, QueryEvent, QueryFailureCode, QueryService, QueryTerminal,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::support::{KernelFixture, TemporaryRoots, TestClock};

#[path = "cursor/event_time.rs"]
mod event_time;

#[test]
fn authenticated_cursor_resumes_the_same_snapshot_and_repeats_deterministically()
-> Result<(), Box<dyn Error>> {
    let roots = TemporaryRoots::new("cursor")?;
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
    let fixture = KernelFixture::new(instance.default_tenant_id(), "cursor-kernel")?;
    fixture.append_log("first", 20, 1)?;
    fixture.append_log("second", 21, 2)?;
    let clock = TestClock::shared(100);
    let service = QueryService::with_clock(
        fixture.authority.governor(),
        fixture.ledger()?,
        1,
        clock.clone(),
    );
    let plan = service.plan_pipeline(
        context,
        "logs | range query_time -100 100 | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let first = service.execute_page(plan)?.collect::<Vec<_>>();
    let cursor = continuation(&first)?.clone();
    let first_batch = batch_identity(&first)?;

    fixture.append_log("future", 22, 3)?;
    clock.set(101);
    let resumed = QueryService::with_clock(
        fixture.authority.governor(),
        fixture.ledger()?,
        1,
        clock.clone(),
    )
    .resume(context, &cursor)?;
    let repeated = service.resume(context, &cursor)?;
    let resumed = resumed.collect::<Vec<_>>();
    assert_eq!(bodies(&resumed), ["second"]);
    assert!(matches!(
        resumed.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));
    let repeated = repeated.collect::<Vec<_>>();
    assert_eq!(batch_identity(&resumed)?, batch_identity(&repeated)?);
    assert_ne!(first_batch, batch_identity(&resumed)?);
    Ok(())
}

#[test]
fn result_envelope_identifies_snapshot_schema_budget_order_lease_and_digest_chain()
-> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let first = fixture
        .service()
        .resume(fixture.context, &fixture.cursor)?
        .collect::<Vec<_>>();
    let header = match first.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("result header missing".into()),
    };
    assert_eq!(header.schema().columns(), ["body"]);
    assert_eq!(header.snapshot().frontier(), 2);
    assert_ne!(header.snapshot().identity(), [0; 32]);
    assert!(header.snapshot().generation() > 0);
    assert_eq!(
        header.ordering().columns(),
        ["query_time", "commit_position", "record_ordinal"]
    );
    assert_eq!(header.budget().output_rows(), 16);
    assert_ne!(header.lease().identity(), [0; 16]);
    assert!(header.lease().expiry() > 0);
    assert!(header.initial_cursor().is_some());

    let batch = first
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("result batch missing")?;
    assert_ne!(batch.prior_digest(), [0; 32]);
    assert_ne!(batch.digest(), batch.prior_digest());
    let terminal = first.last().ok_or("terminal missing")?;
    assert!(matches!(
        terminal,
        QueryEvent::Terminal(QueryTerminal::Complete(stats))
            if stats.result_digest() == batch.digest()
    ));
    Ok(())
}

#[test]
fn cursor_tampering_expiry_and_wrong_authority_fail_before_resume_work()
-> Result<(), Box<dyn Error>> {
    let fixture = CursorFixture::new()?;
    let mut bytes = fixture.cursor.as_bytes().to_vec();
    let byte = bytes
        .get_mut(8)
        .ok_or("bounded cursor is unexpectedly short")?;
    *byte ^= 1;
    let tampered = positron_query::QueryCursor::from_bytes(&bytes)?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &tampered)
            .expect_err("tampering must fail closed")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    fixture.clock.set(161);
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &fixture.cursor)
            .expect_err("expired cursor must fail closed")
            .code(),
        QueryFailureCode::SnapshotExpired
    );
    assert_eq!(
        fixture
            .service()
            .resume(fixture.administrator, &fixture.cursor)
            .expect_err("system administrator cannot resume tenant data")
            .code(),
        QueryFailureCode::Unauthorized
    );
    let empty = KernelFixture::new(
        fixture
            .context
            .tenant_attribution()
            .ok_or("query attribution missing")?
            .tenant_id(),
        "cursor-frontier-regression",
    )?;
    let behind = QueryService::new(empty.authority.governor(), empty.ledger()?, 1);
    assert_eq!(
        behind
            .resume(fixture.context, &fixture.cursor)
            .expect_err("snapshot frontier cannot move backwards")
            .code(),
        QueryFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn authenticated_cursor_semantics_versions_and_domain_are_fail_closed() -> Result<(), Box<dyn Error>>
{
    let fixture = CursorFixture::new()?;
    assert_eq!(fixture.cursor.as_bytes().len(), 373);
    for (label, rewrite) in [
        (
            "magic",
            (|bytes: &mut Vec<u8>| bytes[0] ^= 1) as fn(&mut Vec<u8>),
        ),
        ("axis", |bytes: &mut Vec<u8>| bytes[104] = u8::MAX),
        ("plan digest", |bytes: &mut Vec<u8>| bytes[123] ^= 1),
        ("zero lease", |bytes: &mut Vec<u8>| bytes[197..213].fill(0)),
        ("zero cpu budget", |bytes: &mut Vec<u8>| {
            bytes[261..269].fill(0)
        }),
    ] {
        let cursor = rewritten_cursor(&fixture, rewrite, b"query-cursor-v1")?;
        assert_eq!(
            fixture
                .service()
                .resume(fixture.context, &cursor)
                .expect_err(label)
                .code(),
            QueryFailureCode::InvalidCursor
        );
    }
    let wrong_domain = rewritten_cursor(&fixture, |_| {}, b"query-result-batch-v1")?;
    assert_eq!(
        fixture
            .service()
            .resume(fixture.context, &wrong_domain)
            .expect_err("control token purpose is part of authentication")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    let legacy = rewritten_cursor(
        &fixture,
        |bytes| {
            bytes.drain(317..341);
            bytes.drain(261..269);
        },
        b"query-cursor-v1",
    )?;
    assert_eq!(legacy.as_bytes().len(), 341);
    let events = fixture
        .service()
        .resume(fixture.context, &legacy)?
        .collect::<Vec<_>>();
    assert_eq!(bodies(&events), ["second"]);
    Ok(())
}

fn rewritten_cursor(
    fixture: &CursorFixture,
    rewrite: impl FnOnce(&mut Vec<u8>),
    purpose: &[u8],
) -> Result<QueryCursor, Box<dyn Error>> {
    let mut payload = fixture.cursor.as_bytes()[..fixture.cursor.as_bytes().len() - 32].to_vec();
    rewrite(&mut payload);
    let protector = fixture.kernel.ledger()?.control_tokens();
    let initial = protector.authenticate(purpose, &payload)?;
    payload[8..16].copy_from_slice(&initial.epoch().to_be_bytes());
    let authentication = protector.authenticate(purpose, &payload)?;
    payload.extend_from_slice(&authentication.tag());
    Ok(QueryCursor::from_bytes(&payload)?)
}

struct CursorFixture {
    _roots: TemporaryRoots,
    kernel: KernelFixture,
    context: positron_governance::AuthorizedContext,
    administrator: positron_governance::AuthorizedContext,
    cursor: positron_query::QueryCursor,
    clock: std::sync::Arc<TestClock>,
}

impl CursorFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let roots = TemporaryRoots::new("cursor-failures")?;
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
        let kernel = KernelFixture::new(instance.default_tenant_id(), "cursor-failure-kernel")?;
        kernel.append_log("first", 20, 1)?;
        kernel.append_log("second", 21, 2)?;
        let clock = TestClock::shared(100);
        let service = QueryService::with_clock(
            kernel.authority.governor(),
            kernel.ledger()?,
            1,
            clock.clone(),
        );
        let plan = service.plan_pipeline(
            context,
            "logs | range query_time -100 100 | limit 2",
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
                .with_cpu_work_units(16)?,
        )?;
        let events = service.execute_page(plan)?.collect::<Vec<_>>();
        let cursor = continuation(&events)?.clone();
        clock.set(101);
        Ok(Self {
            _roots: roots,
            kernel,
            context,
            administrator,
            cursor,
            clock,
        })
    }

    fn service(&self) -> QueryService<'static, 'static, '_> {
        QueryService::with_clock(
            self.kernel.authority.governor(),
            self.kernel.ledger().expect("fixture ledger"),
            1,
            self.clock.clone(),
        )
    }
}

fn continuation(events: &[QueryEvent]) -> Result<&positron_query::QueryCursor, Box<dyn Error>> {
    match events.last() {
        Some(QueryEvent::Terminal(QueryTerminal::Continued(cursor))) => Ok(cursor),
        _ => Err("continuation cursor missing".into()),
    }
}

fn batch_identity(events: &[QueryEvent]) -> Result<(u64, [u8; 32]), Box<dyn Error>> {
    events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some((batch.sequence(), batch.digest())),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or_else(|| "result batch missing".into())
}

fn bodies(events: &[QueryEvent]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .filter_map(|record| record.body_text())
        .collect()
}
