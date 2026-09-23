use std::error::Error;
use std::sync::Arc;

use positron_domain::identity::TenantId;
use positron_query::{
    ExportDestination, ExportManifest, ExportSink, QueryBatch, QueryBudget, QueryFailureCode,
};

use super::{
    support::{TestClock, zero_work_clock_service},
    terminal_and_bounds::QueryFixture,
};

#[derive(Default)]
struct RecordingSink {
    started: bool,
    batches: Vec<([u8; 16], u64, [u8; 32])>,
}

struct InterruptingSink {
    writes: usize,
}

struct TestExportDestinationResolver;

impl positron_query::ExportDestinationResolver for TestExportDestinationResolver {
    fn resolve(&self, _tenant: TenantId, name: &str) -> Option<[u8; 16]> {
        (name == "configured").then_some([0x7a; 16])
    }
}

impl ExportSink for InterruptingSink {
    fn write_batch(
        &mut self,
        _destination: ExportDestination,
        _batch: &QueryBatch,
        _continuation: Option<&positron_query::QueryCursor>,
    ) -> Result<(), positron_query::QueryFailure> {
        self.writes += 1;
        Err(QueryBudget::new(0, 1, 1, 1, 1, 1)
            .expect_err("invalid budget supplies a public typed sink failure"))
    }
}

impl ExportSink for RecordingSink {
    fn start(
        &mut self,
        _header: &positron_query::QueryHeader,
    ) -> Result<(), positron_query::QueryFailure> {
        self.started = true;
        Ok(())
    }

    fn write_batch(
        &mut self,
        destination: ExportDestination,
        batch: &QueryBatch,
        _continuation: Option<&positron_query::QueryCursor>,
    ) -> Result<(), positron_query::QueryFailure> {
        self.batches
            .push((destination.identity(), batch.sequence(), batch.digest()));
        Ok(())
    }
}

#[test]
fn durable_export_writes_each_deterministic_batch_to_its_configured_destination()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-manifest")?;
    fixture.kernel.append_log("first", 20, 1)?;
    fixture.kernel.append_log("second", 21, 2)?;
    let service = fixture.service(1)?;
    let destination = "configured";
    let mut sink = RecordingSink::default();

    let manifest: ExportManifest = service
        .export_pipeline_as_operation(
            fixture.kernel.catalog_for_test(),
            &fixture.export_manifest_signer()?,
            fixture.context,
            positron_governance::AdministrativeIdempotencyKey::new([0x40; 16])?,
            "logs | range query_time -100 100 | limit 2",
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?,
            destination,
            &mut sink,
        )?
        .manifest()
        .clone();

    assert_eq!(sink.batches.len(), 2);
    assert!(
        sink.started,
        "destination must bind the snapshot before batch output"
    );
    assert!(
        sink.batches
            .iter()
            .all(|(actual, _, _)| *actual == [0x7a; 16])
    );
    assert_eq!(manifest.destination().identity(), [0x7a; 16]);
    assert_eq!(manifest.batch_count(), 2);
    assert_ne!(manifest.result_digest(), [0; 32]);
    service.verify_export_manifest(&manifest)?;
    Ok(())
}

#[test]
fn durable_export_records_a_catalog_backed_terminal_operation_after_the_signed_manifest()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-operation")?;
    fixture.kernel.append_log("accepted", 20, 1)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let destination = "configured";
    let mut sink = RecordingSink::default();

    let receipt = service.export_pipeline_as_operation(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        positron_governance::AdministrativeIdempotencyKey::new([0x41; 16])?,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?,
        destination,
        &mut sink,
    )?;

    assert_eq!(receipt.manifest().destination().identity(), [0x7a; 16]);
    assert!(receipt.manifest().signature().is_some());
    let output_identity = receipt
        .manifest()
        .output_identity()
        .ok_or("durable exports must name their protected output")?;
    let operation = positron_governance::DurableOperationAdministration::inspect(
        fixture.kernel.catalog_for_test(),
        receipt.operation_id(),
    )?
    .ok_or("durable export operation missing")?;
    assert_eq!(
        operation.status(),
        positron_governance::DurableOperationStatus::Succeeded
    );
    let output =
        positron_kernel::ExportOutput::reopen(fixture.kernel.catalog_for_test(), output_identity)
            .map_err(|failure| format!("reopen durable payload: {failure:?}"))?;
    assert_eq!(output.binding().destination(), [0x7a; 16]);
    assert_eq!(
        receipt.manifest().snapshot().identity(),
        output.binding().snapshot_identity(),
        "the signed receipt must identify the exact protected snapshot"
    );
    assert_eq!(
        receipt.manifest().snapshot().generation(),
        output.binding().snapshot_generation(),
        "the signed receipt must identify the exact protected generation"
    );
    assert_eq!(
        receipt.manifest().snapshot().frontier(),
        output.binding().snapshot_frontier(),
        "the signed receipt must identify the exact protected frontier"
    );
    assert_eq!(output.batch_count(), 1);
    let bytes = output
        .read_batch(fixture.kernel.catalog_for_test(), 100, 0)
        .map_err(|failure| format!("read protected durable payload: {failure:?}"))?;
    assert!(bytes.starts_with(b"POSQBT01"));
    let recovered = service.resolve_durable_export(
        fixture.kernel.catalog_for_test(),
        fixture.context,
        receipt.operation_id(),
        output_identity,
        destination,
    )?;
    assert_eq!(
        recovered.manifest().result_digest(),
        receipt.manifest().result_digest()
    );
    assert_eq!(recovered.manifest().batches(), receipt.manifest().batches());
    assert_eq!(
        operation.kind(),
        positron_governance::DurableOperationKind::QueryExport
    );
    assert_eq!(
        positron_governance::DurableOperationAdministration::cancel_query_export(
            fixture.kernel.catalog_for_test(),
            fixture.context,
            receipt.operation_id(),
            operation.request().idempotency_key(),
            101,
        )
        .expect_err("completed exports cannot be cancelled"),
        positron_governance::DurableOperationFailure::CancellationUnavailable
    );
    Ok(())
}

#[test]
fn query_export_audit_decodes_and_is_visible_only_to_its_tenant() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-audit-tenant")?;
    fixture.kernel.append_log("accepted", 20, 1)?;
    let service = fixture.service(1)?;
    let key = positron_governance::AdministrativeIdempotencyKey::new([0x4a; 16])?;
    let receipt = service.export_pipeline_as_operation(
        fixture.kernel.catalog_for_test(),
        &fixture.export_manifest_signer()?,
        fixture.context,
        key,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?,
        "configured",
        &mut RecordingSink::default(),
    )?;
    let tenant_administrator = fixture.tenant_administration_context()?;
    let catalog = fixture.kernel.catalog_for_test();
    let audit = catalog
        .governance_audit_records()?
        .iter()
        .map(positron_governance::GovernanceAuditEntry::decode)
        .collect::<Result<Vec<_>, _>>()?;
    let tenant = fixture
        .context
        .tenant_attribution()
        .ok_or("query context lacks tenant")?
        .tenant_id();
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let visible = identity.inspect_audit(tenant_administrator, &audit)?;
    let tenant_records = visible.audit_records().collect::<Vec<_>>();
    let export_transitions = tenant_records
        .iter()
        .filter_map(|entry| match entry {
            positron_governance::GovernanceAuditEntry::DurableOperation(entry)
                if entry.operation_id() == receipt.operation_id() =>
            {
                Some(entry)
            },
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(export_transitions.len(), 4);
    assert!(export_transitions.iter().all(|entry| {
        entry.applicable_tenant() == Some(tenant)
            && entry.acting_principal() == Some(fixture.context.principal_id())
            && entry.request_id() == Some(key)
    }));
    assert_eq!(
        export_transitions.last().map(|entry| entry.outcome()),
        Some(positron_governance::DurableOperationStatus::Succeeded)
    );
    assert!(
        tenant_records
            .iter()
            .all(|entry| entry.tenant_id() == Some(tenant))
    );
    Ok(())
}

#[test]
fn exact_caller_key_retry_resolves_its_completed_export_after_catalog_advances()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-idempotent-retry")?;
    fixture.kernel.append_log("first", 20, 1)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let destination = "configured";
    let key = positron_governance::AdministrativeIdempotencyKey::new([0x42; 16])?;
    let source = "logs | range query_time -100 100 | limit 1";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;

    let first = service.export_pipeline_as_operation(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        key,
        source,
        budget,
        destination,
        &mut RecordingSink::default(),
    )?;
    fixture.kernel.append_log("later", 21, 2)?;

    let retry = service.export_pipeline_as_operation(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        key,
        source,
        budget,
        destination,
        &mut RecordingSink::default(),
    )?;

    assert_eq!(retry.operation_id(), first.operation_id());
    assert_eq!(retry.manifest().snapshot(), first.manifest().snapshot());
    assert_eq!(
        retry.manifest().result_digest(),
        first.manifest().result_digest()
    );
    Ok(())
}

#[test]
fn caller_key_rejects_a_changed_canonical_export_intent() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-idempotency-conflict")?;
    fixture.kernel.append_log("first", 20, 1)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let destination = "configured";
    let key = positron_governance::AdministrativeIdempotencyKey::new([0x43; 16])?;
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;

    service.export_pipeline_as_operation(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        key,
        "logs | range query_time -100 100 | limit 1",
        budget,
        destination,
        &mut RecordingSink::default(),
    )?;

    assert_eq!(
        service
            .export_pipeline_as_operation(
                fixture.kernel.catalog_for_test(),
                &signer,
                fixture.context,
                key,
                "logs | range query_time -100 100 | limit 2",
                budget,
                destination,
                &mut RecordingSink::default(),
            )
            .expect_err("a caller key cannot be reused for changed export intent")
            .code(),
        QueryFailureCode::IdempotencyConflict
    );
    Ok(())
}

#[test]
fn a_new_caller_key_for_the_same_export_intent_creates_a_new_snapshot_and_output()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-new-key")?;
    fixture.kernel.append_log("first", 20, 1)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let source = "logs | range query_time -100 100 | limit 2";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;

    let first = service.export_pipeline_as_operation(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        positron_governance::AdministrativeIdempotencyKey::new([0x44; 16])?,
        source,
        budget,
        "configured",
        &mut RecordingSink::default(),
    )?;
    fixture.kernel.append_log("later", 21, 2)?;
    let second = service.export_pipeline_as_operation(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        positron_governance::AdministrativeIdempotencyKey::new([0x45; 16])?,
        source,
        budget,
        "configured",
        &mut RecordingSink::default(),
    )?;

    assert_ne!(first.operation_id(), second.operation_id());
    assert_ne!(first.manifest().snapshot(), second.manifest().snapshot());
    assert_ne!(
        first.manifest().output_identity(),
        second.manifest().output_identity()
    );
    assert_eq!(second.manifest().batch_count(), 2);
    Ok(())
}

#[test]
fn durable_export_recovery_rejects_another_operation_output_before_terminal_mutation()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-recovery-output-binding")?;
    fixture.kernel.append_log("first", 20, 1)?;
    fixture.kernel.append_log("second", 21, 2)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let destination = "configured";
    let source = "logs | range query_time -100 100 | limit 2";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;
    let generation = fixture.kernel.catalog_for_test().pin()?.number();

    service
        .export_pipeline_as_operation(
            fixture.kernel.catalog_for_test(),
            &signer,
            fixture.context,
            positron_governance::AdministrativeIdempotencyKey::new([0x56; 16])?,
            source,
            budget,
            destination,
            &mut InterruptingSink { writes: 0 },
        )
        .expect_err("an interrupted export leaves a running operation to recover");
    let interrupted_operation = export_operation_id(
        &fixture,
        destination,
        source,
        budget,
        generation,
        [0x56; 16],
    )?;
    let tenant = fixture
        .context
        .tenant_attribution()
        .ok_or("query context lacks tenant")?
        .tenant_id();
    let interrupted_output = positron_kernel::ExportOutput::recover_initial(
        fixture.kernel.catalog_for_test(),
        positron_kernel::ExportOutputRequest::new(
            interrupted_operation.to_bytes(),
            tenant,
            [0x7a; 16],
            export_request_digest(&fixture, destination, source, budget)?,
        )?,
        100,
    )?
    .ok_or("interrupted export output missing")?;
    let completed = service.export_pipeline_as_operation(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        positron_governance::AdministrativeIdempotencyKey::new([0x57; 16])?,
        source,
        budget,
        destination,
        &mut RecordingSink::default(),
    )?;
    let substituted_output = completed
        .manifest()
        .output_identity()
        .ok_or("completed export output missing")?;
    let audit_before_rejection = fixture
        .kernel
        .catalog_for_test()
        .governance_audit_records()?
        .len();

    assert_eq!(
        service
            .resolve_durable_export(
                fixture.kernel.catalog_for_test(),
                fixture.context,
                interrupted_operation,
                substituted_output,
                destination,
            )
            .expect_err("another export output cannot settle this operation")
            .code(),
        QueryFailureCode::Unauthorized
    );
    assert_eq!(
        positron_governance::DurableOperationAdministration::inspect(
            fixture.kernel.catalog_for_test(),
            interrupted_operation,
        )?
        .ok_or("interrupted operation missing")?
        .status(),
        positron_governance::DurableOperationStatus::Running
    );
    assert_eq!(
        fixture
            .kernel
            .catalog_for_test()
            .governance_audit_records()?
            .len(),
        audit_before_rejection,
        "a rejected output substitution must not append an operation transition"
    );

    let resumed = service.resume_durable_export(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        interrupted_operation,
        source,
        budget,
        destination,
        &mut RecordingSink::default(),
    )?;
    let recovered = service.resolve_durable_export(
        fixture.kernel.catalog_for_test(),
        fixture.context,
        interrupted_operation,
        interrupted_output.identity(),
        destination,
    )?;
    assert_eq!(recovered.operation_id(), interrupted_operation);
    assert_eq!(
        recovered.manifest().result_digest(),
        resumed.manifest().result_digest(),
        "the original output remains recoverable after rejecting the substitution"
    );
    Ok(())
}

#[test]
fn pipeline_and_sql_durable_exports_share_ordered_rows_and_budget_execution()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-sql-parity")?;
    fixture.kernel.append_log("first", 20, 1)?;
    fixture.kernel.append_log("second", 21, 2)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;
    let pipeline = service.export_pipeline_as_operation(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        positron_governance::AdministrativeIdempotencyKey::new([0x46; 16])?,
        "logs | range query_time -100 100 | limit 2",
        budget,
        "configured",
        &mut RecordingSink::default(),
    )?;
    let sql = service.export_sql_as_operation(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        positron_governance::AdministrativeIdempotencyKey::new([0x47; 16])?,
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 ORDER BY query_time, commit_position LIMIT 2",
        budget,
        "configured",
        &mut RecordingSink::default(),
    )?;

    assert_eq!(pipeline.manifest().batches(), sql.manifest().batches());
    assert_eq!(
        pipeline.manifest().result_digest(),
        sql.manifest().result_digest()
    );
    assert_eq!(
        pipeline.manifest().terminal().stats().cumulative_budget(),
        sql.manifest().terminal().stats().cumulative_budget()
    );
    assert_ne!(
        pipeline.manifest().request_digest(),
        sql.manifest().request_digest()
    );
    Ok(())
}

#[test]
fn caller_key_retry_recovers_the_initial_cursor_after_descriptor_publication_failure()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-initial-recovery")?;
    fixture.kernel.append_log("first", 20, 1)?;
    let clock = TestClock::shared(100);
    let service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        clock.clone(),
    )
    .with_export_destination_resolver(Arc::new(TestExportDestinationResolver));
    let signer = fixture.export_manifest_signer()?;
    let source = "logs | range query_time -100 100 | limit 1";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;
    let key = positron_governance::AdministrativeIdempotencyKey::new([0x48; 16])?;
    let generation = fixture.kernel.catalog_for_test().pin()?.number();
    let operation_id = export_operation_id(
        &fixture,
        "configured",
        source,
        budget,
        generation,
        key.to_bytes(),
    )?;

    let failure = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        4,
        || {
            service.export_pipeline_as_operation(
                fixture.kernel.catalog_for_test(),
                &signer,
                fixture.context,
                key,
                source,
                budget,
                "configured",
                &mut RecordingSink::default(),
            )
        },
    )
    .expect_err("descriptor publication acknowledgement is ambiguous");
    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    let tenant = fixture
        .context
        .tenant_attribution()
        .ok_or("query context lacks tenant")?
        .tenant_id();
    let request = positron_kernel::ExportOutputRequest::new(
        operation_id.to_bytes(),
        tenant,
        [0x7a; 16],
        export_request_digest(&fixture, "configured", source, budget)?,
    )?;
    let recovered = positron_kernel::ExportOutput::recover_initial(
        fixture.kernel.catalog_for_test(),
        request,
        100,
    )?
    .ok_or("the synchronized initial cursor must survive descriptor failure")?;
    assert!(
        recovered
            .initial_cursor(fixture.kernel.catalog_for_test(), 100)?
            .is_some()
    );
    let original_snapshot = recovered.binding();
    fixture.kernel.append_log("later", 21, 2)?;

    let receipt = service.export_pipeline_as_operation(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        key,
        source,
        budget,
        "configured",
        &mut RecordingSink::default(),
    )?;
    assert_eq!(receipt.operation_id(), operation_id);
    assert_eq!(
        receipt.manifest().snapshot().identity(),
        original_snapshot.snapshot_identity()
    );
    assert_eq!(
        receipt.manifest().snapshot().generation(),
        original_snapshot.snapshot_generation()
    );
    Ok(())
}

#[test]
fn terminal_audit_publication_failure_is_reported_as_store_unavailable()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-terminal-audit-failure")?;
    fixture.kernel.append_log("first", 20, 1)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let key = positron_governance::AdministrativeIdempotencyKey::new([0x49; 16])?;
    let mut sink = RecordingSink::default();

    let failure = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        2,
        || {
            service.export_pipeline_as_operation(
                fixture.kernel.catalog_for_test(),
                &signer,
                fixture.context,
                key,
                "unrecognized pipeline syntax",
                QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60).expect("valid budget"),
                "configured",
                &mut sink,
            )
        },
    )
    .expect_err("a failed terminal audit publication leaves the caller outcome unknown");

    assert_eq!(failure.code(), QueryFailureCode::StoreUnavailable);
    assert!(sink.batches.is_empty());
    Ok(())
}

#[test]
fn kernel_owned_export_output_recovers_the_same_batch_receipts_after_restart()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-output-restart")?;
    fixture.kernel.append_log("catalog-basis", 20, 1)?;
    let tenant = fixture
        .context
        .tenant_attribution()
        .ok_or("query context lacks tenant")?
        .tenant_id();
    let binding = positron_kernel::ExportOutputBinding::new(
        tenant,
        [0x51; 16],
        [0x61; 32],
        [0x62; 32],
        1,
        1,
        positron_kernel::SnapshotLeaseId::new([0x63; 16])?,
        10,
        11,
    )?;
    let mut output =
        positron_kernel::ExportOutput::create(fixture.kernel.catalog_for_test(), binding)
            .map_err(|failure| format!("create descriptor: {failure:?}"))?;
    output
        .append_batch(
            fixture.kernel.catalog_for_test(),
            10,
            0,
            [0x71; 32],
            b"bounded canonical batch",
            Some(b"authenticated cursor"),
        )
        .map_err(|failure| format!("append protected batch: {failure:?}"))?;
    let recovered =
        positron_kernel::ExportOutput::reopen(fixture.kernel.catalog_for_test(), output.identity())
            .map_err(|failure| format!("reopen descriptor: {failure:?}"))?;
    assert_eq!(recovered.binding(), binding);
    assert_eq!(
        recovered
            .read_batch(fixture.kernel.catalog_for_test(), 10, 0)
            .map_err(|failure| format!("read recovered payload: {failure:?}"))?,
        b"bounded canonical batch"
    );
    let checkpoint = recovered
        .latest_checkpoint(fixture.kernel.catalog_for_test(), 10)
        .map_err(|failure| format!("read recovered checkpoint: {failure:?}"))?
        .ok_or("recoverable batch checkpoint missing")?;
    assert_eq!(checkpoint.receipt().digest(), [0x71; 32]);
    assert_eq!(
        checkpoint.continuation_cursor().as_deref(),
        Some(b"authenticated cursor" as &[u8])
    );
    Ok(())
}

#[test]
fn durable_export_resumes_the_original_snapshot_and_cumulative_cursor_after_interruption()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-resume")?;
    fixture.kernel.append_log("first", 20, 1)?;
    fixture.kernel.append_log("second", 21, 2)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let destination = "configured";
    let source = "logs | range query_time -100 100 | limit 2";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;
    let accepted_generation = fixture.kernel.catalog_for_test().pin()?.number();
    let mut interrupted = InterruptingSink { writes: 0 };

    let failure = service
        .export_pipeline_as_operation(
            fixture.kernel.catalog_for_test(),
            &signer,
            fixture.context,
            positron_governance::AdministrativeIdempotencyKey::new([0x53; 16])?,
            source,
            budget,
            destination,
            &mut interrupted,
        )
        .expect_err("an acknowledgement-ambiguous sink failure leaves the operation resumable");
    assert_eq!(
        failure.code(),
        positron_query::QueryFailureCode::InvalidBudget
    );
    assert_eq!(interrupted.writes, 1);

    let mut request_payload = Vec::new();
    request_payload.extend_from_slice(&[0x7a; 16]);
    request_payload.push(1);
    for limit in [
        budget.scanned_bytes(),
        budget.decoded_records(),
        budget.output_rows(),
        budget.output_bytes(),
        budget.memory_bytes(),
        budget.cpu_work_units(),
        budget.wall_seconds(),
        budget.maximum_time_range_nanoseconds(),
    ] {
        request_payload.extend_from_slice(&limit.to_be_bytes());
    }
    request_payload.extend_from_slice(source.as_bytes());
    let request_digest = fixture
        .kernel
        .ledger()?
        .control_tokens()
        .digest_query_cursor(b"query-export-request-v1", &request_payload)?;
    let request = positron_governance::DurableOperationRequest::query_export(
        fixture.context.principal_id(),
        fixture
            .context
            .tenant_attribution()
            .ok_or("query context lacks tenant")?
            .tenant_id(),
        positron_governance::AdministrativeIdempotencyKey::new([0x53; 16])?,
        [0x7a; 16],
        accepted_generation,
        1,
        request_digest,
    )?;
    let operation_id = request.operation_id();
    let operation = positron_governance::DurableOperationAdministration::inspect(
        fixture.kernel.catalog_for_test(),
        operation_id,
    )?
    .ok_or("interrupted operation missing")?;
    assert_eq!(
        operation.status(),
        positron_governance::DurableOperationStatus::Running
    );
    let substituted_budget = QueryBudget::new(1_048_576, 16, 15, 1_048_576, 16_384, 60)?;
    assert_eq!(
        service
            .resume_durable_export(
                fixture.kernel.catalog_for_test(),
                &signer,
                fixture.context,
                operation_id,
                source,
                substituted_budget,
                destination,
                &mut RecordingSink::default(),
            )
            .expect_err("a changed cumulative budget is not the accepted export request")
            .code(),
        positron_query::QueryFailureCode::Unauthorized
    );
    let mut resumed = RecordingSink::default();
    let receipt = service.resume_durable_export(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        operation_id,
        source,
        budget,
        destination,
        &mut resumed,
    )?;
    assert_eq!(resumed.batches.len(), 1);
    assert_eq!(resumed.batches[0].1, 1);
    assert_eq!(receipt.manifest().batch_count(), 2);
    assert!(receipt.manifest().signature().is_some());
    assert_eq!(receipt.manifest().terminal().stats().resume_count(), 1);
    assert_eq!(
        receipt.manifest().terminal().stats().cumulative_budget(),
        budget
    );
    assert_eq!(
        positron_governance::DurableOperationAdministration::inspect(
            fixture.kernel.catalog_for_test(),
            operation_id,
        )?
        .ok_or("resumed operation missing")?
        .status(),
        positron_governance::DurableOperationStatus::Succeeded
    );
    Ok(())
}

#[test]
fn another_same_tenant_query_principal_cannot_resume_or_terminally_mutate_an_owners_export()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-other-principal")?;
    fixture.kernel.append_log("first", 20, 1)?;
    fixture.kernel.append_log("second", 21, 2)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let destination = "configured";
    let source = "logs | range query_time -100 100 | limit 2";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;
    let generation = fixture.kernel.catalog_for_test().pin()?.number();
    service
        .export_pipeline_as_operation(
            fixture.kernel.catalog_for_test(),
            &signer,
            fixture.context,
            positron_governance::AdministrativeIdempotencyKey::new([0x91; 16])?,
            source,
            budget,
            destination,
            &mut InterruptingSink { writes: 0 },
        )
        .expect_err("checkpointed observer failure");
    let operation_id = export_operation_id(
        &fixture,
        destination,
        source,
        budget,
        generation,
        [0x91; 16],
    )?;
    let other_context = fixture.additional_query_context()?;
    let audit_before = fixture
        .kernel
        .catalog_for_test()
        .governance_audit_records()?
        .len();

    assert_eq!(
        service
            .resume_durable_export(
                fixture.kernel.catalog_for_test(),
                &signer,
                other_context,
                operation_id,
                source,
                budget,
                destination,
                &mut RecordingSink::default(),
            )
            .expect_err("a different valid query principal is not the export owner")
            .code(),
        QueryFailureCode::Unauthorized
    );
    assert_eq!(
        positron_governance::DurableOperationAdministration::inspect(
            fixture.kernel.catalog_for_test(),
            operation_id,
        )?
        .ok_or("operation missing")?
        .status(),
        positron_governance::DurableOperationStatus::Running
    );
    assert_eq!(
        fixture
            .kernel
            .catalog_for_test()
            .governance_audit_records()?
            .len(),
        audit_before,
        "a rejected different principal must not append an owner operation transition"
    );
    Ok(())
}

#[test]
fn expired_lease_after_checkpoint_and_service_restart_fails_once_without_leaving_running()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-expired-restart")?;
    fixture.kernel.append_log("first", 20, 1)?;
    fixture.kernel.append_log("second", 21, 2)?;
    let clock = TestClock::shared(100);
    let service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        clock.clone(),
    )
    .with_export_destination_resolver(Arc::new(TestExportDestinationResolver));
    let signer = fixture.export_manifest_signer()?;
    let destination = "configured";
    let source = "logs | range query_time -100 100 | limit 2";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;
    let generation = fixture.kernel.catalog_for_test().pin()?.number();
    service
        .export_pipeline_as_operation(
            fixture.kernel.catalog_for_test(),
            &signer,
            fixture.context,
            positron_governance::AdministrativeIdempotencyKey::new([0x92; 16])?,
            source,
            budget,
            destination,
            &mut InterruptingSink { writes: 0 },
        )
        .expect_err("checkpointed observer failure");
    let operation_id = export_operation_id(
        &fixture,
        destination,
        source,
        budget,
        generation,
        [0x92; 16],
    )?;
    let tenant = fixture
        .context
        .tenant_attribution()
        .ok_or("query context lacks tenant")?
        .tenant_id();
    let output = positron_kernel::ExportOutput::recover_initial(
        fixture.kernel.catalog_for_test(),
        positron_kernel::ExportOutputRequest::new(
            operation_id.to_bytes(),
            tenant,
            [0x7a; 16],
            export_request_digest(&fixture, destination, source, budget)?,
        )?,
        100,
    )
    .map_err(|failure| format!("find checkpointed durable output: {failure:?}"))?
    .ok_or("checkpointed durable output missing")?;
    assert!(
        output
            .latest_checkpoint(fixture.kernel.catalog_for_test(), 100)
            .map_err(|failure| format!("read protected checkpoint: {failure:?}"))?
            .is_some(),
        "the interrupted first batch must have a protected recovery checkpoint"
    );

    let audit_before_expiry = fixture
        .kernel
        .catalog_for_test()
        .governance_audit_records()?
        .len();
    clock.set(161);
    let restarted_service = zero_work_clock_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        clock,
    )
    .with_export_destination_resolver(Arc::new(TestExportDestinationResolver));
    assert_eq!(
        restarted_service
            .resume_durable_export(
                fixture.kernel.catalog_for_test(),
                &signer,
                fixture.context,
                operation_id,
                source,
                budget,
                destination,
                &mut RecordingSink::default(),
            )
            .expect_err("the persisted snapshot lease has expired after restart")
            .code(),
        QueryFailureCode::SnapshotExpired
    );
    assert_eq!(
        positron_governance::DurableOperationAdministration::inspect(
            fixture.kernel.catalog_for_test(),
            operation_id,
        )?
        .ok_or("operation missing")?
        .status(),
        positron_governance::DurableOperationStatus::Failed
    );
    let audit_after_failure = fixture
        .kernel
        .catalog_for_test()
        .governance_audit_records()?
        .len();
    assert_eq!(
        audit_after_failure,
        audit_before_expiry + 1,
        "expiry must produce one audited terminal failure"
    );
    assert_eq!(
        restarted_service
            .resume_durable_export(
                fixture.kernel.catalog_for_test(),
                &signer,
                fixture.context,
                operation_id,
                source,
                budget,
                destination,
                &mut RecordingSink::default(),
            )
            .expect_err("a terminal expired export cannot be resumed")
            .code(),
        QueryFailureCode::SnapshotExpired
    );
    assert_eq!(
        fixture
            .kernel
            .catalog_for_test()
            .governance_audit_records()?
            .len(),
        audit_after_failure,
        "repeating expiry recovery must not duplicate its audit transition"
    );
    Ok(())
}

#[test]
fn revoked_owner_closes_its_checkpointed_export_with_an_audited_terminal_state()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-revoked-owner")?;
    fixture.kernel.append_log("first", 20, 1)?;
    fixture.kernel.append_log("second", 21, 2)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let destination = "configured";
    let source = "logs | range query_time -100 100 | limit 2";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;
    let generation = fixture.kernel.catalog_for_test().pin()?.number();
    service
        .export_pipeline_as_operation(
            fixture.kernel.catalog_for_test(),
            &signer,
            fixture.context,
            positron_governance::AdministrativeIdempotencyKey::new([0x93; 16])?,
            source,
            budget,
            destination,
            &mut InterruptingSink { writes: 0 },
        )
        .expect_err("checkpointed observer failure");
    let operation_id = export_operation_id(
        &fixture,
        destination,
        source,
        budget,
        generation,
        [0x93; 16],
    )?;
    fixture.revoke_query_context()?;
    let failure = service
        .resume_durable_export(
            fixture.kernel.catalog_for_test(),
            &signer,
            fixture.context,
            operation_id,
            source,
            budget,
            destination,
            &mut RecordingSink::default(),
        )
        .expect_err("revoked context");
    assert_eq!(
        positron_governance::DurableOperationAdministration::inspect(
            fixture.kernel.catalog_for_test(),
            operation_id
        )?
        .ok_or("operation missing")?
        .status(),
        positron_governance::DurableOperationStatus::Failed
    );
    assert_eq!(failure.code(), QueryFailureCode::AuthorizationChanged);
    Ok(())
}

#[test]
fn suspended_tenant_closes_its_checkpointed_export_with_an_audited_terminal_state()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-suspended-tenant")?;
    fixture.kernel.append_log("first", 20, 1)?;
    fixture.kernel.append_log("second", 21, 2)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let destination = "configured";
    let source = "logs | range query_time -100 100 | limit 2";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;
    let generation = fixture.kernel.catalog_for_test().pin()?.number();
    service
        .export_pipeline_as_operation(
            fixture.kernel.catalog_for_test(),
            &signer,
            fixture.context,
            positron_governance::AdministrativeIdempotencyKey::new([0x95; 16])?,
            source,
            budget,
            destination,
            &mut InterruptingSink { writes: 0 },
        )
        .expect_err("checkpointed observer failure");
    let operation_id = export_operation_id(
        &fixture,
        destination,
        source,
        budget,
        generation,
        [0x95; 16],
    )?;
    fixture.suspend_query_tenant()?;
    let failure = service
        .resume_durable_export(
            fixture.kernel.catalog_for_test(),
            &signer,
            fixture.context,
            operation_id,
            source,
            budget,
            destination,
            &mut RecordingSink::default(),
        )
        .expect_err("suspended tenant");
    assert_eq!(
        positron_governance::DurableOperationAdministration::inspect(
            fixture.kernel.catalog_for_test(),
            operation_id
        )?
        .ok_or("operation missing")?
        .status(),
        positron_governance::DurableOperationStatus::Failed
    );
    assert_eq!(failure.code(), QueryFailureCode::AuthorizationChanged);
    Ok(())
}

fn export_operation_id(
    fixture: &QueryFixture,
    destination: &str,
    source: &str,
    budget: QueryBudget,
    generation: u64,
    key: [u8; 16],
) -> Result<positron_governance::OperationId, Box<dyn Error>> {
    let digest = export_request_digest(fixture, destination, source, budget)?;
    Ok(positron_governance::DurableOperationRequest::query_export(
        fixture.context.principal_id(),
        fixture
            .context
            .tenant_attribution()
            .ok_or("query context lacks tenant")?
            .tenant_id(),
        positron_governance::AdministrativeIdempotencyKey::new(key)?,
        [0x7a; 16],
        generation,
        1,
        digest,
    )?
    .operation_id())
}

fn export_request_digest(
    fixture: &QueryFixture,
    _destination: &str,
    source: &str,
    budget: QueryBudget,
) -> Result<[u8; 32], Box<dyn Error>> {
    let mut payload = [0x7a; 16].to_vec();
    payload.push(1);
    for limit in [
        budget.scanned_bytes(),
        budget.decoded_records(),
        budget.output_rows(),
        budget.output_bytes(),
        budget.memory_bytes(),
        budget.cpu_work_units(),
        budget.wall_seconds(),
        budget.maximum_time_range_nanoseconds(),
    ] {
        payload.extend_from_slice(&limit.to_be_bytes());
    }
    payload.extend_from_slice(source.as_bytes());
    Ok(fixture
        .kernel
        .ledger()?
        .control_tokens()
        .digest_query_cursor(b"query-export-request-v1", &payload)?)
}
