use std::error::Error;

use positron_query::{ExportDestination, ExportManifest, ExportSink, QueryBatch, QueryBudget};

use super::terminal_and_bounds::QueryFixture;

#[derive(Default)]
struct RecordingSink {
    started: bool,
    batches: Vec<([u8; 16], u64, [u8; 32])>,
}

struct InterruptingSink {
    writes: usize,
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
fn durable_export_writes_each_deterministic_batch_to_its_bound_destination_and_signs_manifest()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-manifest")?;
    fixture.kernel.append_log("first", 20, 1)?;
    fixture.kernel.append_log("second", 21, 2)?;
    let service = fixture.service(1)?;
    let destination = ExportDestination::new([0x7a; 16])?;
    let mut sink = RecordingSink::default();

    let manifest: ExportManifest = service.export_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 2",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?,
        destination,
        &mut sink,
    )?;

    assert_eq!(sink.batches.len(), 2);
    assert!(
        sink.started,
        "destination must bind the snapshot before batch output"
    );
    assert!(
        sink.batches
            .iter()
            .all(|(actual, _, _)| *actual == destination.identity())
    );
    assert_eq!(manifest.destination(), destination);
    assert_eq!(manifest.batch_count(), 2);
    assert_ne!(manifest.result_digest(), [0; 32]);
    service.verify_export_manifest(&manifest)?;
    assert_eq!(
        service
            .verify_export_manifest_for_destination(&manifest, ExportDestination::new([0x7b; 16])?)
            .expect_err("manifest must not validate for a substituted output identity")
            .code(),
        positron_query::QueryFailureCode::Unauthorized
    );
    Ok(())
}

#[test]
fn durable_export_records_a_catalog_backed_terminal_operation_after_the_signed_manifest()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("durable-export-operation")?;
    fixture.kernel.append_log("accepted", 20, 1)?;
    let service = fixture.service(1)?;
    let signer = fixture.export_manifest_signer()?;
    let destination = ExportDestination::new([0x5a; 16])?;
    let mut sink = RecordingSink::default();

    let receipt = service.export_pipeline_as_operation(
        fixture.kernel.catalog_for_test(),
        &signer,
        fixture.context,
        "logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?,
        destination,
        &mut sink,
    )?;

    assert_eq!(receipt.manifest().destination(), destination);
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
    assert_eq!(output.binding().destination(), destination.identity());
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
        ExportDestination::new([0x51; 16])?.identity(),
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
    let destination = ExportDestination::new([0x53; 16])?;
    let source = "logs | range query_time -100 100 | limit 2";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)?;
    let accepted_generation = fixture.kernel.catalog_for_test().pin()?.number();
    let mut interrupted = InterruptingSink { writes: 0 };

    let failure = service
        .export_pipeline_as_operation(
            fixture.kernel.catalog_for_test(),
            &signer,
            fixture.context,
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
    request_payload.extend_from_slice(&destination.identity());
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
    let mut idempotency = [0_u8; 16];
    idempotency.copy_from_slice(&request_digest[..16]);
    let request = positron_governance::DurableOperationRequest::query_export(
        fixture.context.principal_id(),
        positron_governance::AdministrativeIdempotencyKey::new(idempotency)?,
        destination.identity(),
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
