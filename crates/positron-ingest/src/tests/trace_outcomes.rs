use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::identity::{PrincipalId, Scope, TenantAttribution, TenantId};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, AppendCancellation, Catalog, CatalogSecret, InstanceId, ResourceAmounts,
    ResourceReservation, SegmentProtectionKey, SegmentScope, StoreBlockIdentity, WorkClaim,
    WorkKind,
};
use positron_signals::{ScanLimit, TraceScan, TraceStore};
use prost::Message;

use super::support::fixture;
use crate::{
    AuthenticatedOtlpTracesRequest, IngestFailureCode, IngestOutcome, OtlpTracesReceiver,
    TraceIngest,
};

#[test]
fn trace_ingest_fallback_reservation_commits_and_can_be_read_immediately()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let shard = VirtualShardId::new(111)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &fixture.authority,
        &fixture.retention_time,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xb4; 32])),
    )?;
    let baseline = fixture.authority.governor().inspect()?.outstanding_total();
    let outcome = TraceIngest::new(&fixture.authority, &ledger, fixture.tenant, shard).accept(
        trace_batch("fallback"),
        StoreBlockIdentity::new([0xb5; 16])?,
    );
    let receipt = match outcome {
        IngestOutcome::Full(committed) => committed.receipt(),
        other => return Err(format!("expected full trace outcome, got {other:?}").into()),
    };
    assert_eq!(receipt.position().value(), 1);
    assert_eq!(
        fixture.authority.governor().inspect()?.outstanding_total(),
        baseline
    );
    assert_eq!(
        TraceStore::new()
            .scan(
                fixture.authority.governor(),
                fixture.tenant,
                &ledger.snapshot()?,
                TraceScan::all(ScanLimit::new(1)?),
            )?
            .observations()
            .len(),
        1
    );
    assert_eq!(
        outcome.producer_disconnected_after_commit(),
        IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable)
    );
    let conflict = TraceIngest::new(&fixture.authority, &ledger, fixture.tenant, shard).accept(
        trace_batch("different-payload"),
        StoreBlockIdentity::new([0xb5; 16])?,
    );
    assert_eq!(
        conflict,
        IngestOutcome::Permanent(IngestFailureCode::IdempotencyConflict)
    );
    assert_eq!(ledger.snapshot()?.blocks().len(), 1);
    Ok(())
}

#[test]
fn trace_ingest_capacity_refusal_releases_fallback_work_without_ledger_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xc1; 16])?,
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
    )?;
    let shard = VirtualShardId::new(112)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &fixture.authority,
        &fixture.retention_time,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xc4; 32])),
    )?;
    let baseline = fixture.authority.governor().inspect()?.outstanding_total();
    let claim = WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        ResourceAmounts::new([1_048_576, 1, 1, 1_048_576, 1, 0, 1, 1, 1, 4, 1_048_576]),
    )?;
    let mut held = Vec::new();
    while let Ok(reservation) = fixture.authority.governor().reserve(claim) {
        held.push(reservation);
    }
    assert!(!held.is_empty());

    let outcome = TraceIngest::new(&fixture.authority, &ledger, fixture.tenant, shard).accept(
        trace_batch("capacity-refused"),
        StoreBlockIdentity::new([0xc5; 16])?,
    );
    assert_eq!(
        outcome,
        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
    );
    assert!(ledger.snapshot()?.blocks().is_empty());
    drop(held);
    assert_eq!(
        fixture.authority.governor().inspect()?.outstanding_total(),
        baseline
    );

    let retry = TraceIngest::new(&fixture.authority, &ledger, fixture.tenant, shard).accept(
        trace_batch("capacity-retry"),
        StoreBlockIdentity::new([0xc6; 16])?,
    );
    assert!(matches!(retry, IngestOutcome::Full(_)));
    Ok(())
}

#[test]
fn trace_ingest_resizes_incoming_admission_or_releases_it_without_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xc7; 16])?,
        CatalogSecret::from_owned(Box::new([0xc8; 32]), Box::new([0xc9; 32])),
    )?;
    let shard = VirtualShardId::new(115)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &fixture.authority,
        &fixture.retention_time,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xca; 32])),
    )?;
    let baseline = fixture.authority.governor().inspect()?.outstanding_total();
    let full_amounts = ResourceAmounts::new([1_049_600, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1_048_576]);
    let full_reservation = fixture.authority.governor().reserve(WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        full_amounts,
    )?)?;
    let committed = TraceIngest::new(&fixture.authority, &ledger, fixture.tenant, shard).accept(
        trace_batch_with_reservation(full_reservation),
        StoreBlockIdentity::new([0xcb; 16])?,
    );
    assert!(matches!(committed, IngestOutcome::Full(_)));
    assert_eq!(ledger.snapshot()?.blocks().len(), 1);
    assert_eq!(
        fixture.authority.governor().inspect()?.outstanding_total(),
        baseline
    );

    let decode_amounts = ResourceAmounts::new([512, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0]);
    let undersized = fixture.authority.governor().reserve(WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        decode_amounts,
    )?)?;
    let with_undersized = fixture.authority.governor().inspect()?.outstanding_total();
    let mut held = Vec::new();
    while let Ok(reservation) = fixture.authority.governor().reserve(WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        full_amounts,
    )?) {
        held.push(reservation);
    }
    let held_total = fixture.authority.governor().inspect()?.outstanding_total();
    let refused = TraceIngest::new(&fixture.authority, &ledger, fixture.tenant, shard).accept(
        trace_batch_with_reservation(undersized),
        StoreBlockIdentity::new([0xcc; 16])?,
    );
    assert_eq!(
        refused,
        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
    );
    assert!(held_total > baseline);
    assert_eq!(ledger.snapshot()?.blocks().len(), 1);
    assert_eq!(
        fixture.authority.governor().inspect()?.outstanding_total(),
        held_total - (with_undersized - baseline)
    );
    drop(held);
    assert_eq!(
        fixture.authority.governor().inspect()?.outstanding_total(),
        baseline
    );

    let retry = TraceIngest::new(&fixture.authority, &ledger, fixture.tenant, shard).accept(
        trace_batch("incoming-reservation-retry"),
        StoreBlockIdentity::new([0xcd; 16])?,
    );
    assert!(matches!(retry, IngestOutcome::Full(_)));
    assert_eq!(
        fixture.authority.governor().inspect()?.outstanding_total(),
        baseline
    );
    Ok(())
}

#[test]
fn trace_ingest_rejects_wrong_identity_or_empty_batches_without_drift_then_reuses_ledger()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xd1; 16])?,
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )?;
    let shard = VirtualShardId::new(113)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &fixture.authority,
        &fixture.retention_time,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xd4; 32])),
    )?;
    let baseline = fixture.authority.governor().inspect()?.outstanding_total();
    let wrong_tenant = TenantId::from_bytes([0xd5; 16])?;
    let wrong_attribution = TenantAttribution::new(
        PrincipalId::from_bytes([1; 16])?,
        Scope::Ingest,
        wrong_tenant,
    )?;
    let wrong = TraceIngest::new(&fixture.authority, &ledger, fixture.tenant, shard).accept(
        trace_batch_with_attribution("wrong-tenant", wrong_attribution),
        StoreBlockIdentity::new([0xd6; 16])?,
    );
    assert_eq!(
        wrong,
        IngestOutcome::Permanent(IngestFailureCode::TenantConflict)
    );

    let empty = TraceIngest::new(&fixture.authority, &ledger, fixture.tenant, shard)
        .accept(empty_batch(), StoreBlockIdentity::new([0xd7; 16])?);
    assert_eq!(
        empty,
        IngestOutcome::Permanent(IngestFailureCode::InvalidRecord)
    );
    assert!(ledger.snapshot()?.blocks().is_empty());
    assert_eq!(
        fixture.authority.governor().inspect()?.outstanding_total(),
        baseline
    );

    let logs_ledger = ActiveSegmentLedger::open_with_retention_time(
        &fixture.authority,
        &fixture.retention_time,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0xd9; 32])),
    )?;
    let after_ledger_open = fixture.authority.governor().inspect()?.outstanding_total();
    let wrong_signal = TraceIngest::new(&fixture.authority, &logs_ledger, fixture.tenant, shard)
        .accept(
            trace_batch("wrong-signal"),
            StoreBlockIdentity::new([0xda; 16])?,
        );
    assert_eq!(
        wrong_signal,
        IngestOutcome::Permanent(IngestFailureCode::InvalidRecord)
    );
    assert!(logs_ledger.snapshot()?.blocks().is_empty());
    assert_eq!(
        fixture.authority.governor().inspect()?.outstanding_total(),
        after_ledger_open
    );

    let valid = TraceIngest::new(&fixture.authority, &ledger, fixture.tenant, shard).accept(
        trace_batch("reused-after-rejection"),
        StoreBlockIdentity::new([0xd8; 16])?,
    );
    assert!(matches!(valid, IngestOutcome::Full(_)));
    assert_eq!(ledger.snapshot()?.blocks().len(), 1);
    Ok(())
}

#[test]
fn trace_ingest_cancellation_is_retryable_before_reservation_and_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xe1; 16])?,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let shard = VirtualShardId::new(114)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &fixture.authority,
        &fixture.retention_time,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xe4; 32])),
    )?;
    let baseline = fixture.authority.governor().inspect()?.outstanding_total();
    let cancellation = AppendCancellation::new();
    cancellation.cancel();
    let outcome = TraceIngest::new(&fixture.authority, &ledger, fixture.tenant, shard)
        .accept_cancellable(
            trace_batch("cancelled"),
            StoreBlockIdentity::new([0xe5; 16])?,
            &cancellation,
        );
    assert_eq!(
        outcome,
        IngestOutcome::Retryable(IngestFailureCode::Cancelled)
    );
    assert!(ledger.snapshot()?.blocks().is_empty());
    assert_eq!(
        fixture.authority.governor().inspect()?.outstanding_total(),
        baseline
    );
    Ok(())
}

fn trace_batch(name: &str) -> crate::NativeSpanBatch<'static> {
    trace_batch_with_attribution(name, attribution())
}

fn trace_batch_with_reservation<'authority>(
    reservation: ResourceReservation<'authority>,
) -> crate::NativeSpanBatch<'authority> {
    let (_, records, profile, _, receiver) = trace_batch("incoming-reservation").into_parts();
    crate::NativeSpanBatch::new(
        attribution(),
        records,
        profile,
        0,
        Some(reservation),
        receiver,
    )
    .expect("incoming reservation should cover decoded trace batch")
}

fn trace_batch_with_attribution(
    name: &str,
    attribution: TenantAttribution,
) -> crate::NativeSpanBatch<'static> {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0xf1; 16],
                    span_id: vec![0xf2; 8],
                    name: name.to_owned(),
                    start_time_unix_nano: 10,
                    end_time_unix_nano: 20,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
            attribution,
            request.encode_to_vec(),
        ))
        .expect("valid trace fixture")
}

fn empty_batch() -> crate::NativeSpanBatch<'static> {
    OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
            attribution(),
            ExportTraceServiceRequest::default().encode_to_vec(),
        ))
        .expect("empty structural trace fixture")
}

fn attribution() -> TenantAttribution {
    TenantAttribution::new(
        PrincipalId::from_bytes([1; 16]).expect("principal"),
        Scope::Ingest,
        TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("trace attribution")
}
