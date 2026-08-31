use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_ingest::{
    AdmissionGroupPlanFailure, AdmissionGroupPlanner, AuthenticatedOtlpLogsRequest,
    IngestFailureCode, IngestOutcome, IngestPolicy, LogIngest, NativeLogCandidate,
    OtlpLogsReceiver,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, ResourceAmounts, SegmentProtectionKey,
    SegmentScope, StoreBlockIdentity, WorkClaim, WorkKind,
};
use prost::Message;

use super::policy_actions::{attributed_instance, bodies_request};
use super::support::fixture;

struct TwoShards([VirtualShardId; 2]);

impl AdmissionGroupPlanner for TwoShards {
    fn assigned_shard(
        &self,
        _tenant: TenantId,
        _signal: SignalKind,
        ordinal: u32,
        _record: &NativeLogCandidate,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        self.0
            .get(
                usize::try_from(ordinal)
                    .map_err(|_| AdmissionGroupPlanFailure::RecordCountExceeded)?,
            )
            .copied()
            .ok_or(AdmissionGroupPlanFailure::RecordCountExceeded)
    }
}

#[test]
fn later_group_capacity_refusal_wins_before_policy_and_never_rolls_back_prior_commit()
-> Result<(), Box<dyn Error>> {
    let (instance, context) = attributed_instance("capacity-policy")?;
    let fixture = fixture(instance.default_tenant_id())?;
    let batch =
        OtlpLogsReceiver::new().decode(AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
            context,
            fixture.authority.governor(),
            bodies_request(&["commit-first", "policy-reject-later"]).encode_to_vec(),
        )?)?;
    let shards = [VirtualShardId::new(91)?, VirtualShardId::new(92)?];
    let mut groups = batch.into_admission_groups(&TwoShards(shards))?;
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x91; 16])?,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let policy = IngestPolicy::reject_exact_text_body(33, "reject-later", "policy-reject-later")?;
    let first = groups.next().ok_or("missing first group")?;
    let second = groups.next().ok_or("missing second group")?;
    let first_ledger = ledger(&fixture, &catalog, first.shard(), 0x95)?;
    let second_ledger = ledger(&fixture, &catalog, second.shard(), 0x97)?;
    let schema = super::schema_support::session(&fixture)?;
    assert!(matches!(
        LogIngest::new(
            &fixture.authority,
            &first_ledger,
            &policy,
            fixture.tenant,
            first.shard(),
            schema.clone(),
        )
        .accept(first.into_batch(), StoreBlockIdentity::new([0x96; 16])?),
        IngestOutcome::Full(_)
    ));
    let before_refusal = schema.checkpoint()?;

    let claim = WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        ResourceAmounts::new([1_000_000, 1, 1, 1_000_000, 1, 1, 1, 1, 1, 1, 100_000]),
    )?;
    let mut held = Vec::new();
    while let Ok(reservation) = fixture.authority.governor().reserve(claim) {
        held.push(reservation);
    }
    assert_eq!(
        LogIngest::new(
            &fixture.authority,
            &second_ledger,
            &policy,
            fixture.tenant,
            second.shard(),
            schema.clone(),
        )
        .accept(second.into_batch(), StoreBlockIdentity::new([0x98; 16])?),
        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
    );
    assert_eq!(first_ledger.snapshot()?.blocks().len(), 1);
    assert!(second_ledger.snapshot()?.blocks().is_empty());
    let after_refusal = schema.checkpoint()?;
    assert_eq!(after_refusal.entry_count(), before_refusal.entry_count());
    assert_eq!(
        after_refusal.overflow_record_count(),
        before_refusal.overflow_record_count()
    );
    assert_eq!(
        after_refusal.catalog_bytes(),
        before_refusal.catalog_bytes()
    );
    drop(held);
    Ok(())
}

fn ledger<'authority, 'catalog>(
    fixture: &'authority super::support::Fixture,
    catalog: &'catalog Catalog<'authority>,
    shard: VirtualShardId,
    marker: u8,
) -> Result<ActiveSegmentLedger<'authority, 'catalog>, Box<dyn Error>> {
    Ok(ActiveSegmentLedger::open_with_retention_time(
        &fixture.authority,
        &fixture.retention_time,
        catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([marker; 32])),
    )?)
}
