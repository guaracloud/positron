use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_ingest::{
    AdmissionGroupPlanFailure, AdmissionGroupPlanner, AuthenticatedOtlpLogsRequest, IngestOutcome,
    IngestPolicy, LogIngest, NativeLogCandidate, OtlpLogsReceiver, PolicyAction, PolicyPredicate,
    PolicyRule, PolicyTarget,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use positron_signals::{LogScan, LogStore, ScanLimit};
use prost::Message;

use super::policy_actions::{attributed_instance, bodies_request, ingest_and_scan};
use super::support::fixture;

struct TwoGroups([VirtualShardId; 2]);

impl AdmissionGroupPlanner for TwoGroups {
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
fn admitted_request_keeps_one_immutable_snapshot_across_groups() -> Result<(), Box<dyn Error>> {
    let (instance, context) = attributed_instance("snapshot-policy")?;
    let first_fixture = fixture(instance.default_tenant_id())?;
    let old = body_policy(31, PolicyAction::Redact(PolicyTarget::body()))?;
    let old_batch =
        OtlpLogsReceiver::new().decode(AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
            context,
            first_fixture.authority.governor(),
            bodies_request(&["sensitive", "sensitive"]).encode_to_vec(),
        )?)?;
    let shards = [VirtualShardId::new(72)?, VirtualShardId::new(73)?];
    let groups = old_batch.into_admission_groups(&TwoGroups(shards))?;
    let current = body_policy(32, PolicyAction::Remove(PolicyTarget::body()))?;

    let catalog = Catalog::open(
        &first_fixture.authority,
        InstanceId::new([0x74; 16])?,
        CatalogSecret::from_owned(Box::new([0x75; 32]), Box::new([0x76; 32])),
    )?;
    let ledgers = [
        ledger(&first_fixture, &catalog, shards[0], 0x77)?,
        ledger(&first_fixture, &catalog, shards[1], 0x78)?,
    ];
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(700)));
    for (ordinal, (group, ledger)) in groups.zip(ledgers.iter()).enumerate() {
        assert!(matches!(
            LogIngest::new(
                &first_fixture.authority,
                ledger,
                &clock,
                &old,
                first_fixture.tenant,
                group.shard(),
                super::schema_support::session(&first_fixture)?,
            )
            .accept(
                group.into_batch(),
                StoreBlockIdentity::new([0x79 + u8::try_from(ordinal)?; 16])?
            ),
            IngestOutcome::Full(_)
        ));
    }
    for ledger in &ledgers {
        let snapshot = ledger.snapshot()?;
        let result = LogStore::new().scan(
            first_fixture.authority.governor(),
            first_fixture.tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
        )?;
        assert!(
            result.records()[0]
                .body()
                .is_some_and(|body| body.is_null())
        );
        assert_eq!(result.records()[0].policy_provenance().generation(), 31);
    }

    let refreshed_fixture = fixture(instance.default_tenant_id())?;
    let new_batch =
        OtlpLogsReceiver::new().decode(AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
            context,
            refreshed_fixture.authority.governor(),
            bodies_request(&["sensitive"]).encode_to_vec(),
        )?)?;
    let new_result = ingest_and_scan(&refreshed_fixture, new_batch, &current, 82)?;
    assert!(new_result.records()[0].body().is_none());
    assert_eq!(new_result.records()[0].policy_provenance().generation(), 32);
    Ok(())
}

fn ledger<'authority, 'catalog>(
    fixture: &'authority super::support::Fixture,
    catalog: &'catalog Catalog<'authority>,
    shard: VirtualShardId,
    marker: u8,
) -> Result<ActiveSegmentLedger<'authority, 'catalog>, Box<dyn Error>> {
    Ok(ActiveSegmentLedger::open(
        &fixture.authority,
        catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([marker; 32])),
    )?)
}

fn body_policy(generation: u64, action: PolicyAction) -> Result<IngestPolicy, Box<dyn Error>> {
    Ok(IngestPolicy::compile(
        generation,
        vec![PolicyRule::new(
            "body-policy",
            vec![PolicyPredicate::body_exact_text("sensitive")?],
            action,
        )?],
    )?)
}
