use positron_domain::routing::SignalKind;
use positron_ingest::{
    AdmissionGroupOutcome, AuthenticatedOtlpLogsRequest, IngestFailureCode, IngestOutcome,
    IngestRequestOutcome, LogIngest, NativeLogBatch, OtlpLogsReceiver,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, LedgerFailureCode, LifecycleClock, SegmentScope,
    StoreBlockIdentity, SystemLifecycleClockSource,
};

use super::{ServiceFailure, ServiceHandle, map_admission_group_plan_failure, map_receive_failure};

pub(super) fn ingest_authenticated<'authority>(
    services: &'authority ServiceHandle,
    request: AuthenticatedOtlpLogsRequest<'authority>,
) -> Result<IngestRequestOutcome, ServiceFailure> {
    let instance = &services.instance;
    let batch = OtlpLogsReceiver::with_value_limit_profile(instance.value_limit_profile)
        .decode(request)
        .map_err(map_receive_failure)?;
    ingest_native_batch(services, batch)
}

pub(super) fn ingest_native_batch(
    services: &ServiceHandle,
    batch: NativeLogBatch<'_>,
) -> Result<IngestRequestOutcome, ServiceFailure> {
    let instance = &services.instance;
    let policy = services
        .ingest_policy
        .pin()
        .map_err(|_| ServiceFailure::Internal)?;
    let schema = services
        .schema_sessions
        .session(instance.tenant, instance.resource_governor())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let groups = batch
        .into_admission_groups(instance.admission_group_planner.as_ref())
        .map_err(map_admission_group_plan_failure)?;
    if groups.is_empty() {
        return Ok(IngestRequestOutcome::new(Vec::new()));
    }
    #[cfg(test)]
    if let Some(backend) = services
        .receiver_test_backend
        .lock()
        .map_err(|_| ServiceFailure::Internal)?
        .clone()
    {
        return Ok(backend.ingest(groups));
    }
    let catalog = open_catalog(instance)?;
    let clock = LifecycleClock::new(SystemLifecycleClockSource);
    let mut outcomes = Vec::new();
    outcomes
        .try_reserve_exact(groups.len())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    for group in groups {
        let shard = group.shard();
        let records = group.records();
        let outcome = ingest_group(instance, &catalog, &clock, &policy, schema.clone(), group);
        outcomes.push(AdmissionGroupOutcome::new(shard, records, outcome));
    }
    drop(catalog);
    let result = IngestRequestOutcome::new(outcomes);
    if result.accepted_records() > 0 {
        services.mark_schema_dirty();
    }
    Ok(result)
}

fn open_catalog<'instance>(
    instance: &'instance crate::InitializedInstance,
) -> Result<Catalog<'instance>, ServiceFailure> {
    Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|_| ServiceFailure::StorageUnavailable)
}

fn ingest_group<S: positron_kernel::LifecycleClockSource>(
    instance: &crate::InitializedInstance,
    catalog: &Catalog<'_>,
    clock: &LifecycleClock<S>,
    policy: &positron_ingest::IngestPolicy,
    schema: positron_ingest::TenantSchemaSession,
    group: positron_ingest::NativeLogAdmissionGroup<'_>,
) -> IngestOutcome {
    let shard = group.shard();
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, shard);
    let Ok(protection) = instance.key.segment_key(instance.instance, scope) else {
        return IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable);
    };
    let ledger = match ActiveSegmentLedger::open(&instance._authority, catalog, scope, protection) {
        Ok(ledger) => ledger,
        Err(failure) if failure.code() == LedgerFailureCode::ResourceAdmissionRefused => {
            return IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable);
        },
        Err(_) => return IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
    };
    let identity = match instance
        .key
        .random_identifier()
        .ok()
        .and_then(|bytes| StoreBlockIdentity::new(bytes).ok())
    {
        Some(identity) => identity,
        None => return IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
    };
    LogIngest::new(
        &instance._authority,
        &ledger,
        clock,
        policy,
        instance.tenant,
        shard,
        schema,
    )
    .accept(group.into_batch(), identity)
}
