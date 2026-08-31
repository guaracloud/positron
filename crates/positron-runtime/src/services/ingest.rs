use positron_domain::routing::SignalKind;
use positron_governance::AuthorizedContext;
use positron_ingest::{
    AdmissionGroupOutcome, AuthenticatedOtlpLogsRequest, IngestFailureCode, IngestOutcome,
    IngestRequestOutcome, LogIngest, NativeLogBatch, OtlpLogsReceiver,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, LedgerFailureCode, SegmentScope, StoreBlockIdentity,
};

use super::{
    ServiceFailure, ServiceHandle, failure::classify_catalog_failure_code,
    failure::classify_ledger_failure_code, map_admission_group_plan_failure, map_receive_failure,
};

pub(super) fn ingest_authenticated<'authority>(
    services: &'authority ServiceHandle,
    context: AuthorizedContext,
    request: AuthenticatedOtlpLogsRequest<'authority>,
) -> Result<IngestRequestOutcome, ServiceFailure> {
    services.revalidate_ingest_context(context)?;
    let instance = &services.instance;
    let batch = OtlpLogsReceiver::with_value_limit_profile(instance.value_limit_profile)
        .decode(request)
        .map_err(map_receive_failure)?;
    ingest_native_batch(services, context, batch)
}

pub(super) fn ingest_native_batch(
    services: &ServiceHandle,
    context: AuthorizedContext,
    batch: NativeLogBatch<'_>,
) -> Result<IngestRequestOutcome, ServiceFailure> {
    services.revalidate_ingest_context(context)?;
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
    // Planning can run for an arbitrary bounded duration. Acquire the sole
    // Catalog writer only after planning and keep it through the final ledger
    // publications, so a lifecycle transition cannot pass the final identity
    // check and interleave with append while unrelated planning is blocked.
    let catalog = open_catalog(instance)?;
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    identity
        .validate_ingest_context(context)
        .map_err(|_| ServiceFailure::Unauthorized)?;
    let mut outcomes = Vec::new();
    outcomes
        .try_reserve_exact(groups.len())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    for group in groups {
        let shard = group.shard();
        let records = group.records();
        let outcome = ingest_group(instance, &catalog, &policy, schema.clone(), group);
        outcomes.push(AdmissionGroupOutcome::new(shard, records, outcome));
    }
    drop(catalog);
    Ok(IngestRequestOutcome::new(outcomes))
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
    .map_err(|failure| classify_catalog_failure_code(failure.code()))
}

pub(super) const fn map_ledger_failure_code(code: LedgerFailureCode) -> IngestFailureCode {
    match classify_ledger_failure_code(code) {
        ServiceFailure::CapacityUnavailable => IngestFailureCode::CapacityUnavailable,
        _ => IngestFailureCode::StorageUnavailable,
    }
}

fn ingest_group(
    instance: &crate::InitializedInstance,
    catalog: &Catalog<'_>,
    policy: &positron_ingest::IngestPolicy,
    schema: positron_ingest::TenantSchemaSession,
    group: positron_ingest::NativeLogAdmissionGroup<'_>,
) -> IngestOutcome {
    let shard = group.shard();
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, shard);
    let Ok(protection) = instance.key.segment_key(instance.instance, scope) else {
        return IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable);
    };
    let ledger = match ActiveSegmentLedger::open_with_retention_time(
        &instance._authority,
        &instance.retention_time,
        catalog,
        scope,
        protection,
    ) {
        Ok(ledger) => ledger,
        Err(failure) => return IngestOutcome::Retryable(map_ledger_failure_code(failure.code())),
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
        policy,
        instance.tenant,
        shard,
        schema,
    )
    .accept(group.into_batch(), identity)
}
