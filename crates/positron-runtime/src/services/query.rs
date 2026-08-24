use positron_domain::routing::SignalKind;
use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};
use positron_query::{QueryBudget, QueryService};

use super::{
    ServiceFailure, ServiceHandle, classify_catalog_failure_code, classify_ledger_failure_code,
    collect_query_bodies, map_query_failure, schema_bootstrap,
};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};

pub(super) fn query_log_bodies(
    services: &ServiceHandle,
    bearer: &str,
    shard: positron_domain::routing::VirtualShardId,
    source: &str,
    budget: QueryBudget,
) -> Result<Vec<String>, ServiceFailure> {
    let instance = &services.instance;
    let initial_identity = instance
        .durable_identity()
        .map_err(|failure| match failure.code() {
            crate::BootstrapFailureCode::KeyCustodyUnavailable => ServiceFailure::KeyUnavailable,
            crate::BootstrapFailureCode::ResourceUnavailable => ServiceFailure::CapacityUnavailable,
            crate::BootstrapFailureCode::CorruptState
            | crate::BootstrapFailureCode::IdentityMismatch => ServiceFailure::CorruptState,
            crate::BootstrapFailureCode::StorageUnavailable
            | crate::BootstrapFailureCode::CatalogUnavailable => ServiceFailure::StorageUnavailable,
            _ => ServiceFailure::Internal,
        })?;
    let context = initial_identity
        .attribute(
            &instance.key,
            PresentedCredential::parse(bearer).map_err(|_| ServiceFailure::Unauthorized)?,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        )
        .map_err(|_| ServiceFailure::Unauthorized)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let identity = positron_governance::Identity::open(
        &catalog
            .pin()
            .map_err(|failure| classify_catalog_failure_code(failure.code()))?,
    )
    .map_err(|_| ServiceFailure::CorruptState)?;
    identity
        .revalidate_query_context(context)
        .map_err(|_| ServiceFailure::Unauthorized)?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, shard);
    let protection = instance
        .key
        .segment_key(instance.instance, scope)
        .map_err(|_| ServiceFailure::KeyUnavailable)?;
    let ledger = ActiveSegmentLedger::open(&instance._authority, &catalog, scope, protection)
        .map_err(|failure| classify_ledger_failure_code(failure.code()))?;
    let service = QueryService::new(instance._authority.governor(), &ledger, 100, identity);
    let query = service
        .plan_pipeline(context, source, budget)
        .map_err(|failure| map_query_failure(&failure))?;
    let schema = services
        .schema_sessions
        .session(instance.tenant, instance.resource_governor())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let events = schema
        .with_catalog_view(instance.tenant, |catalog| {
            service.execute_with_schema(query, catalog)
        })
        .map_err(schema_bootstrap::classify_replay_failure)?
        .map_err(|failure| map_query_failure(&failure))?;
    collect_query_bodies(events)
}
