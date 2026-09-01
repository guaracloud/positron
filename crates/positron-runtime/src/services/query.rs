#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use positron_domain::routing::SignalKind;
use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};
use positron_query::{QueryBudget, QueryService};
#[cfg(test)]
use positron_query::{QueryClock, QueryClockFailure, QueryCursor, QueryEvent, QueryFailureCode};

use super::{
    ServiceFailure, ServiceHandle, classify_bootstrap_failure_code, classify_catalog_failure_code,
    classify_ledger_failure_code, collect_query_bodies, map_query_failure, schema_bootstrap,
};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum QueryTestOutcome {
    Events(Vec<QueryEvent>),
    Failure(QueryFailureCode),
}

#[cfg(test)]
struct RuntimeTestQueryClock;

#[cfg(test)]
impl QueryClock for RuntimeTestQueryClock {
    fn now_seconds(&self) -> Result<u64, QueryClockFailure> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| QueryClockFailure)
    }
}

#[cfg(test)]
pub(super) fn query_events_for_test(
    services: &ServiceHandle,
    context: positron_governance::AuthorizedContext,
    shard: positron_domain::routing::VirtualShardId,
    source: &str,
    budget: QueryBudget,
    page_limit: Option<u16>,
) -> Result<QueryTestOutcome, ServiceFailure> {
    let instance = &services.instance;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, shard);
    let protection = instance
        .key
        .segment_key(instance.instance, scope)
        .map_err(|_| ServiceFailure::KeyUnavailable)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &instance._authority,
        &instance.retention_time,
        &catalog,
        scope,
        protection,
    )
    .map_err(|failure| classify_ledger_failure_code(failure.code()))?;
    let service = QueryService::with_clock(
        instance.resource_governor(),
        &ledger,
        page_limit.unwrap_or(100),
        Arc::new(RuntimeTestQueryClock),
    );
    let query = match service.plan_pipeline(context, source, budget) {
        Ok(query) => query,
        Err(failure) => return Ok(QueryTestOutcome::Failure(failure.code())),
    };
    let schema = services
        .schema_sessions
        .session(instance.tenant, instance.resource_governor())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let events = schema
        .with_catalog_view(instance.tenant, |view| match page_limit {
            Some(_) => service.execute_page(query),
            None => service.execute_with_schema(query, view),
        })
        .map_err(schema_bootstrap::classify_replay_failure)?
        .map_err(|failure| QueryTestOutcome::Failure(failure.code()));
    match events {
        Ok(events) => Ok(QueryTestOutcome::Events(events.collect::<Vec<_>>())),
        Err(outcome) => Ok(outcome),
    }
}

#[cfg(test)]
pub(super) fn resume_query_events_for_test(
    services: &ServiceHandle,
    context: positron_governance::AuthorizedContext,
    cursor: &QueryCursor,
    shard: positron_domain::routing::VirtualShardId,
    batch_limit: u16,
) -> Result<QueryTestOutcome, ServiceFailure> {
    let instance = &services.instance;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, shard);
    let protection = instance
        .key
        .segment_key(instance.instance, scope)
        .map_err(|_| ServiceFailure::KeyUnavailable)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &instance._authority,
        &instance.retention_time,
        &catalog,
        scope,
        protection,
    )
    .map_err(|failure| classify_ledger_failure_code(failure.code()))?;
    let service = QueryService::with_clock(
        instance.resource_governor(),
        &ledger,
        batch_limit,
        Arc::new(RuntimeTestQueryClock),
    );
    let events = service
        .resume(context, cursor)
        .map_err(|failure| QueryTestOutcome::Failure(failure.code()));
    match events {
        Ok(events) => Ok(QueryTestOutcome::Events(events.collect::<Vec<_>>())),
        Err(outcome) => Ok(outcome),
    }
}

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
        .map_err(|failure| classify_bootstrap_failure_code(failure.code()))?;
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
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &instance._authority,
        &instance.retention_time,
        &catalog,
        scope,
        protection,
    )
    .map_err(|failure| classify_ledger_failure_code(failure.code()))?;
    let service = QueryService::new(instance._authority.governor(), &ledger, 100);
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
