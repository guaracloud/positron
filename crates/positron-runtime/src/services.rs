use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};

use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_governance::{
    AuthorizedContext, CompatibilityHints, PresentedCredential, RequestedIntent,
};
use positron_ingest::{
    AuthenticatedOtlpLogsRequest, IngestOutcome, IngestPolicy, LogIngest, OtlpLogsReceiver,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, LifecycleClock, SegmentScope, StoreBlockIdentity,
    SystemLifecycleClockSource,
};
use positron_query::{QueryBudget, QueryEvent, QueryService};

use crate::InitializedInstance;

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct ServiceHandle {
    instance: Arc<Mutex<InitializedInstance>>,
}

impl std::fmt::Debug for ServiceHandle {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ServiceHandle { <authorized runtime services> }")
    }
}

impl ServiceHandle {
    pub(crate) fn new(instance: Arc<Mutex<InitializedInstance>>) -> Self {
        Self { instance }
    }

    pub fn ingest_otlp_logs(
        &self,
        bearer: &str,
        protobuf: Vec<u8>,
    ) -> Result<IngestOutcome, ServiceFailure> {
        let context = self.authorize_otlp_logs(bearer)?;
        let instance = self.instance.lock().map_err(|_| ServiceFailure::Internal)?;
        let request = AuthenticatedOtlpLogsRequest::protobuf(
            context,
            instance._authority.governor(),
            protobuf,
        )
        .map_err(|_| ServiceFailure::InvalidRequest)?;
        ingest_authenticated(&instance, request)
    }

    pub(crate) fn authorize_otlp_logs(
        &self,
        bearer: &str,
    ) -> Result<AuthorizedContext, ServiceFailure> {
        self.authorize_otlp_logs_with_hints(bearer, CompatibilityHints::none())
    }

    pub(crate) fn authorize_otlp_logs_with_hints(
        &self,
        bearer: &str,
        hints: CompatibilityHints,
    ) -> Result<AuthorizedContext, ServiceFailure> {
        let instance = self.instance.lock().map_err(|_| ServiceFailure::Internal)?;
        instance
            .attribute(
                PresentedCredential::parse(bearer).map_err(|_| ServiceFailure::Unauthorized)?,
                RequestedIntent::Ingest,
                hints,
            )
            .map_err(|_| ServiceFailure::Unauthorized)
    }

    pub(crate) fn ingest_decoded_otlp_logs(
        &self,
        context: AuthorizedContext,
        decoded: opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest,
    ) -> Result<IngestOutcome, ServiceFailure> {
        let instance = self.instance.lock().map_err(|_| ServiceFailure::Internal)?;
        let request =
            AuthenticatedOtlpLogsRequest::decoded(context, instance._authority.governor(), decoded)
                .map_err(|_| ServiceFailure::InvalidRequest)?;
        ingest_authenticated(&instance, request)
    }

    /// Runs the generated capability contract without adding a second API authority.
    pub fn negotiate_capability(
        &self,
        body: &[u8],
    ) -> Result<positron_api::generated::CapabilityResponse, positron_api::generated::ApiError>
    {
        positron_api::generated::CapabilityService::decode_and_negotiate(
            positron_api::generated::Transport::HttpJson,
            body,
        )
    }

    /// Reads durable log bodies through the existing native Query service.
    ///
    /// This is deliberately not a wire route: the public v1 schema does not yet
    /// publish a query transport.
    pub fn query_log_bodies(
        &self,
        bearer: &str,
        source: &str,
        budget: QueryBudget,
    ) -> Result<Vec<String>, ServiceFailure> {
        let instance = self.instance.lock().map_err(|_| ServiceFailure::Internal)?;
        let context = instance
            .attribute(
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
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
        let shard = VirtualShardId::new(1).map_err(|_| ServiceFailure::Internal)?;
        let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, shard);
        let protection = instance
            .key
            .segment_key(instance.instance, scope)
            .map_err(|_| ServiceFailure::KeyUnavailable)?;
        let ledger = ActiveSegmentLedger::open(&instance._authority, &catalog, scope, protection)
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        let service = QueryService::new(instance._authority.governor(), &ledger, 100);
        let query = service
            .plan_pipeline(context, source, budget)
            .map_err(|_| ServiceFailure::InvalidRequest)?;
        let events = service
            .execute(query)
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        Ok(events
            .filter_map(|event| match event {
                QueryEvent::Batch(batch) => Some(
                    batch
                        .records()
                        .iter()
                        .filter_map(|record| record.body_text().map(ToOwned::to_owned))
                        .collect::<Vec<_>>(),
                ),
                QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
            })
            .flatten()
            .collect())
    }
}

fn ingest_authenticated<'authority>(
    instance: &'authority InitializedInstance,
    request: AuthenticatedOtlpLogsRequest<'authority>,
) -> Result<IngestOutcome, ServiceFailure> {
    let batch = OtlpLogsReceiver::new()
        .decode(request)
        .map_err(|_| ServiceFailure::InvalidRequest)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let shard = VirtualShardId::new(1).map_err(|_| ServiceFailure::Internal)?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, shard);
    let protection = instance
        .key
        .segment_key(instance.instance, scope)
        .map_err(|_| ServiceFailure::KeyUnavailable)?;
    let ledger = ActiveSegmentLedger::open(&instance._authority, &catalog, scope, protection)
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let policy = IngestPolicy::preserving(1, [1_u8; 32]).map_err(|_| ServiceFailure::Internal)?;
    let clock = LifecycleClock::new(SystemLifecycleClockSource);
    let identity = StoreBlockIdentity::new(
        instance
            .key
            .random_identifier()
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|_| ServiceFailure::Internal)?;
    Ok(LogIngest::new(
        &instance._authority,
        &ledger,
        &clock,
        &policy,
        instance.tenant,
        shard,
    )
    .accept(batch, identity))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceFailure {
    Unauthorized,
    InvalidRequest,
    KeyUnavailable,
    StorageUnavailable,
    Internal,
}

impl Display for ServiceFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("runtime service request failed")
    }
}

impl Error for ServiceFailure {}
