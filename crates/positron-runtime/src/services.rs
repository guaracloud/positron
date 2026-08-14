use std::sync::{Arc, Mutex};

use positron_domain::routing::SignalKind;
use positron_governance::{
    AuthorizedContext, CompatibilityHints, IngestPolicyServingSnapshot, PresentedCredential,
    RequestedIntent,
};
use positron_ingest::{
    AdmissionGroupOutcome, AuthenticatedLokiPushRequest, AuthenticatedOtlpLogsRequest,
    IngestFailureCode, IngestOutcome, IngestRequestOutcome, LogIngest, LokiPushReceiver,
    LokiPushRequestEncoding, NativeLogBatch, OtlpLogsReceiver, reserve_log_receiver_transport,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, LedgerFailureCode, LifecycleClock, SegmentScope,
    StoreBlockIdentity, SystemLifecycleClockSource, TransferredResourceReservation,
};
use positron_query::{QueryBudget, QueryEvent, QueryService};

use crate::InitializedInstance;

mod failure;
mod otlp;
mod policy;

pub use failure::ServiceFailure;
use failure::{map_admission_group_plan_failure, map_receive_failure};

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct ServiceHandle {
    instance: Arc<InitializedInstance>,
    ingest_policy: IngestPolicyServingSnapshot,
    #[cfg(test)]
    receiver_test_backend: Arc<Mutex<Option<Arc<dyn ReceiverTestBackend>>>>,
}

#[cfg(test)]
pub(crate) trait ReceiverTestBackend: Send + Sync {
    fn ingest(&self, groups: positron_ingest::NativeLogAdmissionGroups<'_>)
    -> IngestRequestOutcome;
}

impl std::fmt::Debug for ServiceHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ServiceHandle { <authorized runtime services> }")
    }
}

impl ServiceHandle {
    pub(crate) fn new(instance: Arc<InitializedInstance>) -> Self {
        let ingest_policy = instance.ingest_policy.serving();
        Self {
            instance,
            ingest_policy,
            #[cfg(test)]
            receiver_test_backend: Arc::new(Mutex::new(None)),
        }
    }

    pub fn ingest_otlp_logs(
        &self,
        bearer: &str,
        protobuf: Vec<u8>,
    ) -> Result<IngestRequestOutcome, ServiceFailure> {
        let context = self.authorize_logs(bearer)?;
        let instance = &self.instance;
        let request = AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
            context,
            instance._authority.governor(),
            protobuf,
        )
        .map_err(map_receive_failure)?;
        ingest_authenticated(self, request)
    }

    pub(crate) fn authorize_logs(&self, bearer: &str) -> Result<AuthorizedContext, ServiceFailure> {
        self.authorize_logs_with_hints(bearer, CompatibilityHints::none())
    }

    pub(crate) fn authorize_logs_with_hints(
        &self,
        bearer: &str,
        hints: CompatibilityHints,
    ) -> Result<AuthorizedContext, ServiceFailure> {
        let instance = &self.instance;
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
        reservation: TransferredResourceReservation,
    ) -> Result<IngestRequestOutcome, ServiceFailure> {
        let instance = &self.instance;
        let capacity = reservation
            .reclaim(instance.resource_governor())
            .map_err(|_| ServiceFailure::Internal)?;
        let request = AuthenticatedOtlpLogsRequest::decoded_otlp_grpc_after_transport_admission(
            context, decoded, capacity,
        )
        .map_err(map_receive_failure)?;
        ingest_authenticated(self, request)
    }

    pub(crate) fn ingest_encoded_loki_push(
        &self,
        context: AuthorizedContext,
        encoding: LokiPushRequestEncoding,
        body: Vec<u8>,
        reservation: TransferredResourceReservation,
    ) -> Result<IngestRequestOutcome, ServiceFailure> {
        let capacity = reservation
            .reclaim(self.instance.resource_governor())
            .map_err(|_| ServiceFailure::Internal)?;
        let request = AuthenticatedLokiPushRequest::encoded_after_transport_admission(
            context, encoding, body, capacity,
        )
        .map_err(map_receive_failure)?;
        let batch = LokiPushReceiver::with_value_limit_profile(self.instance.value_limit_profile)
            .decode(request)
            .map_err(map_receive_failure)?;
        ingest_native_batch(self, batch)
    }

    pub(crate) fn logs_transport_limits(&self) -> Result<(usize, usize), ServiceFailure> {
        let request = self
            .instance
            .value_limit_profile
            .effective_limits()
            .request();
        Ok((
            usize::try_from(request.compressed_bytes().value())
                .map_err(|_| ServiceFailure::Internal)?,
            usize::try_from(request.decompressed_bytes().value())
                .map_err(|_| ServiceFailure::Internal)?,
        ))
    }

    #[cfg(test)]
    pub(crate) fn install_receiver_test_backend(
        &self,
        backend: Arc<dyn ReceiverTestBackend>,
    ) -> Result<(), ServiceFailure> {
        *self
            .receiver_test_backend
            .lock()
            .map_err(|_| ServiceFailure::Internal)? = Some(backend);
        Ok(())
    }

    pub(crate) fn admit_logs(
        &self,
        context: AuthorizedContext,
    ) -> Result<ReceiverAdmissionLease, ServiceFailure> {
        let reservation =
            reserve_log_receiver_transport(context, self.instance.resource_governor())
                .map_err(|failure| match failure {
                    positron_ingest::ReceiveFailure::CapacityUnavailable => {
                        ServiceFailure::CapacityUnavailable
                    },
                    _ => ServiceFailure::InvalidRequest,
                })?
                .transfer();
        Ok(ReceiverAdmissionLease {
            inner: Arc::new(ReceiverAdmissionLeaseInner {
                services: self.clone(),
                reservation: Mutex::new(Some(reservation)),
            }),
        })
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
        self.query_log_bodies_on_shard(bearer, self.instance.logs_shard, source, budget)
    }

    fn query_log_bodies_on_shard(
        &self,
        bearer: &str,
        shard: positron_domain::routing::VirtualShardId,
        source: &str,
        budget: QueryBudget,
    ) -> Result<Vec<String>, ServiceFailure> {
        let instance = &self.instance;
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
    services: &'authority ServiceHandle,
    request: AuthenticatedOtlpLogsRequest<'authority>,
) -> Result<IngestRequestOutcome, ServiceFailure> {
    let instance = &services.instance;
    let batch = OtlpLogsReceiver::with_value_limit_profile(instance.value_limit_profile)
        .decode(request)
        .map_err(map_receive_failure)?;
    ingest_native_batch(services, batch)
}

fn ingest_native_batch(
    services: &ServiceHandle,
    batch: NativeLogBatch<'_>,
) -> Result<IngestRequestOutcome, ServiceFailure> {
    let instance = &services.instance;
    let policy = services
        .ingest_policy
        .pin()
        .map_err(|_| ServiceFailure::Internal)?;
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
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let clock = LifecycleClock::new(SystemLifecycleClockSource);
    let mut outcomes = Vec::new();
    outcomes
        .try_reserve_exact(groups.len())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    for group in groups {
        let shard = group.shard();
        let records = group.records();
        let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, shard);
        let outcome = match instance.key.segment_key(instance.instance, scope) {
            Ok(protection) => {
                let ledger =
                    ActiveSegmentLedger::open(&instance._authority, &catalog, scope, protection);
                match ledger {
                    Ok(ledger) => match instance.key.random_identifier() {
                        Ok(identifier) => match StoreBlockIdentity::new(identifier) {
                            Ok(identity) => LogIngest::new(
                                &instance._authority,
                                &ledger,
                                &clock,
                                &policy,
                                instance.tenant,
                                shard,
                            )
                            .accept(group.into_batch(), identity),
                            Err(_) => IngestOutcome::Permanent(IngestFailureCode::InvalidRecord),
                        },
                        Err(_) => IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
                    },
                    Err(failure)
                        if failure.code() == LedgerFailureCode::ResourceAdmissionRefused =>
                    {
                        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
                    },
                    Err(_) => IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
                }
            },
            Err(_) => IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
        };
        outcomes.push(AdmissionGroupOutcome::new(shard, records, outcome));
    }
    Ok(IngestRequestOutcome::new(outcomes))
}

#[derive(Clone)]
pub(crate) struct ReceiverAdmissionLease {
    inner: Arc<ReceiverAdmissionLeaseInner>,
}

struct ReceiverAdmissionLeaseInner {
    services: ServiceHandle,
    reservation: Mutex<Option<TransferredResourceReservation>>,
}

impl ReceiverAdmissionLease {
    pub(crate) fn take(&self) -> Result<TransferredResourceReservation, ServiceFailure> {
        self.inner
            .reservation
            .lock()
            .map_err(|_| ServiceFailure::Internal)?
            .take()
            .ok_or(ServiceFailure::Internal)
    }
}

impl Drop for ReceiverAdmissionLeaseInner {
    fn drop(&mut self) {
        let reservation = match self.reservation.get_mut() {
            Ok(reservation) => reservation,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(reservation) = reservation.take() {
            reservation.release(self.services.instance.resource_governor());
        }
    }
}
