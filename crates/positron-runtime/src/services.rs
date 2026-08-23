use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use positron_domain::routing::SignalKind;
use positron_governance::{
    AuthorizedContext, CompatibilityHints, IngestPolicyServingSnapshot, PresentedCredential,
    RequestedIntent,
};
use positron_ingest::{
    AuthenticatedLokiPushRequest, AuthenticatedOtlpLogsRequest, IngestRequestOutcome,
    LokiPushReceiver, LokiPushRequestEncoding, TenantSchemaRegistry,
    reserve_log_receiver_transport,
};
use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope, TransferredResourceReservation};
use positron_query::{QueryBudget, QueryEvent, QueryService};

use crate::InitializedInstance;

mod failure;
mod ingest;
mod otlp;
mod policy;
mod schema_bootstrap;
mod schema_maintenance;

pub use failure::ServiceFailure;
use failure::{map_admission_group_plan_failure, map_receive_failure};
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct ServiceHandle {
    ingest_policy: IngestPolicyServingSnapshot,
    schema_sessions: TenantSchemaRegistry,
    schema_dirty: Arc<AtomicBool>,
    shutdown_schema_capacity: Arc<Mutex<Option<TransferredResourceReservation>>>,
    #[cfg(test)]
    receiver_test_backend: Arc<Mutex<Option<Arc<dyn ReceiverTestBackend>>>>,
    // Keep the authority alive until every governed session and admission
    // capability above has released its transferred reservations.
    instance: Arc<InitializedInstance>,
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
    #[allow(dead_code)]
    pub(crate) fn new(instance: Arc<InitializedInstance>) -> Result<Self, ServiceFailure> {
        Self::new_with_cancellation(instance, None)
    }

    pub(crate) fn new_with_cancellation(
        instance: Arc<InitializedInstance>,
        cancellation: Option<&crate::TaskCancellation>,
    ) -> Result<Self, ServiceFailure> {
        let ingest_policy = instance.ingest_policy.serving();
        let fallback = crate::TaskCancellation::new();
        let cancellation = cancellation.unwrap_or(&fallback);
        let recovered = schema_bootstrap::recover(&instance, cancellation)?;
        if cancellation.is_cancelled() {
            return Err(ServiceFailure::Cancelled);
        }
        if let Some(checkpoint) = recovered.dirty_checkpoint {
            if cancellation.is_cancelled() {
                return Err(ServiceFailure::Cancelled);
            }
            schema_maintenance::publish_quiescent_checkpoint(&instance, checkpoint)?;
        }
        Ok(Self {
            ingest_policy,
            schema_sessions: recovered.registry,
            schema_dirty: Arc::new(AtomicBool::new(false)),
            shutdown_schema_capacity: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            receiver_test_backend: Arc::new(Mutex::new(None)),
            instance,
        })
    }

    pub(crate) fn prepare_shutdown_schema_checkpoint(&self) -> Result<(), ServiceFailure> {
        if !self.schema_dirty.load(Ordering::Acquire) {
            return Ok(());
        }
        let capacity = schema_maintenance::reserve_shutdown_capacity(&self.instance)?;
        *self
            .shutdown_schema_capacity
            .lock()
            .map_err(|_| ServiceFailure::Internal)? = Some(capacity);
        Ok(())
    }

    pub(crate) fn publish_prepared_shutdown_schema_checkpoint(&self) -> Result<(), ServiceFailure> {
        if !self.schema_dirty.load(Ordering::Acquire) {
            return Ok(());
        }
        let capacity = self
            .shutdown_schema_capacity
            .lock()
            .map_err(|_| ServiceFailure::Internal)?
            .take()
            .ok_or(ServiceFailure::CapacityUnavailable)?;
        let checkpoint = self
            .schema_sessions
            .session(self.instance.tenant, self.instance.resource_governor())
            .map_err(|_| ServiceFailure::CapacityUnavailable)?
            .checkpoint()
            .map_err(|_| ServiceFailure::Internal)?;
        schema_maintenance::publish_with_capacity(&self.instance, checkpoint, capacity)?;
        self.schema_dirty.store(false, Ordering::Release);
        Ok(())
    }

    pub(super) fn mark_schema_dirty(&self) {
        self.schema_dirty.store(true, Ordering::Release);
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
        ingest::ingest_authenticated(self, request)
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
        let identity = instance
            .durable_identity()
            .map_err(|_| ServiceFailure::Unauthorized)?;
        identity
            .attribute(
                &instance.key,
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
        ingest::ingest_authenticated(self, request)
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
        ingest::ingest_native_batch(self, batch)
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
        let identity = positron_governance::Identity::open(
            &catalog
                .pin()
                .map_err(|_| ServiceFailure::StorageUnavailable)?,
        )
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
        let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, shard);
        let protection = instance
            .key
            .segment_key(instance.instance, scope)
            .map_err(|_| ServiceFailure::KeyUnavailable)?;
        let ledger = ActiveSegmentLedger::open(&instance._authority, &catalog, scope, protection)
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        let service = QueryService::new(instance._authority.governor(), &ledger, 100, identity);
        let query = service
            .plan_pipeline(context, source, budget)
            .map_err(|_| ServiceFailure::InvalidRequest)?;
        let schema = self
            .schema_sessions
            .session(instance.tenant, instance.resource_governor())
            .map_err(|_| ServiceFailure::CapacityUnavailable)?;
        let events = schema
            .with_catalog_view(instance.tenant, |catalog| {
                service.execute_with_schema(query, catalog)
            })
            .map_err(|_| ServiceFailure::StorageUnavailable)?
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
