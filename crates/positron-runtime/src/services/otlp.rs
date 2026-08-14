use positron_governance::AuthorizedContext;
use positron_ingest::{
    AuthenticatedOtlpLogsRequest, IngestRequestOutcome, OtlpLogsRequestEncoding,
};
use positron_kernel::TransferredResourceReservation;

use super::{ServiceFailure, ServiceHandle, ingest_authenticated, map_receive_failure};

impl ServiceHandle {
    pub(crate) fn ingest_encoded_otlp_http_logs(
        &self,
        context: AuthorizedContext,
        encoding: OtlpLogsRequestEncoding,
        body: Vec<u8>,
        reservation: TransferredResourceReservation,
    ) -> Result<IngestRequestOutcome, ServiceFailure> {
        let capacity = reservation
            .reclaim(self.instance.resource_governor())
            .map_err(|_| ServiceFailure::Internal)?;
        let request = AuthenticatedOtlpLogsRequest::encoded_otlp_http_after_transport_admission(
            context, encoding, body, capacity,
        )
        .map_err(map_receive_failure)?;
        ingest_authenticated(self, request)
    }

    pub(crate) fn ingest_encoded_loki_otlp_logs(
        &self,
        context: AuthorizedContext,
        encoding: OtlpLogsRequestEncoding,
        body: Vec<u8>,
        reservation: TransferredResourceReservation,
    ) -> Result<IngestRequestOutcome, ServiceFailure> {
        let capacity = reservation
            .reclaim(self.instance.resource_governor())
            .map_err(|_| ServiceFailure::Internal)?;
        let request = AuthenticatedOtlpLogsRequest::encoded_loki_otlp_after_transport_admission(
            context, encoding, body, capacity,
        )
        .map_err(map_receive_failure)?;
        ingest_authenticated(self, request)
    }
}
