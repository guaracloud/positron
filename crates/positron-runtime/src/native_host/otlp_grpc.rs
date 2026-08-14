use std::sync::Arc;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_server::{
    LogsService, LogsServiceServer,
};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use positron_governance::{AuthorizedContext, CompatibilityHints};
use positron_ingest::{IngestFailureCode, IngestOutcome};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codec::CompressionEncoding;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use super::Admission;
use crate::{ServiceFailure, ServiceHandle, TaskCancellation};

const MAX_MESSAGE_BYTES: usize = 1_048_576;

#[cfg(test)]
mod tests;

pub(super) fn serve(
    admission: Arc<Admission>,
    cancellation: TaskCancellation,
    services: Option<ServiceHandle>,
) -> Result<(), GrpcFailure> {
    let services = services.ok_or(GrpcFailure)?;
    let listener = admission.tcp_listener().map_err(|_| GrpcFailure)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| GrpcFailure)?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::from_std(listener).map_err(|_| GrpcFailure)?;
        let incoming = TcpListenerStream::new(listener);
        let authentication = services.clone();
        let receiver = LogsServiceServer::new(OtlpLogsGrpc { services })
            .accept_compressed(CompressionEncoding::Gzip)
            .max_decoding_message_size(MAX_MESSAGE_BYTES);
        let receiver = InterceptedService::new(receiver, move |request| {
            authenticate(request, &authentication)
        });
        Server::builder()
            .add_service(receiver)
            .serve_with_incoming_shutdown(incoming, async move {
                while admission.is_accepting() && !cancellation.is_cancelled() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .map_err(|_| GrpcFailure)
    })
}

fn authenticate(mut request: Request<()>, services: &ServiceHandle) -> Result<Request<()>, Status> {
    let bearer = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(authentication_rejected)?;
    let hints = request
        .metadata()
        .get("x-scope-orgid")
        .map(|value| value.to_str().map_err(|_| authentication_rejected()))
        .transpose()?
        .map(CompatibilityHints::external_tenant_alias)
        .transpose()
        .map_err(|_| authentication_rejected())?
        .unwrap_or_else(CompatibilityHints::none);
    let context = services
        .authorize_otlp_logs_with_hints(bearer, hints)
        .map_err(|_| authentication_rejected())?;
    request.extensions_mut().insert(context);
    Ok(request)
}

fn authentication_rejected() -> Status {
    Status::unauthenticated("OTLP Logs request authentication was rejected")
}

#[derive(Clone, Debug)]
struct OtlpLogsGrpc {
    services: ServiceHandle,
}

#[tonic::async_trait]
impl LogsService for OtlpLogsGrpc {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        let context = request
            .extensions()
            .get::<AuthorizedContext>()
            .copied()
            .ok_or_else(authentication_rejected)?;
        let outcome = self
            .services
            .ingest_decoded_otlp_logs(context, request.into_inner())
            .map_err(service_status)?;
        render(outcome)
    }
}

fn render(outcome: IngestOutcome) -> Result<Response<ExportLogsServiceResponse>, Status> {
    match outcome {
        IngestOutcome::Full(_) => Ok(Response::new(ExportLogsServiceResponse {
            partial_success: None,
        })),
        IngestOutcome::Partial(partial) => {
            let rejected_log_records = i64::try_from(partial.permanently_rejected())
                .map_err(|_| Status::internal("OTLP Logs outcome could not be represented"))?;
            Ok(Response::new(ExportLogsServiceResponse {
                partial_success: Some(ExportLogsPartialSuccess {
                    rejected_log_records,
                    error_message: "some log records were permanently rejected".to_owned(),
                }),
            }))
        },
        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable) => Err(
            Status::resource_exhausted("OTLP Logs ingest capacity is unavailable"),
        ),
        IngestOutcome::Retryable(_) => Err(Status::unavailable(
            "OTLP Logs ingest is temporarily unavailable",
        )),
        IngestOutcome::Permanent(_) => {
            Err(Status::invalid_argument("OTLP Logs request was rejected"))
        },
        IngestOutcome::Ambiguous(_) => Err(Status::unavailable(
            "OTLP Logs commit outcome is ambiguous; retry may duplicate records",
        )),
    }
}

fn service_status(failure: ServiceFailure) -> Status {
    match failure {
        ServiceFailure::Unauthorized => authentication_rejected(),
        ServiceFailure::InvalidRequest => {
            Status::invalid_argument("OTLP Logs request was rejected")
        },
        ServiceFailure::KeyUnavailable | ServiceFailure::StorageUnavailable => {
            Status::unavailable("OTLP Logs ingest is temporarily unavailable")
        },
        ServiceFailure::Internal => Status::internal("OTLP Logs ingest failed"),
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct GrpcFailure;
