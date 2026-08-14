use std::sync::Arc;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_server::{
    LogsService, LogsServiceServer,
};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use positron_governance::{AuthorizedContext, CompatibilityHints};
use positron_ingest::{IngestFailureCode, IngestOutcome, IngestRequestOutcome};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codec::CompressionEncoding;
use tonic::service::LayerExt;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tower::util::MapResponseLayer;

use super::Admission;
use crate::{ServiceFailure, ServiceHandle, TaskCancellation};

const MAX_MESSAGE_BYTES: usize = 1_048_576;

mod blocking;
use blocking::{BlockingIngestExecutor, BlockingIngestHandle};

#[cfg(test)]
mod tests;

pub(super) fn serve(
    admission: Arc<Admission>,
    cancellation: TaskCancellation,
    force: TaskCancellation,
    services: Option<ServiceHandle>,
) -> Result<(), GrpcFailure> {
    let services = services.ok_or(GrpcFailure)?;
    let listener = admission.tcp_listener().map_err(|_| GrpcFailure)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| GrpcFailure)?;
    let mut blocking = BlockingIngestExecutor::start()?;
    let blocking_handle = blocking.handle()?;
    let (result, forced) = runtime.block_on(async move {
        let listener = match tokio::net::TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(_) => return (Err(GrpcFailure), false),
        };
        let incoming = TcpListenerStream::new(listener);
        let authentication = services.clone();
        let receiver = LogsServiceServer::new(OtlpLogsGrpc {
            services,
            blocking: blocking_handle,
        })
        .accept_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(MAX_MESSAGE_BYTES);
        let receiver = MapResponseLayer::new(map_decode_failure).named_layer(receiver);
        let receiver = InterceptedService::new(receiver, move |request| {
            authenticate(request, &authentication)
        });
        let graceful_admission = Arc::clone(&admission);
        let serving = Server::builder()
            .add_service(receiver)
            .serve_with_incoming_shutdown(incoming, async move {
                while graceful_admission.is_accepting() && !cancellation.is_cancelled() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
        tokio::pin!(serving);
        tokio::select! {
            result = &mut serving => (result.map_err(|_| GrpcFailure), false),
            () = wait_for(force) => (Ok(()), true),
        }
    });
    if forced {
        let _worker_joined = blocking.shutdown_within(Duration::from_millis(100))?;
    } else {
        blocking.shutdown()?;
    }
    result
}

fn map_decode_failure<B>(mut response: http::Response<B>) -> http::Response<B> {
    let is_wire_decode_failure = response
        .headers()
        .get("grpc-status")
        .is_some_and(|value| value == "13")
        && response
            .headers()
            .get("grpc-message")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|message| {
                message.starts_with("failed%20to%20decode%20Protobuf%20message:")
            });
    if is_wire_decode_failure {
        response
            .headers_mut()
            .insert("grpc-status", http::HeaderValue::from_static("3"));
        response.headers_mut().insert(
            "grpc-message",
            http::HeaderValue::from_static("OTLP%20Logs%20request%20was%20malformed"),
        );
    }
    response
}

async fn wait_for(cancellation: TaskCancellation) {
    while !cancellation.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
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
    let admission = services.admit_otlp_grpc(context).map_err(service_status)?;
    request.extensions_mut().insert(context);
    request.extensions_mut().insert(admission);
    Ok(request)
}

fn authentication_rejected() -> Status {
    Status::unauthenticated("OTLP Logs request authentication was rejected")
}

#[derive(Clone, Debug)]
struct OtlpLogsGrpc {
    services: ServiceHandle,
    blocking: BlockingIngestHandle,
}

#[tonic::async_trait]
impl LogsService for OtlpLogsGrpc {
    async fn export(
        &self,
        mut request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        let context = request
            .extensions()
            .get::<AuthorizedContext>()
            .copied()
            .ok_or_else(authentication_rejected)?;
        let admission = request
            .extensions_mut()
            .remove::<crate::services::GrpcAdmissionLease>()
            .ok_or_else(|| Status::internal("OTLP Logs admission context was unavailable"))?;
        let reservation = admission.take().map_err(service_status)?;
        if request.get_ref().resource_logs.iter().all(|resource| {
            resource
                .scope_logs
                .iter()
                .all(|scope| scope.log_records.is_empty())
        }) {
            drop(reservation);
            return render(IngestRequestOutcome::new(Vec::new()));
        }
        let outcome = self
            .blocking
            .ingest(
                self.services.clone(),
                context,
                request.into_inner(),
                reservation,
            )
            .await
            .map_err(service_status)?;
        render(outcome)
    }
}

fn render(outcome: IngestRequestOutcome) -> Result<Response<ExportLogsServiceResponse>, Status> {
    if let Some(failure) = outcome.terminal_failure() {
        return render_failure(failure);
    }
    let rejected = outcome.permanently_rejected_records();
    if rejected == 0 {
        Ok(Response::new(ExportLogsServiceResponse {
            partial_success: None,
        }))
    } else {
        let rejected_log_records = i64::try_from(rejected)
            .map_err(|_| Status::internal("OTLP Logs outcome could not be represented"))?;
        Ok(Response::new(ExportLogsServiceResponse {
            partial_success: Some(ExportLogsPartialSuccess {
                rejected_log_records,
                error_message: "some log records were permanently rejected".to_owned(),
            }),
        }))
    }
}

fn render_failure(outcome: IngestOutcome) -> Result<Response<ExportLogsServiceResponse>, Status> {
    match outcome {
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
        IngestOutcome::Full(_) | IngestOutcome::Partial(_) => {
            Err(Status::internal("OTLP Logs outcome aggregation failed"))
        },
    }
}

fn service_status(failure: ServiceFailure) -> Status {
    match failure {
        ServiceFailure::Unauthorized => authentication_rejected(),
        ServiceFailure::CapacityUnavailable => {
            Status::resource_exhausted("OTLP Logs ingest capacity is unavailable")
        },
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
