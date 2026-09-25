use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_server::LogsService;
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::TraceService;
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTracePartialSuccess, ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use positron_governance::{AuthorizedContext, CompatibilityHints};
use positron_ingest::{IngestRequestOutcome, OtlpGrpcTransportEvidence};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;
use tokio_stream::{Stream, StreamExt};
use tonic::codec::CompressionEncoding;
use tonic::service::LayerExt;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Server;
use tonic::transport::server::{Connected, TcpConnectInfo};
use tonic::{Request, Response, Status};
use tower::util::MapResponseLayer;

use super::api_http::IdleIo;
use super::otlp_outcome::{OtlpFailure, OtlpSignal};
use super::{Admission, ConnectionLease, TrustedProxy};
use crate::{ServiceFailure, ServiceHandle, TaskCancellation};

const MAX_MESSAGE_BYTES: usize = 1_048_576;

mod blocking;
use blocking::{BlockingIngestExecutor, BlockingIngestHandle};
mod codec;
use codec::OtlpLogsServer;
mod trace_codec;
use trace_codec::OtlpTracesServer;

#[cfg(test)]
mod tests;

pub(super) struct PreparedGrpc {
    admission: Arc<Admission>,
    runtime: tokio::runtime::Runtime,
    listener: tokio::net::TcpListener,
    server: Server,
    tls: Option<Arc<rustls::ServerConfig>>,
    protection: crate::ConnectionProtection,
    services: ServiceHandle,
    blocking: BlockingIngestExecutor,
    blocking_handle: BlockingIngestHandle,
}

pub(super) fn prepare(
    admission: Arc<Admission>,
    services: Option<ServiceHandle>,
) -> Result<PreparedGrpc, GrpcFailure> {
    let services = services.ok_or(GrpcFailure)?;
    let listener = admission.tcp_listener().map_err(|_| GrpcFailure)?;
    let protection = admission.connection_protection();
    let tls = admission.grpc_tls_config().map_err(|_| GrpcFailure)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| GrpcFailure)?;
    let listener = {
        let _entered = runtime.enter();
        tokio::net::TcpListener::from_std(listener).map_err(|_| GrpcFailure)?
    };
    let server = Server::builder().timeout(protection.request_deadline());
    let blocking = BlockingIngestExecutor::start()?;
    let blocking_handle = blocking.handle()?;
    Ok(PreparedGrpc {
        admission,
        runtime,
        listener,
        server,
        tls,
        protection,
        services,
        blocking,
        blocking_handle,
    })
}

impl PreparedGrpc {
    pub(super) fn discard(mut self) -> Result<(), GrpcFailure> {
        self.blocking.shutdown()
    }

    pub(super) fn serve(
        mut self,
        cancellation: TaskCancellation,
        force: TaskCancellation,
    ) -> Result<(), GrpcFailure> {
        let admission = Arc::clone(&self.admission);
        let services = self.services.clone();
        let blocking_handle = self.blocking_handle.clone();
        let listener = self.listener;
        let mut server = self.server;
        let tls = self.tls;
        let protection = self.protection;
        let (result, forced) = self.runtime.block_on(async move {
            let handshake_admission = Arc::clone(&admission);
            let incoming = AdmittedIncoming {
                listener,
                admission: Arc::clone(&admission),
                cancellation: cancellation.clone(),
            }
            .then(move |accepted| {
                let tls = tls.clone();
                let admission = Arc::clone(&handshake_admission);
                async move { secure_grpc_connection(accepted, admission, tls, protection).await }
            });
            let authentication = services.clone();
            let trace_authentication = services.clone();
            let trusted_proxy = admission.trusted_proxy.clone();
            let trace_trusted_proxy = trusted_proxy.clone();
            let receiver = OtlpLogsServer::new(OtlpLogsGrpc {
                services: services.clone(),
                blocking: blocking_handle.clone(),
            })
            .accept_compressed(CompressionEncoding::Gzip)
            .max_decoding_message_size(MAX_MESSAGE_BYTES);
            let receiver = MapResponseLayer::new(map_decode_failure).named_layer(receiver);
            let receiver = InterceptedService::new(receiver, move |request| {
                authenticate(request, &authentication, trusted_proxy.clone())
            });
            let trace_receiver = OtlpTracesServer::new(OtlpTracesGrpc {
                services,
                blocking: blocking_handle,
            })
            .accept_compressed(CompressionEncoding::Gzip);
            let trace_receiver =
                MapResponseLayer::new(map_trace_decode_failure).named_layer(trace_receiver);
            let trace_receiver = InterceptedService::new(trace_receiver, move |request| {
                authenticate_traces(request, &trace_authentication, trace_trusted_proxy.clone())
            });
            let graceful_admission = Arc::clone(&admission);
            let serving = server
                .add_service(receiver)
                .add_service(trace_receiver)
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
            let _worker_joined = self.blocking.shutdown_within(Duration::from_millis(100))?;
        } else {
            self.blocking.shutdown()?;
        }
        result
    }
}

struct AdmittedIncoming {
    listener: tokio::net::TcpListener,
    admission: Arc<Admission>,
    cancellation: TaskCancellation,
}

struct AdmittedTcpStream {
    stream: Pin<Box<tokio::net::TcpStream>>,
    _lease: ConnectionLease,
}

enum AdmittedIo {
    Plain(AdmittedTcpStream),
    Tls {
        stream: Pin<Box<tokio_rustls::server::TlsStream<AdmittedTcpStream>>>,
        connection_info: TcpConnectInfo,
    },
}

async fn secure_grpc_connection(
    stream: Result<AdmittedTcpStream, io::Error>,
    admission: Arc<Admission>,
    tls: Option<Arc<rustls::ServerConfig>>,
    protection: crate::ConnectionProtection,
) -> Result<IdleIo<AdmittedIo>, io::Error> {
    let stream = stream?;
    let Some(configuration) = tls else {
        return Ok(IdleIo::new(
            AdmittedIo::Plain(stream),
            protection.idle_deadline(),
        ));
    };
    let connection_info = stream.connect_info();
    let _handshake = admission.reserve_tls_handshake().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "TLS handshake admission limit reached",
        )
    })?;
    let stream = tokio::time::timeout(
        protection.tls_handshake_deadline(),
        TlsAcceptor::from(configuration).accept(stream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake deadline elapsed"))?
    .map_err(io::Error::other)?;
    Ok(IdleIo::new(
        AdmittedIo::Tls {
            stream: Box::pin(stream),
            connection_info,
        },
        protection.idle_deadline(),
    ))
}

impl Stream for AdmittedIncoming {
    type Item = Result<AdmittedTcpStream, io::Error>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if !super::can_serve_accepted_connection(&this.admission, &this.cancellation) {
            return Poll::Ready(None);
        }
        match this.listener.poll_accept(context) {
            Poll::Ready(Ok((stream, peer))) => {
                if !super::can_serve_accepted_connection(&this.admission, &this.cancellation) {
                    return Poll::Ready(None);
                }
                match this.admission.accept_connection(peer.ip()) {
                    Some(lease) => Poll::Ready(Some(Ok(AdmittedTcpStream {
                        stream: Box::pin(stream),
                        _lease: lease,
                    }))),
                    None => {
                        context.waker().wake_by_ref();
                        Poll::Pending
                    },
                }
            },
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for AdmittedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_read(context, buffer)
    }
}

impl AsyncRead for AdmittedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls { stream, .. } => stream.as_mut().poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for AdmittedTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stream.as_mut().poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_shutdown(context)
    }
}

impl AsyncWrite for AdmittedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Tls { stream, .. } => stream.as_mut().poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls { stream, .. } => stream.as_mut().poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls { stream, .. } => stream.as_mut().poll_shutdown(context),
        }
    }
}

impl Connected for AdmittedTcpStream {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.as_ref().get_ref().connect_info()
    }
}

impl Connected for AdmittedIo {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        match self {
            Self::Plain(stream) => stream.connect_info(),
            Self::Tls {
                connection_info, ..
            } => connection_info.clone(),
        }
    }
}

impl Connected for IdleIo<AdmittedIo> {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.inner().connect_info()
    }
}

pub(super) fn serve(
    admission: Arc<Admission>,
    cancellation: TaskCancellation,
    force: TaskCancellation,
    services: Option<ServiceHandle>,
) -> Result<(), GrpcFailure> {
    prepare(admission, services)?.serve(cancellation, force)
}

fn map_decode_failure<B>(response: http::Response<B>) -> http::Response<B> {
    map_wire_decode_failure(response, "OTLP%20Logs%20request%20was%20malformed")
}

fn map_trace_decode_failure<B>(response: http::Response<B>) -> http::Response<B> {
    map_wire_decode_failure(response, "OTLP%20Traces%20request%20was%20malformed")
}

fn map_wire_decode_failure<B>(
    mut response: http::Response<B>,
    message: &'static str,
) -> http::Response<B> {
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
        response
            .headers_mut()
            .insert("grpc-message", http::HeaderValue::from_static(message));
    }
    response
}

async fn wait_for(cancellation: TaskCancellation) {
    while !cancellation.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn authenticate(
    mut request: Request<()>,
    services: &ServiceHandle,
    trusted_proxy: Option<TrustedProxy>,
) -> Result<Request<()>, Status> {
    let bearer = unique_metadata(&request, "authorization", authentication_rejected)?
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(authentication_rejected)?;
    let hints = proxy_hints(&request, trusted_proxy, authentication_rejected)?;
    let context = services
        .authorize_logs_with_hints(bearer, hints)
        .map_err(|_| authentication_rejected())?;
    let admission = services.admit_logs(context).map_err(service_status)?;
    request.extensions_mut().insert(context);
    request.extensions_mut().insert(admission);
    Ok(request)
}

fn authentication_rejected() -> Status {
    status_from_failure(OtlpSignal::Logs.authentication_rejected())
}

fn authenticate_traces(
    mut request: Request<()>,
    services: &ServiceHandle,
    trusted_proxy: Option<TrustedProxy>,
) -> Result<Request<()>, Status> {
    let bearer = unique_metadata(&request, "authorization", trace_authentication_rejected)?
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(trace_authentication_rejected)?;
    let hints = proxy_hints(&request, trusted_proxy, trace_authentication_rejected)?;
    let context = services
        .authorize_traces_with_hints(bearer, hints)
        .map_err(|_| trace_authentication_rejected())?;
    let admission = services
        .admit_traces(context)
        .map_err(trace_service_status)?;
    request.extensions_mut().insert(context);
    request.extensions_mut().insert(admission);
    Ok(request)
}

fn trace_authentication_rejected() -> Status {
    status_from_failure(OtlpSignal::Traces.authentication_rejected())
}

fn unique_metadata<'request>(
    request: &'request Request<()>,
    name: &str,
    rejected: fn() -> Status,
) -> Result<Option<&'request str>, Status> {
    let mut values = request.metadata().get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(rejected());
    }
    value.to_str().map(Some).map_err(|_| rejected())
}

fn proxy_hints(
    request: &Request<()>,
    trusted_proxy: Option<TrustedProxy>,
    rejected: fn() -> Status,
) -> Result<CompatibilityHints, Status> {
    let external_alias = unique_metadata(request, "x-scope-orgid", rejected)?;
    let forwarded_for = unique_metadata(request, "x-forwarded-for", rejected)?;
    let forwarded_user = unique_metadata(request, "x-forwarded-user", rejected)?;
    let forwarded_service = unique_metadata(request, "x-forwarded-service", rejected)?;
    if forwarded_user.is_some() && forwarded_service.is_some() {
        return Err(rejected());
    }
    let actor = forwarded_user.or(forwarded_service);
    if (forwarded_for.is_some() || actor.is_some())
        && let Some(policy) = trusted_proxy
    {
        let peer = request.remote_addr().ok_or_else(rejected)?;
        if !policy.validates(peer, forwarded_for) {
            return Err(rejected());
        }
        return CompatibilityHints::trusted_proxy(external_alias, actor).map_err(|_| rejected());
    }
    external_alias
        .map(CompatibilityHints::external_tenant_alias)
        .transpose()
        .map_err(|_| rejected())
        .map(|hints| hints.unwrap_or_else(CompatibilityHints::none))
}

#[derive(Clone, Debug)]
struct OtlpLogsGrpc {
    services: ServiceHandle,
    blocking: BlockingIngestHandle,
}

#[derive(Clone, Debug)]
struct OtlpTracesGrpc {
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
            .remove::<crate::services::ReceiverAdmissionLease>()
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

#[tonic::async_trait]
impl TraceService for OtlpTracesGrpc {
    async fn export(
        &self,
        mut request: Request<ExportTraceServiceRequest>,
    ) -> Result<Response<ExportTraceServiceResponse>, Status> {
        let context = request
            .extensions()
            .get::<AuthorizedContext>()
            .copied()
            .ok_or_else(trace_authentication_rejected)?;
        let admission = request
            .extensions_mut()
            .remove::<crate::services::ReceiverAdmissionLease>()
            .ok_or_else(|| Status::internal("OTLP Traces admission context was unavailable"))?;
        let evidence = request
            .extensions()
            .get::<OtlpGrpcTransportEvidence>()
            .cloned()
            .ok_or_else(|| Status::internal("OTLP Traces transport evidence was unavailable"))?;
        let reservation = admission.take().map_err(trace_service_status)?;
        if request.get_ref().resource_spans.iter().all(|resource| {
            resource
                .scope_spans
                .iter()
                .all(|scope| scope.spans.is_empty())
        }) {
            drop(reservation);
            return trace_render(IngestRequestOutcome::new(Vec::new()));
        }
        let outcome = self
            .blocking
            .ingest_traces(
                self.services.clone(),
                context,
                request.into_inner(),
                evidence,
                reservation,
            )
            .await
            .map_err(trace_service_status)?;
        trace_render(outcome)
    }
}

fn render(outcome: IngestRequestOutcome) -> Result<Response<ExportLogsServiceResponse>, Status> {
    if let Some(failure) = outcome.terminal_failure() {
        return Err(status_from_failure(
            OtlpSignal::Logs.outcome_failure(failure),
        ));
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

fn service_status(failure: ServiceFailure) -> Status {
    status_from_failure(OtlpSignal::Logs.service_failure(failure))
}

fn trace_render(
    outcome: IngestRequestOutcome,
) -> Result<Response<ExportTraceServiceResponse>, Status> {
    if let Some(failure) = outcome.terminal_failure() {
        return Err(status_from_failure(
            OtlpSignal::Traces.outcome_failure(failure),
        ));
    }
    let rejected = outcome.permanently_rejected_records();
    if rejected == 0 {
        Ok(Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    } else {
        let rejected_spans = i64::try_from(rejected)
            .map_err(|_| Status::internal("OTLP Traces outcome could not be represented"))?;
        let error_message = OtlpSignal::trace_partial_message(outcome.limit_rejections())
            .map_err(|_| Status::internal("OTLP Traces response encoding failed"))?;
        Ok(Response::new(ExportTraceServiceResponse {
            partial_success: Some(ExportTracePartialSuccess {
                rejected_spans,
                error_message,
            }),
        }))
    }
}

fn trace_service_status(failure: ServiceFailure) -> Status {
    status_from_failure(OtlpSignal::Traces.service_failure(failure))
}

fn status_from_failure(failure: OtlpFailure) -> Status {
    let message = failure.rendered_message();
    match failure.grpc_code {
        3 => Status::invalid_argument(message),
        8 => Status::resource_exhausted(message),
        13 => Status::internal(message),
        14 => Status::unavailable(message),
        16 => Status::unauthenticated(message),
        _ => Status::internal(message),
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct GrpcFailure;

#[cfg(test)]
mod admission_tests {
    use std::future::poll_fn;
    use std::net::{Ipv4Addr, TcpListener};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio_stream::Stream;

    use super::AdmittedIncoming;
    use crate::native_host::{Admission, NativeListener, TransportProfile};
    use crate::{ListenerRole, TaskCancellation};

    #[tokio::test(flavor = "current_thread")]
    async fn retired_grpc_listener_does_not_admit_an_already_queued_socket()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let tokio_listener = listener.try_clone()?;
        tokio_listener.set_nonblocking(true)?;
        let tokio_listener = tokio::net::TcpListener::from_std(tokio_listener)?;
        let client = tokio::net::TcpStream::connect(address).await?;
        let admission = Arc::new(Admission {
            role: ListenerRole::OtlpGrpc,
            listener: NativeListener::Tcp(listener),
            accepting: AtomicBool::new(true),
            accepted_connections: AtomicUsize::new(0),
            control_path: None,
            transport: Some(TransportProfile::plaintext_opt_out()),
            trusted_proxy: None,
            connection_admission: None,
            connection_protection: None,
        });
        let cancellation = TaskCancellation::new();
        admission.stop();
        let mut incoming = AdmittedIncoming {
            listener: tokio_listener,
            admission: Arc::clone(&admission),
            cancellation,
        };

        let next = poll_fn(|context| Pin::new(&mut incoming).poll_next(context)).await;
        assert!(next.is_none());
        assert_eq!(admission.accepted_connections.load(Ordering::Acquire), 0);
        drop(client);
        Ok(())
    }
}
