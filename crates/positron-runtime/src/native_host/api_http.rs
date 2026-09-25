use std::convert::Infallible;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body::{Body, Frame};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::native_http::{self, Response as NativeResponse};
use super::{
    Admission, HealthState, ServiceHandle, TaskCancellation, TransportProfile, TrustedProxy,
};

const MAX_HEADER_BYTES: usize = 8 * 1024;

pub(super) struct ConnectionContext {
    pub(super) transport: Option<TransportProfile>,
    pub(super) admission: Arc<Admission>,
    pub(super) cancellation: TaskCancellation,
    pub(super) peer: std::net::SocketAddr,
    pub(super) trusted_proxy: Option<TrustedProxy>,
    pub(super) health: HealthState,
    pub(super) services: Option<ServiceHandle>,
}

pub(super) fn serve_connection(
    stream: std::net::TcpStream,
    context: ConnectionContext,
) -> Result<(), ApiHttpFailure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ApiHttpFailure)?;
    let ConnectionContext {
        transport,
        admission,
        cancellation,
        peer,
        trusted_proxy,
        health,
        services,
    } = context;
    runtime.block_on(async move {
        let stream = TcpStream::from_std(stream).map_err(|_| ApiHttpFailure)?;
        match transport {
            Some(profile) if profile.is_tls() => {
                let configuration = profile
                    .api_http_server_config()
                    .map_err(|_| ApiHttpFailure)?
                    .ok_or(ApiHttpFailure)?;
                let stream = TlsAcceptor::from(configuration)
                    .accept(stream)
                    .await
                    .map_err(|_| ApiHttpFailure)?;
                serve_io(
                    stream,
                    admission,
                    cancellation,
                    peer,
                    trusted_proxy,
                    health,
                    services,
                )
                .await
            },
            Some(_) | None => {
                serve_io(
                    stream,
                    admission,
                    cancellation,
                    peer,
                    trusted_proxy,
                    health,
                    services,
                )
                .await
            },
        }
    })
}

async fn serve_io<I>(
    stream: I,
    admission: Arc<Admission>,
    cancellation: TaskCancellation,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    health: HealthState,
    services: Option<ServiceHandle>,
) -> Result<(), ApiHttpFailure>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .auto_date_header(false)
        .half_close(true)
        .keep_alive(false)
        .max_buf_size(MAX_HEADER_BYTES);
    builder
        .http2()
        .auto_date_header(false)
        .max_concurrent_streams(1)
        .max_header_list_size(MAX_HEADER_BYTES as u32);
    let connection = builder.serve_connection(
        TokioIo::new(stream),
        service_fn(move |request| {
            let trusted_proxy = trusted_proxy.clone();
            let health = health.clone();
            let services = services.clone();
            async move {
                Ok::<_, Infallible>(
                    route_request(request, peer, trusted_proxy, &health, services.as_ref()).await,
                )
            }
        }),
    );
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result.map_err(|_| ApiHttpFailure),
        () = wait_for_shutdown(admission, cancellation) => {
            connection.as_mut().graceful_shutdown();
            connection.await.map_err(|_| ApiHttpFailure)
        },
    }
}

async fn wait_for_shutdown(admission: Arc<Admission>, cancellation: TaskCancellation) {
    while super::can_serve_accepted_connection(&admission, &cancellation) {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

async fn route_request(
    request: Request<Incoming>,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Response<ApiResponseBody> {
    let (parts, body) = request.into_parts();
    let body_limit = native_http::api_body_limit(
        parts.method.as_str(),
        parts
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str),
    );
    let response = match collect_body(body, body_limit).await {
        Ok(body) => match native_http::head_from_http_parts(
            &parts.method,
            &parts.uri,
            &parts.headers,
            body.len(),
        ) {
            Ok(head) => {
                native_http::route_buffered_api(head, body, peer, trusted_proxy, health, services)
            },
            Err(response) => response,
        },
        Err(response) => response,
    };
    response_from_native(response)
}

async fn collect_body(mut body: Incoming, maximum: usize) -> Result<Vec<u8>, NativeResponse> {
    let mut collected = Vec::new();
    while let Some(frame) = poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await {
        let frame = frame.map_err(|_| NativeResponse::empty(400))?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let remaining = maximum.saturating_sub(collected.len());
        if data.len() > remaining {
            return Err(NativeResponse::empty(413));
        }
        collected
            .try_reserve(data.len())
            .map_err(|_| NativeResponse::empty(500))?;
        collected.extend_from_slice(&data);
    }
    Ok(collected)
}

fn response_from_native(response: NativeResponse) -> Response<ApiResponseBody> {
    let mut result = Response::new(ApiResponseBody::new(&response.body));
    *result.status_mut() =
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if let Ok(content_type) = HeaderValue::from_str(response.content_type) {
        result
            .headers_mut()
            .insert(http::header::CONTENT_TYPE, content_type);
    }
    if let Ok(content_length) = HeaderValue::from_str(&response.body.len().to_string()) {
        result
            .headers_mut()
            .insert(http::header::CONTENT_LENGTH, content_length);
    }
    if let Some(seconds) = response.retry_after_seconds
        && let Ok(retry_after) = HeaderValue::from_str(&seconds.to_string())
    {
        result
            .headers_mut()
            .insert(http::header::RETRY_AFTER, retry_after);
    }
    result
}

struct ApiResponseBody {
    data: Option<Bytes>,
}

impl ApiResponseBody {
    fn new(data: &[u8]) -> Self {
        Self {
            data: Some(Bytes::copy_from_slice(data)),
        }
    }
}

impl Body for ApiResponseBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.data.take().map(|data| Ok(Frame::data(data))))
    }
}

pub(super) struct ApiHttpFailure;
