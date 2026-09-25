use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body::{Body, Frame};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::native_http::{self, Response as NativeResponse};
use super::{
    Admission, ConnectionProtection, HealthState, ServiceHandle, TaskCancellation,
    TransportProfile, TrustedProxy,
};

const MAX_HEADER_BYTES: usize = 8 * 1024;
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const BAD_REQUEST_RESPONSE: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

pub(super) struct ConnectionContext {
    pub(super) transport: Option<TransportProfile>,
    pub(super) admission: Arc<Admission>,
    pub(super) cancellation: TaskCancellation,
    pub(super) peer: std::net::SocketAddr,
    pub(super) trusted_proxy: Option<TrustedProxy>,
    pub(super) health: HealthState,
    pub(super) services: Option<ServiceHandle>,
    pub(super) protection: ConnectionProtection,
}

pub(super) fn serve_connection(
    stream: std::net::TcpStream,
    context: ConnectionContext,
) -> Result<(), ApiHttpFailure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ApiHttpFailure)?;
    runtime.block_on(async move {
        let stream = TcpStream::from_std(stream).map_err(|_| ApiHttpFailure)?;
        match context.transport.clone() {
            Some(profile) if profile.is_tls() => {
                let configuration = profile
                    .api_http_server_config()
                    .map_err(|_| ApiHttpFailure)?
                    .ok_or(ApiHttpFailure)?;
                let stream = {
                    let _handshake = context
                        .admission
                        .reserve_tls_handshake()
                        .ok_or(ApiHttpFailure)?;
                    tokio::time::timeout(
                        context.protection.tls_handshake_deadline(),
                        TlsAcceptor::from(configuration).accept(stream),
                    )
                    .await
                    .map_err(|_| ApiHttpFailure)?
                    .map_err(|_| ApiHttpFailure)?
                };
                serve_io(stream, context).await
            },
            Some(_) | None => serve_io(stream, context).await,
        }
    })
}

async fn serve_io<I>(stream: I, context: ConnectionContext) -> Result<(), ApiHttpFailure>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ConnectionContext {
        admission,
        cancellation,
        peer,
        trusted_proxy,
        health,
        services,
        protection,
        ..
    } = context;
    let stream = IdleIo::new(stream, protection.idle_deadline());
    let header_deadline = tokio::time::Instant::now() + protection.header_deadline();
    let stream =
        match tokio::time::timeout_at(header_deadline, preflight_http1_framing(stream)).await {
            Ok(Ok(FramingPreflight::Continue(stream))) => stream,
            Ok(Ok(FramingPreflight::Rejected(mut stream))) => {
                write_bad_request(&mut stream).await;
                return Ok(());
            },
            Ok(Err(())) | Err(_) => return Err(ApiHttpFailure),
        };
    let remaining_header_deadline = header_deadline
        .checked_duration_since(tokio::time::Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(ApiHttpFailure)?;
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .auto_date_header(false)
        .half_close(true)
        .keep_alive(false)
        .max_buf_size(MAX_HEADER_BYTES)
        .timer(TokioTimer::new())
        .header_read_timeout(remaining_header_deadline);
    builder
        .http2()
        .auto_date_header(false)
        .max_concurrent_streams(1)
        .timer(TokioTimer::new())
        .max_header_list_size(MAX_HEADER_BYTES as u32);
    let connection = builder.serve_connection(
        TokioIo::new(stream),
        service_fn(move |request| {
            let trusted_proxy = trusted_proxy.clone();
            let health = health.clone();
            let services = services.clone();
            let protection = protection;
            async move {
                Ok::<_, Infallible>(
                    match tokio::time::timeout(
                        protection.request_deadline(),
                        route_request(
                            request,
                            peer,
                            trusted_proxy,
                            &health,
                            services.as_ref(),
                            protection,
                        ),
                    )
                    .await
                    {
                        Ok(response) => response,
                        Err(_) => response_from_native(NativeResponse::empty(408)),
                    },
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

enum FramingPreflight<I> {
    Continue(PrefetchedIo<I>),
    Rejected(I),
}

async fn preflight_http1_framing<I>(mut stream: I) -> Result<FramingPreflight<I>, ()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut prefetched = Vec::with_capacity(512);
    loop {
        if prefetched.starts_with(HTTP2_PREFACE) {
            return Ok(FramingPreflight::Continue(PrefetchedIo::new(
                stream, prefetched,
            )));
        }
        if let Some(header_end) = http1_header_end(&prefetched) {
            if has_duplicate_content_length(&prefetched[..header_end]) {
                return Ok(FramingPreflight::Rejected(stream));
            }
            return Ok(FramingPreflight::Continue(PrefetchedIo::new(
                stream, prefetched,
            )));
        }
        if prefetched.len() == MAX_HEADER_BYTES {
            return Ok(FramingPreflight::Continue(PrefetchedIo::new(
                stream, prefetched,
            )));
        }
        let mut buffer = [0_u8; 512];
        let maximum = buffer.len().min(MAX_HEADER_BYTES - prefetched.len());
        let mut read = ReadBuf::new(&mut buffer[..maximum]);
        poll_fn(|context| Pin::new(&mut stream).poll_read(context, &mut read))
            .await
            .map_err(|_| ())?;
        let bytes = read.filled();
        if bytes.is_empty() {
            return Err(());
        }
        prefetched.extend_from_slice(bytes);
    }
}

fn http1_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn has_duplicate_content_length(header: &[u8]) -> bool {
    let mut content_length_seen = false;
    for line in header.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = &line[..separator];
        if name.eq_ignore_ascii_case(b"content-length") {
            if content_length_seen {
                return true;
            }
            content_length_seen = true;
        }
    }
    false
}

async fn write_bad_request<I>(stream: &mut I)
where
    I: tokio::io::AsyncWrite + Unpin,
{
    let mut remaining = BAD_REQUEST_RESPONSE;
    while !remaining.is_empty() {
        let Ok(written) =
            poll_fn(|context| Pin::new(&mut *stream).poll_write(context, remaining)).await
        else {
            return;
        };
        if written == 0 {
            return;
        }
        remaining = &remaining[written..];
    }
    let _ = poll_fn(|context| Pin::new(&mut *stream).poll_flush(context)).await;
    let _ = poll_fn(|context| Pin::new(&mut *stream).poll_shutdown(context)).await;
}

struct PrefetchedIo<I> {
    inner: I,
    prefetched: Vec<u8>,
    offset: usize,
}

impl<I> PrefetchedIo<I> {
    fn new(inner: I, prefetched: Vec<u8>) -> Self {
        Self {
            inner,
            prefetched,
            offset: 0,
        }
    }
}

impl<I: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefetchedIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefetched.len() {
            let available = &self.prefetched[self.offset..];
            let count = available.len().min(buffer.remaining());
            buffer.put_slice(&available[..count]);
            self.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<I: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefetchedIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
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
    protection: ConnectionProtection,
) -> Response<ApiResponseBody> {
    let (parts, body) = request.into_parts();
    let body_limit = native_http::api_body_limit(
        parts.method.as_str(),
        parts
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str),
    );
    let response = match tokio::time::timeout(
        protection.body_deadline(),
        collect_body(body, body_limit),
    )
    .await
    {
        Err(_) => NativeResponse::empty(408),
        Ok(Err(response)) => response,
        Ok(Ok(body)) => match native_http::head_from_http_parts(
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
    };
    response_from_native(response)
}

pub(super) struct IdleIo<I> {
    inner: I,
    idle_deadline: std::time::Duration,
    idle_until: std::pin::Pin<Box<tokio::time::Sleep>>,
}

impl<I> IdleIo<I> {
    pub(super) fn new(inner: I, idle_deadline: std::time::Duration) -> Self {
        Self {
            inner,
            idle_deadline,
            idle_until: Box::pin(tokio::time::sleep(idle_deadline)),
        }
    }

    fn record_activity(&mut self) {
        self.idle_until
            .as_mut()
            .reset(tokio::time::Instant::now() + self.idle_deadline);
    }

    pub(super) fn inner(&self) -> &I {
        &self.inner
    }
}

impl<I: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for IdleIo<I> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.idle_until.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection idle deadline elapsed",
            )));
        }
        let before = buffer.filled().len();
        match std::pin::Pin::new(&mut self.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                if buffer.filled().len() > before {
                    self.record_activity();
                }
                Poll::Ready(Ok(()))
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<I: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for IdleIo<I> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.idle_until.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection idle deadline elapsed",
            )));
        }
        match std::pin::Pin::new(&mut self.inner).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                if written != 0 {
                    self.record_activity();
                }
                Poll::Ready(Ok(written))
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(context)
    }
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
