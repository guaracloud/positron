use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use http_body::{Frame, SizeHint};
use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::TraceService;
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use positron_domain::value::ValueLimitProfile;
use positron_ingest::{
    OtlpGrpcTransportEvidence, TraceReceiveFailure, preflight_otlp_traces_protobuf_with_profile,
};
use prost::Message;
use prost::bytes::Buf;
use tonic::codec::{
    Codec, CompressionEncoding, DecodeBuf, Decoder, EnabledCompressionEncodings, EncodeBuf, Encoder,
};
use tonic::codegen::{Body, BoxFuture, Service, StdError};
use tonic::{Request, Response, Status};

use crate::services::ReceiverAdmissionLease;

const EXPORT_PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";
const SERVICE_NAME: &str = "opentelemetry.proto.collector.trace.v1.TraceService";

#[derive(Debug)]
pub(super) struct OtlpTracesServer<T> {
    inner: Arc<T>,
    accepted_compression: EnabledCompressionEncodings,
}

impl<T> OtlpTracesServer<T> {
    pub(super) fn new(inner: T) -> Self {
        Self {
            inner: Arc::new(inner),
            accepted_compression: EnabledCompressionEncodings::default(),
        }
    }

    pub(super) fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
        self.accepted_compression.enable(encoding);
        self
    }
}

impl<T> Clone for OtlpTracesServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            accepted_compression: self.accepted_compression,
        }
    }
}

impl<T, B> Service<http::Request<B>> for OtlpTracesServer<T>
where
    T: TraceService,
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        if request.uri().path() != EXPORT_PATH {
            return Box::pin(async move { Ok(unimplemented_response()) });
        }
        let profile = request
            .extensions()
            .get::<ReceiverAdmissionLease>()
            .map_or_else(ValueLimitProfile::release_1_system_maximum, |lease| {
                lease.value_limit_profile()
            });
        let request_limits = profile.effective_limits().request();
        let compressed_limit =
            usize::try_from(request_limits.compressed_bytes().value()).unwrap_or(usize::MAX);
        let decompressed_limit =
            usize::try_from(request_limits.decompressed_bytes().value()).unwrap_or(usize::MAX);
        let measurement = Arc::new(Mutex::new(WireMeasurement::default()));
        let request = request
            .map(|body| BoundedGrpcBody::new(body, compressed_limit, Arc::clone(&measurement)));
        let method = ExportService {
            inner: Arc::clone(&self.inner),
            measurement: Arc::clone(&measurement),
        };
        let accepted_compression = self.accepted_compression;
        Box::pin(async move {
            let mut grpc = tonic::server::Grpc::new(OtlpTracesCodec {
                profile,
                measurement,
            })
            .apply_compression_config(accepted_compression, EnabledCompressionEncodings::default())
            .apply_max_message_size_config(Some(decompressed_limit), None);
            Ok(grpc.unary(method, request).await)
        })
    }
}

impl<T> tonic::server::NamedService for OtlpTracesServer<T> {
    const NAME: &'static str = SERVICE_NAME;
}

struct ExportService<T> {
    inner: Arc<T>,
    measurement: Arc<Mutex<WireMeasurement>>,
}

impl<T: TraceService> tonic::server::UnaryService<ExportTraceServiceRequest> for ExportService<T> {
    type Response = ExportTraceServiceResponse;
    type Future = BoxFuture<Response<Self::Response>, Status>;

    fn call(&mut self, mut request: Request<ExportTraceServiceRequest>) -> Self::Future {
        let inner = Arc::clone(&self.inner);
        let measurement = Arc::clone(&self.measurement);
        Box::pin(async move {
            let evidence = {
                let measurement = measurement
                    .lock()
                    .map_err(|_| Status::internal("OTLP Traces transport measurement failed"))?;
                OtlpGrpcTransportEvidence::prevalidated(
                    measurement.wire_body_bytes,
                    measurement.decompressed_message_bytes,
                )
            };
            request.extensions_mut().insert(evidence);
            T::export(&inner, request).await
        })
    }
}

#[derive(Clone, Debug)]
struct OtlpTracesCodec {
    profile: ValueLimitProfile,
    measurement: Arc<Mutex<WireMeasurement>>,
}

impl Codec for OtlpTracesCodec {
    type Encode = ExportTraceServiceResponse;
    type Decode = ExportTraceServiceRequest;
    type Encoder = OtlpTracesEncoder;
    type Decoder = OtlpTracesDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        OtlpTracesEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        OtlpTracesDecoder {
            profile: self.profile,
            measurement: Arc::clone(&self.measurement),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct OtlpTracesEncoder;

impl Encoder for OtlpTracesEncoder {
    type Item = ExportTraceServiceResponse;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, destination: &mut EncodeBuf<'_>) -> Result<(), Status> {
        item.encode(destination)
            .map_err(|_| Status::internal("OTLP Traces response encoding failed"))
    }
}

#[derive(Clone, Debug)]
struct OtlpTracesDecoder {
    profile: ValueLimitProfile,
    measurement: Arc<Mutex<WireMeasurement>>,
}

impl Decoder for OtlpTracesDecoder {
    type Item = ExportTraceServiceRequest;
    type Error = Status;

    fn decode(&mut self, source: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Status> {
        let frame_length = source.remaining();
        self.measurement
            .lock()
            .map_err(|_| Status::internal("OTLP Traces transport measurement failed"))?
            .decompressed_message_bytes = frame_length;
        let frame = source.copy_to_bytes(frame_length);
        preflight_otlp_traces_protobuf_with_profile(frame.as_ref(), self.profile)
            .map_err(preflight_status)?;
        ExportTraceServiceRequest::decode(frame)
            .map(Some)
            .map_err(|_| malformed_status())
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct WireMeasurement {
    wire_body_bytes: usize,
    decompressed_message_bytes: usize,
}

struct BoundedGrpcBody<B> {
    inner: Pin<Box<B>>,
    limit: usize,
    seen: usize,
    measurement: Arc<Mutex<WireMeasurement>>,
}

impl<B> BoundedGrpcBody<B> {
    fn new(inner: B, limit: usize, measurement: Arc<Mutex<WireMeasurement>>) -> Self {
        Self {
            inner: Box::pin(inner),
            limit,
            seen: 0,
            measurement,
        }
    }
}

impl<B> Body for BoundedGrpcBody<B>
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Data = B::Data;
    type Error = Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        match this.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let data_bytes = data.remaining();
                    let Some(total) = this.seen.checked_add(data_bytes) else {
                        return Poll::Ready(Some(Err(Status::resource_exhausted(
                            "OTLP Traces request exceeds the receiver limit",
                        ))));
                    };
                    if total > this.limit {
                        return Poll::Ready(Some(Err(Status::resource_exhausted(
                            "OTLP Traces request exceeds the receiver limit",
                        ))));
                    }
                    this.seen = total;
                    if let Ok(mut measurement) = this.measurement.lock() {
                        measurement.wire_body_bytes = total;
                    } else {
                        return Poll::Ready(Some(Err(Status::internal(
                            "OTLP Traces transport measurement failed",
                        ))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            },
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(Err(Status::from_error(error.into()))))
            },
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().get_ref().is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = self.inner.as_ref().get_ref().size_hint();
        let remaining = self.limit.saturating_sub(self.seen) as u64;
        hint.set_lower(hint.lower().min(remaining));
        if let Some(upper) = hint.upper() {
            hint.set_upper(upper.min(remaining));
        }
        hint
    }
}

fn preflight_status(failure: TraceReceiveFailure) -> Status {
    match failure {
        TraceReceiveFailure::MalformedPayload => malformed_status(),
        _ => Status::invalid_argument("OTLP Traces request was rejected"),
    }
}

fn malformed_status() -> Status {
    Status::invalid_argument("OTLP Traces request was malformed")
}

fn unimplemented_response() -> http::Response<tonic::body::Body> {
    let mut response = http::Response::new(tonic::body::Body::default());
    response.headers_mut().insert(
        tonic::Status::GRPC_STATUS,
        (tonic::Code::Unimplemented as i32).into(),
    );
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        tonic::metadata::GRPC_CONTENT_TYPE,
    );
    response
}
