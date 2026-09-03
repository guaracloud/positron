use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::TraceService;
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use positron_ingest::{TraceReceiveFailure, preflight_otlp_traces_protobuf};
use prost::Message;
use prost::bytes::Buf;
use tonic::codec::{
    Codec, CompressionEncoding, DecodeBuf, Decoder, EnabledCompressionEncodings, EncodeBuf, Encoder,
};
use tonic::codegen::{Body, BoxFuture, Service, StdError};
use tonic::{Request, Response, Status};

const EXPORT_PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";
const SERVICE_NAME: &str = "opentelemetry.proto.collector.trace.v1.TraceService";

#[derive(Debug)]
pub(super) struct OtlpTracesServer<T> {
    inner: Arc<T>,
    accepted_compression: EnabledCompressionEncodings,
    maximum_decoding_bytes: Option<usize>,
}

impl<T> OtlpTracesServer<T> {
    pub(super) fn new(inner: T) -> Self {
        Self {
            inner: Arc::new(inner),
            accepted_compression: EnabledCompressionEncodings::default(),
            maximum_decoding_bytes: None,
        }
    }

    pub(super) fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
        self.accepted_compression.enable(encoding);
        self
    }

    pub(super) const fn max_decoding_message_size(mut self, limit: usize) -> Self {
        self.maximum_decoding_bytes = Some(limit);
        self
    }
}

impl<T> Clone for OtlpTracesServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            accepted_compression: self.accepted_compression,
            maximum_decoding_bytes: self.maximum_decoding_bytes,
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
        let method = ExportService(Arc::clone(&self.inner));
        let accepted_compression = self.accepted_compression;
        let maximum_decoding_bytes = self.maximum_decoding_bytes;
        Box::pin(async move {
            let mut grpc = tonic::server::Grpc::new(OtlpTracesCodec)
                .apply_compression_config(
                    accepted_compression,
                    EnabledCompressionEncodings::default(),
                )
                .apply_max_message_size_config(maximum_decoding_bytes, None);
            Ok(grpc.unary(method, request).await)
        })
    }
}

impl<T> tonic::server::NamedService for OtlpTracesServer<T> {
    const NAME: &'static str = SERVICE_NAME;
}

struct ExportService<T>(Arc<T>);

impl<T: TraceService> tonic::server::UnaryService<ExportTraceServiceRequest> for ExportService<T> {
    type Response = ExportTraceServiceResponse;
    type Future = BoxFuture<Response<Self::Response>, Status>;

    fn call(&mut self, request: Request<ExportTraceServiceRequest>) -> Self::Future {
        let inner = Arc::clone(&self.0);
        Box::pin(async move { T::export(&inner, request).await })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct OtlpTracesCodec;

impl Codec for OtlpTracesCodec {
    type Encode = ExportTraceServiceResponse;
    type Decode = ExportTraceServiceRequest;
    type Encoder = OtlpTracesEncoder;
    type Decoder = OtlpTracesDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        OtlpTracesEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        OtlpTracesDecoder
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

#[derive(Clone, Copy, Debug, Default)]
struct OtlpTracesDecoder;

impl Decoder for OtlpTracesDecoder {
    type Item = ExportTraceServiceRequest;
    type Error = Status;

    fn decode(&mut self, source: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Status> {
        let frame = source.copy_to_bytes(source.remaining());
        preflight_otlp_traces_protobuf(frame.as_ref()).map_err(preflight_status)?;
        ExportTraceServiceRequest::decode(frame)
            .map(Some)
            .map_err(|_| malformed_status())
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
