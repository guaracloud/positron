use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_server::LogsService;
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use positron_ingest::{ReceiveFailure, preflight_otlp_logs_protobuf};
use prost::Message;
use prost::bytes::Buf;
use tonic::codec::{
    Codec, CompressionEncoding, DecodeBuf, Decoder, EnabledCompressionEncodings, EncodeBuf, Encoder,
};
use tonic::codegen::{Body, BoxFuture, Service, StdError};
use tonic::{Request, Response, Status};

const EXPORT_PATH: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";
const SERVICE_NAME: &str = "opentelemetry.proto.collector.logs.v1.LogsService";

#[derive(Debug)]
pub(super) struct OtlpLogsServer<T> {
    inner: Arc<T>,
    accepted_compression: EnabledCompressionEncodings,
    maximum_decoding_bytes: Option<usize>,
}

impl<T> OtlpLogsServer<T> {
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

impl<T> Clone for OtlpLogsServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            accepted_compression: self.accepted_compression,
            maximum_decoding_bytes: self.maximum_decoding_bytes,
        }
    }
}

impl<T, B> Service<http::Request<B>> for OtlpLogsServer<T>
where
    T: LogsService,
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
            let mut grpc = tonic::server::Grpc::new(OtlpLogsCodec)
                .apply_compression_config(
                    accepted_compression,
                    EnabledCompressionEncodings::default(),
                )
                .apply_max_message_size_config(maximum_decoding_bytes, None);
            Ok(grpc.unary(method, request).await)
        })
    }
}

impl<T> tonic::server::NamedService for OtlpLogsServer<T> {
    const NAME: &'static str = SERVICE_NAME;
}

struct ExportService<T>(Arc<T>);

impl<T: LogsService> tonic::server::UnaryService<ExportLogsServiceRequest> for ExportService<T> {
    type Response = ExportLogsServiceResponse;
    type Future = BoxFuture<Response<Self::Response>, Status>;

    fn call(&mut self, request: Request<ExportLogsServiceRequest>) -> Self::Future {
        let inner = Arc::clone(&self.0);
        Box::pin(async move { T::export(&inner, request).await })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct OtlpLogsCodec;

impl Codec for OtlpLogsCodec {
    type Encode = ExportLogsServiceResponse;
    type Decode = ExportLogsServiceRequest;
    type Encoder = OtlpLogsEncoder;
    type Decoder = OtlpLogsDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        OtlpLogsEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        OtlpLogsDecoder
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct OtlpLogsEncoder;

impl Encoder for OtlpLogsEncoder {
    type Item = ExportLogsServiceResponse;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, destination: &mut EncodeBuf<'_>) -> Result<(), Status> {
        item.encode(destination)
            .map_err(|_| Status::internal("OTLP Logs response encoding failed"))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct OtlpLogsDecoder;

impl Decoder for OtlpLogsDecoder {
    type Item = ExportLogsServiceRequest;
    type Error = Status;

    fn decode(&mut self, source: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Status> {
        let frame = source.copy_to_bytes(source.remaining());
        preflight_otlp_logs_protobuf(frame.as_ref()).map_err(preflight_status)?;
        ExportLogsServiceRequest::decode(frame)
            .map(Some)
            .map_err(|_| malformed_status())
    }
}

fn preflight_status(failure: ReceiveFailure) -> Status {
    match failure {
        ReceiveFailure::MalformedPayload => malformed_status(),
        _ => Status::invalid_argument("OTLP Logs request was rejected"),
    }
}

fn malformed_status() -> Status {
    Status::invalid_argument("OTLP Logs request was malformed")
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

#[cfg(test)]
#[path = "codec/tests/mod.rs"]
mod tests;
