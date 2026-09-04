use std::convert::Infallible;
use std::io::Read;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Frame, SizeHint};
use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::TraceService;
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use positron_domain::value::{ValueLimitProfile, ValueLimitProfileCandidate};
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
            return Box::pin(async move { Ok(super::codec::unimplemented_response()) });
        }
        let profile = request
            .extensions()
            .get::<ReceiverAdmissionLease>()
            .map_or_else(ValueLimitProfile::release_1_system_maximum, |lease| {
                lease.value_limit_profile()
            });
        let request_limits = profile.effective_limits().request();
        let compressed_limit = match usize::try_from(request_limits.compressed_bytes().value()) {
            Ok(limit) => limit,
            Err(_) => usize::MAX,
        };
        let decompressed_limit = match usize::try_from(request_limits.decompressed_bytes().value())
        {
            Ok(limit) => limit,
            Err(_) => usize::MAX,
        };
        let measurement = Arc::new(Mutex::new(WireMeasurement::default()));
        let request_encoding = request
            .headers()
            .get("grpc-encoding")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let request = request.map(|body| {
            BoundedGrpcBody::new(
                body,
                compressed_limit,
                decompressed_limit,
                request_encoding,
                Arc::clone(&measurement),
            )
        });
        let method = ExportService {
            inner: Arc::clone(&self.inner),
            measurement: Arc::clone(&measurement),
        };
        let accepted_compression = self.accepted_compression;
        Box::pin(async move {
            let tonic_message_limit = decompressed_limit
                .checked_add(5)
                .map_or(usize::MAX, |limit| compressed_limit.max(limit));
            let mut grpc = tonic::server::Grpc::new(OtlpTracesCodec {
                profile,
                measurement,
            })
            .apply_compression_config(accepted_compression, EnabledCompressionEncodings::default())
            .apply_max_message_size_config(Some(tonic_message_limit), None);
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
                let presence = measurement.timestamp_presence.clone().ok_or_else(|| {
                    Status::internal("OTLP Traces timestamp presence was unavailable")
                })?;
                OtlpGrpcTransportEvidence::prevalidated_with_presence(
                    measurement.wire_body_bytes,
                    measurement.decompressed_message_bytes,
                    presence,
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
        // Transport and decompressed-message ceilings are enforced by the
        // bounded body and tonic's message-size limit above. This preflight
        // must use only the system semantic profile: tenant semantic limits
        // apply after the ingest policy has had a chance to redact or
        // truncate a value.
        let system_profile = ValueLimitProfileCandidate::new(self.profile.system_limits(), None)
            .validate()
            .map_err(|_| Status::internal("OTLP Traces system profile was invalid"))?;
        preflight_otlp_traces_protobuf_with_profile(frame.as_ref(), system_profile)
            .map_err(preflight_status)?;
        let timestamp_presence =
            positron_ingest::otlp_traces_timestamp_presence_protobuf(frame.as_ref())
                .map_err(preflight_status)?;
        self.measurement
            .lock()
            .map_err(|_| Status::internal("OTLP Traces transport measurement failed"))?
            .timestamp_presence = Some(timestamp_presence);
        ExportTraceServiceRequest::decode(frame)
            .map(Some)
            .map_err(|_| malformed_status())
    }
}

#[derive(Clone, Debug, Default)]
struct WireMeasurement {
    wire_body_bytes: usize,
    decompressed_message_bytes: usize,
    timestamp_presence: Option<positron_ingest::OtlpTraceTimestampPresence>,
}

struct BoundedGrpcBody<B> {
    inner: Pin<Box<B>>,
    compressed_limit: usize,
    decompressed_limit: usize,
    request_encoding: Option<String>,
    seen: usize,
    frames_seen: usize,
    input: Vec<u8>,
    output: Option<Bytes>,
    trailers: Option<http::HeaderMap>,
    ended: bool,
    failed: bool,
    measurement: Arc<Mutex<WireMeasurement>>,
}

impl<B> BoundedGrpcBody<B> {
    fn new(
        inner: B,
        compressed_limit: usize,
        decompressed_limit: usize,
        request_encoding: Option<String>,
        measurement: Arc<Mutex<WireMeasurement>>,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            compressed_limit,
            decompressed_limit,
            request_encoding,
            seen: 0,
            frames_seen: 0,
            input: Vec::new(),
            output: None,
            trailers: None,
            ended: false,
            failed: false,
            measurement,
        }
    }

    fn decode_next_frame(&mut self) -> Result<Option<Bytes>, Status> {
        if self.input.len() < 5 {
            return Ok(None);
        }
        let Some((&flag, header)) = self
            .input
            .split_first()
            .and_then(|(flag, remaining)| remaining.get(..4).map(|header| (flag, header)))
        else {
            return Ok(None);
        };
        let compressed = flag == 1;
        let length = header
            .iter()
            .fold(0_u32, |length, byte| (length << 8) | u32::from(*byte));
        let length = usize::try_from(length).map_err(|_| receiver_limit_exceeded())?;
        let frame_length = 5_usize
            .checked_add(length)
            .ok_or_else(receiver_limit_exceeded)?;
        if self.input.len() < frame_length {
            return Ok(None);
        }
        if self.frames_seen > 0 {
            return Err(Status::invalid_argument(
                "OTLP Traces unary request contained multiple messages",
            ));
        }
        self.frames_seen = 1;
        if !compressed {
            if flag != 0 {
                return Err(Status::internal(format!(
                    "protocol error: received message with invalid compression flag: {flag} (valid flags are 0 and 1), while sending request"
                )));
            }
            if length > self.decompressed_limit {
                return Err(receiver_limit_exceeded());
            }
            let mut payload = Vec::new();
            payload
                .try_reserve_exact(length)
                .map_err(|_| receiver_limit_exceeded())?;
            let frame_payload = self.frame_payload(frame_length)?;
            payload.extend_from_slice(frame_payload);
            self.consume_input(frame_length);
            return Ok(Some(encode_uncompressed_frame(payload)?));
        }
        if self.request_encoding.as_deref() != Some("gzip") {
            return Err(Status::internal(
                "protocol error: received message with compressed-flag but no grpc-encoding was specified",
            ));
        }
        let frame_payload = self.frame_payload(frame_length)?;
        let payload = decompress_gzip(frame_payload, self.decompressed_limit)?;
        self.consume_input(frame_length);
        Ok(Some(encode_uncompressed_frame(payload)?))
    }

    fn frame_payload(&self, frame_length: usize) -> Result<&[u8], Status> {
        self.input
            .get(5..frame_length)
            .ok_or_else(|| Status::internal("OTLP Traces transport frame was incomplete"))
    }

    fn consume_input(&mut self, frame_length: usize) {
        let remaining = self.input.len().saturating_sub(frame_length);
        self.input.copy_within(frame_length.., 0);
        self.input.truncate(remaining);
    }

    fn malformed_end(&mut self) -> Result<(), Status> {
        if self.input.is_empty() {
            Ok(())
        } else {
            self.failed = true;
            Err(Status::internal("Unexpected EOF decoding stream."))
        }
    }
}

impl<B> Body for BoundedGrpcBody<B>
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Data = Bytes;
    type Error = Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        loop {
            if let Some(output) = this.output.take() {
                return Poll::Ready(Some(Ok(Frame::data(output))));
            }
            match this.decode_next_frame() {
                Ok(Some(output)) => {
                    this.output = Some(output);
                    continue;
                },
                Ok(None) => {},
                Err(error) => {
                    this.failed = true;
                    return Poll::Ready(Some(Err(error)));
                },
            }
            if let Some(trailers) = this.trailers.take() {
                return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
            }
            if this.ended {
                if let Err(error) = this.malformed_end() {
                    return Poll::Ready(Some(Err(error)));
                }
                return Poll::Ready(None);
            }
            if this.failed {
                return Poll::Ready(None);
            }
            match this.inner.as_mut().poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => {
                    if frame.is_data() {
                        let mut data = match frame.into_data() {
                            Ok(data) => data,
                            Err(_) => {
                                this.failed = true;
                                return Poll::Ready(Some(Err(Status::internal(
                                    "OTLP Traces transport frame conversion failed",
                                ))));
                            },
                        };
                        let data_bytes = data.remaining();
                        let Some(total) = this.seen.checked_add(data_bytes) else {
                            this.failed = true;
                            return Poll::Ready(Some(Err(receiver_limit_exceeded())));
                        };
                        if total > this.compressed_limit {
                            this.failed = true;
                            return Poll::Ready(Some(Err(receiver_limit_exceeded())));
                        }
                        if this.input.try_reserve(data_bytes).is_err() {
                            this.failed = true;
                            return Poll::Ready(Some(Err(receiver_limit_exceeded())));
                        }
                        while data.has_remaining() {
                            let chunk = data.chunk();
                            let chunk_length = chunk.len();
                            this.input.extend_from_slice(chunk);
                            data.advance(chunk_length);
                        }
                        this.seen = total;
                        if let Ok(mut measurement) = this.measurement.lock() {
                            measurement.wire_body_bytes = total;
                        } else {
                            this.failed = true;
                            return Poll::Ready(Some(Err(Status::internal(
                                "OTLP Traces transport measurement failed",
                            ))));
                        }
                    } else if let Ok(trailers) = frame.into_trailers() {
                        this.trailers = Some(trailers);
                        this.ended = true;
                    } else {
                        this.failed = true;
                        return Poll::Ready(Some(Err(Status::internal(
                            "OTLP Traces transport frame conversion failed",
                        ))));
                    }
                },
                Poll::Ready(Some(Err(error))) => {
                    this.failed = true;
                    return Poll::Ready(Some(Err(Status::from_error(error.into()))));
                },
                Poll::Ready(None) => {
                    this.ended = true;
                },
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended && self.output.is_none() && self.input.is_empty() && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = self.inner.as_ref().get_ref().size_hint();
        let remaining = self.compressed_limit.saturating_sub(self.seen) as u64;
        hint.set_lower(hint.lower().min(remaining));
        if let Some(upper) = hint.upper() {
            hint.set_upper(upper.min(remaining));
        }
        hint
    }
}

fn decompress_gzip(payload: &[u8], maximum: usize) -> Result<Vec<u8>, Status> {
    let read_limit = maximum.checked_add(1).ok_or_else(receiver_limit_exceeded)?;
    let mut decoded = Vec::new();
    decoded
        .try_reserve(payload.len().saturating_mul(4).min(maximum))
        .map_err(|_| receiver_limit_exceeded())?;
    flate2::read::MultiGzDecoder::new(payload)
        .take(u64::try_from(read_limit).map_err(|_| receiver_limit_exceeded())?)
        .read_to_end(&mut decoded)
        .map_err(|_| Status::internal("OTLP Traces request compression was malformed"))?;
    if decoded.len() > maximum {
        return Err(receiver_limit_exceeded());
    }
    Ok(decoded)
}

fn encode_uncompressed_frame(mut payload: Vec<u8>) -> Result<Bytes, Status> {
    let payload_length = payload.len();
    let length = u32::try_from(payload_length).map_err(|_| receiver_limit_exceeded())?;
    payload
        .try_reserve_exact(5)
        .map_err(|_| receiver_limit_exceeded())?;
    let frame_length = payload_length
        .checked_add(5)
        .ok_or_else(receiver_limit_exceeded)?;
    payload.resize(frame_length, 0);
    payload.copy_within(..payload_length, 5);
    let Some(header) = payload.get_mut(..5) else {
        return Err(Status::internal(
            "OTLP Traces transport frame was incomplete",
        ));
    };
    header.fill(0);
    header[1..].copy_from_slice(&length.to_be_bytes());
    Ok(Bytes::from(payload))
}

fn receiver_limit_exceeded() -> Status {
    Status::resource_exhausted("OTLP Traces request exceeds the receiver limit")
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
