//! Shared OTLP transport representation.

/// Supported OTLP request body encodings after HTTP metadata validation.
///
/// This representation is signal-neutral: Logs and Traces use the same
/// protocol media types and compression variants while retaining their own
/// receiver adapters and payload types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OtlpRequestEncoding {
    Protobuf,
    GzipProtobuf,
    Json,
    GzipJson,
}
