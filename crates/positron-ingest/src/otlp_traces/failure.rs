use std::fmt::{Display, Formatter};

/// Stable receiver-side rejection classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceReceiveFailure {
    AuthenticationRejected,
    CapacityUnavailable,
    MalformedPayload,
    MalformedCompression,
    TransportLimitExceeded,
    PolicyEvaluationFailed,
    ValueLimitExceeded,
    TimestampOutOfRange,
    UnsupportedValue,
}

impl Display for TraceReceiveFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OTLP Traces request was rejected")
    }
}

impl std::error::Error for TraceReceiveFailure {}
