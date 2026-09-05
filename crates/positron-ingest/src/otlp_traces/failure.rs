use std::fmt::{Display, Formatter};

/// The semantic value dimension that rejected a bounded receiver payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceLimitClass {
    ContainerCount,
    RecordCount,
    AggregateAttributeCount,
    AttributesPerNamespace,
    NestingDepth,
    ArrayEntries,
    KeyValueListEntries,
    DecodedBatchBytes,
    IndividualValueBytes,
    KeyPathBytes,
}

impl TraceLimitClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ContainerCount => "container count",
            Self::RecordCount => "record count",
            Self::AggregateAttributeCount => "aggregate attribute count",
            Self::AttributesPerNamespace => "attributes per namespace",
            Self::NestingDepth => "nesting depth",
            Self::ArrayEntries => "array entries",
            Self::KeyValueListEntries => "key/value-list entries",
            Self::DecodedBatchBytes => "decoded batch bytes",
            Self::IndividualValueBytes => "individual value bytes",
            Self::KeyPathBytes => "key/path bytes",
        }
    }
}

/// Safe, protocol-neutral detail for a semantic limit failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceLimitViolation {
    class: TraceLimitClass,
    actual: u64,
    allowed: u64,
}

impl TraceLimitViolation {
    #[must_use]
    pub const fn new(class: TraceLimitClass, actual: u64, allowed: u64) -> Self {
        Self {
            class,
            actual,
            allowed,
        }
    }

    #[must_use]
    pub const fn class(self) -> TraceLimitClass {
        self.class
    }

    #[must_use]
    pub const fn actual(self) -> u64 {
        self.actual
    }

    #[must_use]
    pub const fn allowed(self) -> u64 {
        self.allowed
    }
}

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
    ValueLimitExceededWithDetail(TraceLimitViolation),
    TimestampOutOfRange,
    UnsupportedValue,
}

impl Display for TraceReceiveFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValueLimitExceededWithDetail(detail) => write!(
                formatter,
                "OTLP Traces request exceeded a value limit ({}: actual {}, allowed {})",
                detail.class().label(),
                detail.actual(),
                detail.allowed(),
            ),
            _ => formatter.write_str("OTLP Traces request was rejected"),
        }
    }
}

impl std::error::Error for TraceReceiveFailure {}
