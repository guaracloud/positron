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
    const ORDERED: [Self; 10] = [
        Self::ContainerCount,
        Self::RecordCount,
        Self::AggregateAttributeCount,
        Self::AttributesPerNamespace,
        Self::NestingDepth,
        Self::ArrayEntries,
        Self::KeyValueListEntries,
        Self::DecodedBatchBytes,
        Self::IndividualValueBytes,
        Self::KeyPathBytes,
    ];

    const fn index(self) -> usize {
        match self {
            Self::ContainerCount => 0,
            Self::RecordCount => 1,
            Self::AggregateAttributeCount => 2,
            Self::AttributesPerNamespace => 3,
            Self::NestingDepth => 4,
            Self::ArrayEntries => 5,
            Self::KeyValueListEntries => 6,
            Self::DecodedBatchBytes => 7,
            Self::IndividualValueBytes => 8,
            Self::KeyPathBytes => 9,
        }
    }

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

/// A fixed-size summary of per-record semantic limit rejections.
///
/// The receiver can reject many records, but the protocol response only needs
/// one truthful representative for each finite limit class. Keeping the
/// representatives in class order makes the result deterministic without
/// retaining producer data or allocating a request-sized collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceLimitRejectionSummary {
    violations: [Option<TraceLimitViolation>; TraceLimitClass::ORDERED.len()],
}

impl TraceLimitRejectionSummary {
    pub const EMPTY: Self = Self {
        violations: [None; TraceLimitClass::ORDERED.len()],
    };

    #[must_use]
    pub const fn new() -> Self {
        Self::EMPTY
    }

    /// Adds one representative, preferring the greatest observed actual value
    /// and then the greatest truthful allowed value for deterministic ties.
    pub fn record(&mut self, violation: TraceLimitViolation) {
        let index = violation.class().index();
        let Some(slot) = self.violations.get_mut(index) else {
            return;
        };
        let replace = slot.is_none_or(|current| {
            (violation.actual(), violation.allowed()) > (current.actual(), current.allowed())
        });
        if replace {
            *slot = Some(violation);
        }
    }

    pub fn merge(&mut self, other: Self) {
        for violation in other.violations.into_iter().flatten() {
            self.record(violation);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = TraceLimitViolation> + '_ {
        self.violations.iter().copied().flatten()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.violations.iter().all(Option::is_none)
    }
}

impl Default for TraceLimitRejectionSummary {
    fn default() -> Self {
        Self::EMPTY
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
