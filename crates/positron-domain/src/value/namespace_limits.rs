use crate::outcome::{DomainFailure, FailureSource};

/// The native namespace that owns one dynamic attribute occurrence.
///
/// Resource, instrumentation-scope, and record attributes remain separate even
/// when their textual paths match. This taxonomy is not a wire representation
/// and never allows an attribute to shadow a signal-defined intrinsic field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AttributeNamespace {
    /// String attributes shared by records received in one stream.
    Stream,
    /// Attributes attached to the telemetry resource.
    Resource,
    /// Attributes attached to the instrumentation scope.
    InstrumentationScope,
    /// Attributes attached to the individual signal record.
    Record,
}
impl AttributeNamespace {
    /// Returns the stable lowercase native namespace name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stream => "stream",
            Self::Resource => "resource",
            Self::InstrumentationScope => "instrumentation-scope",
            Self::Record => "record",
        }
    }
}

/// A non-zero byte bound used by a Value Limit Profile.
///
/// This native unit prevents byte counts from being confused with collection
/// entries or nesting depth. Configuration owns source loading and system
/// ceilings; this type makes no wire or durable serialization promise.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ByteLimit(u32);

impl ByteLimit {
    /// Creates a non-zero byte limit.
    pub fn new(value: u32) -> Result<Self, DomainFailure> {
        if value == 0 {
            return Err(DomainFailure::invalid_limit(FailureSource::ValueLimit));
        }
        Ok(Self(value))
    }

    /// Returns the exact bounded byte count.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// A non-zero collection-entry bound used by a Value Limit Profile.
///
/// This unit remains distinct from bytes and nesting so a caller cannot use an
/// allocation byte budget as an attribute or array count by accident.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CollectionLimit(u32);

impl CollectionLimit {
    /// Creates a non-zero collection-entry limit.
    pub fn new(value: u32) -> Result<Self, DomainFailure> {
        if value == 0 {
            return Err(DomainFailure::invalid_limit(FailureSource::ValueLimit));
        }
        Ok(Self(value))
    }

    /// Returns the exact bounded entry count.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// A non-zero nesting-depth bound used by a Value Limit Profile.
///
/// It is intentionally a separate unit from byte and collection limits. A
/// receiver must apply it before recursive decode or construction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NestingLimit(u16);

impl NestingLimit {
    /// Creates a non-zero nesting-depth limit.
    pub fn new(value: u16) -> Result<Self, DomainFailure> {
        if value == 0 {
            return Err(DomainFailure::invalid_limit(FailureSource::ValueLimit));
        }
        Ok(Self(value))
    }

    /// Returns the exact bounded nesting depth.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Checked request-level bounds in one Value Limit Profile.
///
/// These limits are native domain values, not wire or durable serialization
/// formats. Receiver adapters apply compressed and decompressed byte bounds
/// before structural decode; record and aggregate-attribute bounds are
/// semantic limits applied after Ingest Policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestLimits {
    request_compressed_bytes: ByteLimit,
    request_decompressed_bytes: ByteLimit,
    request_records: CollectionLimit,
    request_attributes: CollectionLimit,
}

impl RequestLimits {
    /// Groups all transport and aggregate request bounds.
    #[must_use]
    pub const fn new(
        request_compressed_bytes: ByteLimit,
        request_decompressed_bytes: ByteLimit,
        request_records: CollectionLimit,
        request_attributes: CollectionLimit,
    ) -> Self {
        Self {
            request_compressed_bytes,
            request_decompressed_bytes,
            request_records,
            request_attributes,
        }
    }

    /// Returns the maximum compressed bytes in one request.
    #[must_use]
    pub const fn compressed_bytes(self) -> ByteLimit {
        self.request_compressed_bytes
    }

    /// Returns the maximum decompressed bytes in one request.
    #[must_use]
    pub const fn decompressed_bytes(self) -> ByteLimit {
        self.request_decompressed_bytes
    }

    /// Returns the maximum records admitted in one request.
    #[must_use]
    pub const fn records(self) -> CollectionLimit {
        self.request_records
    }

    /// Returns the maximum aggregate attributes admitted in one request.
    #[must_use]
    pub const fn aggregate_attributes(self) -> CollectionLimit {
        self.request_attributes
    }

    const fn exceeds(self, system: Self) -> bool {
        self.request_compressed_bytes.value() > system.request_compressed_bytes.value()
            || self.request_decompressed_bytes.value() > system.request_decompressed_bytes.value()
            || self.request_records.value() > system.request_records.value()
            || self.request_attributes.value() > system.request_attributes.value()
    }
}

/// Checked encoded, decoded, and log-body record bounds in one profile.
///
/// These limits are native domain values, not wire or durable serialization
/// formats. Record owners bound encoded input during safe structural decode;
/// decoded-record and log-body bounds are semantic limits applied after Ingest
/// Policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordLimits {
    encoded_record_bytes: ByteLimit,
    decoded_record_bytes: ByteLimit,
    log_body_bytes: ByteLimit,
}

impl RecordLimits {
    /// Groups the distinct encoded, decoded, and log-body record bounds.
    #[must_use]
    pub const fn new(
        encoded_record_bytes: ByteLimit,
        decoded_record_bytes: ByteLimit,
        log_body_bytes: ByteLimit,
    ) -> Self {
        Self {
            encoded_record_bytes,
            decoded_record_bytes,
            log_body_bytes,
        }
    }

    /// Returns the maximum encoded bytes in one record.
    #[must_use]
    pub const fn encoded_bytes(self) -> ByteLimit {
        self.encoded_record_bytes
    }

    /// Returns the maximum decoded bytes in one record.
    #[must_use]
    pub const fn decoded_bytes(self) -> ByteLimit {
        self.decoded_record_bytes
    }

    /// Returns the maximum bytes in one log body.
    #[must_use]
    pub const fn log_body_bytes(self) -> ByteLimit {
        self.log_body_bytes
    }

    const fn exceeds(self, system: Self) -> bool {
        self.encoded_record_bytes.value() > system.encoded_record_bytes.value()
            || self.decoded_record_bytes.value() > system.decoded_record_bytes.value()
            || self.log_body_bytes.value() > system.log_body_bytes.value()
    }
}
