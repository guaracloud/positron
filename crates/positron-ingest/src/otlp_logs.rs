use std::fmt::{Display, Formatter};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use positron_domain::identity::TenantAttribution;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, ValueLimitProfile};
use positron_governance::AuthorizedContext;
use positron_kernel::{
    ResourceAmounts, ResourceGovernor, ResourceReservation, WorkClaim, WorkKind,
};
use prost::Message;

mod admission_groups;
mod bounds;
mod decoded;
mod mapping;
mod preflight;
mod request;
mod transport;

#[cfg(test)]
mod tests;

use preflight::{validate_json, validate_record_count};
use request::OtlpPayload;
use transport::bounded_payload;

pub use admission_groups::{NativeLogAdmissionGroup, NativeLogAdmissionGroups};
pub use request::{AuthenticatedOtlpLogsRequest, OtlpLogsRequestEncoding};

const RECEIVER_CAPACITY: ResourceAmounts =
    ResourceAmounts::new([4_194_304, 1, 1, 1_048_576, 1_024, 0, 0, 0, 1, 1, 0]);

/// Reserves the canonical receiver budget before an authenticated transport
/// begins structural decode or decompression.
pub fn reserve_otlp_logs_transport<'authority>(
    context: AuthorizedContext,
    governor: ResourceGovernor<'authority>,
) -> Result<ResourceReservation<'authority>, ReceiveFailure> {
    let attribution = ingest_attribution(context)?;
    let claim = WorkClaim::tenant(attribution.tenant_id(), WorkKind::Ingest, RECEIVER_CAPACITY)
        .map_err(|_| ReceiveFailure::CapacityUnavailable)?;
    governor
        .reserve(claim)
        .map_err(|_| ReceiveFailure::CapacityUnavailable)
}

/// Validates the Release 1 OTLP Logs protobuf shape before structural decoding.
pub fn preflight_otlp_logs_protobuf(protobuf: &[u8]) -> Result<(), ReceiveFailure> {
    validate_record_count(protobuf, ValueLimitProfile::release_1_system_maximum())
}

/// Validates the Release 1 OTLP Logs ProtoJSON shape before materializing decode.
pub fn preflight_otlp_logs_json(json: &[u8]) -> Result<(), ReceiveFailure> {
    validate_json(json, ValueLimitProfile::release_1_system_maximum())
}

fn ingest_attribution(context: AuthorizedContext) -> Result<TenantAttribution, ReceiveFailure> {
    context
        .tenant_attribution()
        .filter(|attribution| attribution.scope() == positron_domain::identity::Scope::Ingest)
        .ok_or(ReceiveFailure::AuthenticationRejected)
}

/// Stable receiver-side rejection classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveFailure {
    AuthenticationRejected,
    CapacityUnavailable,
    MalformedPayload,
    MalformedCompression,
    TransportLimitExceeded,
    ValueLimitExceeded,
    TimestampOutOfRange,
    UnsupportedValue,
}

impl Display for ReceiveFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OTLP Logs request was rejected")
    }
}

impl std::error::Error for ReceiveFailure {}

/// One native dynamic attribute before policy and semantic Value Limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLogAttribute {
    namespace: AttributeNamespace,
    key: String,
    occurrences: Vec<CandidateAttributeValue>,
}

impl NativeLogAttribute {
    #[must_use]
    pub const fn namespace(&self) -> AttributeNamespace {
        self.namespace
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn occurrences(&self) -> &[CandidateAttributeValue] {
        &self.occurrences
    }
}

/// One structurally decoded native Log candidate awaiting policy and limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLogCandidate {
    event_time_unix_nanos: Option<i64>,
    observed_time_unix_nanos: Option<i64>,
    body: Option<CandidateAttributeValue>,
    attributes: Vec<NativeLogAttribute>,
    metadata: positron_signals::LogMetadata,
}

impl NativeLogCandidate {
    #[must_use]
    pub const fn event_time_unix_nanos(&self) -> Option<i64> {
        self.event_time_unix_nanos
    }

    #[must_use]
    pub const fn observed_time_unix_nanos(&self) -> Option<i64> {
        self.observed_time_unix_nanos
    }

    #[must_use]
    pub const fn body(&self) -> Option<&CandidateAttributeValue> {
        self.body.as_ref()
    }

    #[must_use]
    pub fn attributes(&self) -> &[NativeLogAttribute] {
        &self.attributes
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<i64>,
        Option<i64>,
        Option<CandidateAttributeValue>,
        Vec<NativeLogAttribute>,
        positron_signals::LogMetadata,
    ) {
        (
            self.event_time_unix_nanos,
            self.observed_time_unix_nanos,
            self.body,
            self.attributes,
            self.metadata,
        )
    }
}

/// One tenant-bound native batch after protocol mapping.
#[derive(Debug)]
pub struct NativeLogBatch<'authority> {
    attribution: TenantAttribution,
    records: Vec<NativeLogCandidate>,
    value_limit_profile: ValueLimitProfile,
    decoded_bytes: u64,
    capacity: Option<ResourceReservation<'authority>>,
}

impl<'authority> NativeLogBatch<'authority> {
    #[must_use]
    pub const fn attribution(&self) -> TenantAttribution {
        self.attribution
    }

    #[must_use]
    pub fn records(&self) -> &[NativeLogCandidate] {
        &self.records
    }

    #[must_use]
    pub const fn value_limit_profile(&self) -> ValueLimitProfile {
        self.value_limit_profile
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        TenantAttribution,
        Vec<NativeLogCandidate>,
        ValueLimitProfile,
        Option<ResourceReservation<'authority>>,
    ) {
        (
            self.attribution,
            self.records,
            self.value_limit_profile,
            self.capacity,
        )
    }

    fn resize_after_decode(&mut self) -> Result<(), ReceiveFailure> {
        let record_count =
            u64::try_from(self.records.len()).map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
        let amounts =
            ResourceAmounts::new([self.decoded_bytes, 1, 1, 0, record_count, 0, 0, 0, 1, 1, 0]);
        if let Some(capacity) = self.capacity.as_mut() {
            capacity
                .try_resize(amounts)
                .map_err(|_| ReceiveFailure::CapacityUnavailable)?;
        }
        Ok(())
    }
}

/// Minimal OTLP Logs Receiver Adapter.
#[derive(Clone, Copy, Debug)]
pub struct OtlpLogsReceiver {
    value_limit_profile: ValueLimitProfile,
}

impl Default for OtlpLogsReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl OtlpLogsReceiver {
    #[must_use]
    pub const fn new() -> Self {
        Self::with_value_limit_profile(ValueLimitProfile::release_1_system_maximum())
    }

    /// Binds one validated profile snapshot to transport and semantic decode.
    #[must_use]
    pub const fn with_value_limit_profile(value_limit_profile: ValueLimitProfile) -> Self {
        Self {
            value_limit_profile,
        }
    }

    pub fn decode<'authority>(
        &self,
        request: AuthenticatedOtlpLogsRequest<'authority>,
    ) -> Result<NativeLogBatch<'authority>, ReceiveFailure> {
        let AuthenticatedOtlpLogsRequest {
            attribution,
            payload,
            capacity,
        } = request;
        let decoded = match payload {
            OtlpPayload::Decoded(decoded) => *decoded,
            encoded => match bounded_payload(encoded, self.value_limit_profile)? {
                transport::BoundedOtlpPayload::Protobuf(protobuf) => {
                    validate_record_count(&protobuf, self.value_limit_profile)?;
                    ExportLogsServiceRequest::decode(protobuf.as_slice())
                        .map_err(|_| ReceiveFailure::MalformedPayload)?
                },
                transport::BoundedOtlpPayload::Json(json) => {
                    validate_json(&json, self.value_limit_profile)?;
                    serde_json::from_slice(&json).map_err(|_| ReceiveFailure::MalformedPayload)?
                },
            },
        };
        let mut batch =
            decoded::native_batch(attribution, decoded, self.value_limit_profile, capacity)?;
        batch.resize_after_decode()?;
        Ok(batch)
    }
}
