use std::fmt::{Display, Formatter};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use positron_domain::identity::TenantAttribution;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, ValueLimitProfile};
use positron_governance::AuthorizedContext;
use positron_kernel::{
    ResourceAmounts, ResourceGovernor, ResourceReservation, WorkClaim, WorkKind,
};
use prost::Message;

mod bounds;
mod mapping;
mod preflight;
mod transport;

use bounds::decoded_record_bytes;
use mapping::{candidate_value, checked_timestamp, grouped_attributes};
use preflight::validate_record_count;
use transport::bounded_protobuf;

const RECEIVER_CAPACITY: ResourceAmounts =
    ResourceAmounts::new([4_194_304, 1, 1, 1_048_576, 1_024, 0, 0, 0, 1, 0, 0]);

enum OtlpPayload {
    Protobuf(Vec<u8>),
    GzipProtobuf(Vec<u8>),
}

/// OTLP bytes that can exist only after authoritative tenant attribution.
///
/// ```compile_fail
/// use positron_ingest::AuthenticatedOtlpLogsRequest;
///
/// // Raw protocol bytes cannot reach the Receiver Adapter without a checked
/// // Tenant Attribution created by the identity boundary.
/// let _ = AuthenticatedOtlpLogsRequest::new(vec![0_u8]);
/// ```
pub struct AuthenticatedOtlpLogsRequest<'authority> {
    attribution: TenantAttribution,
    payload: OtlpPayload,
    capacity: Option<ResourceReservation<'authority>>,
}

impl<'authority> AuthenticatedOtlpLogsRequest<'authority> {
    pub fn protobuf(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        protobuf: Vec<u8>,
    ) -> Result<Self, ReceiveFailure> {
        Self::admit(context, governor, OtlpPayload::Protobuf(protobuf))
    }

    pub fn gzip_protobuf(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        gzip_protobuf: Vec<u8>,
    ) -> Result<Self, ReceiveFailure> {
        Self::admit(context, governor, OtlpPayload::GzipProtobuf(gzip_protobuf))
    }

    fn admit(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        payload: OtlpPayload,
    ) -> Result<Self, ReceiveFailure> {
        let attribution = context
            .tenant_attribution()
            .filter(|attribution| attribution.scope() == positron_domain::identity::Scope::Ingest)
            .ok_or(ReceiveFailure::AuthenticationRejected)?;
        let maximum_request_bytes = usize::try_from(
            ValueLimitProfile::release_1_system_maximum()
                .system_limits()
                .request()
                .compressed_bytes()
                .value(),
        )
        .map_err(|_| ReceiveFailure::TransportLimitExceeded)?;
        if payload.encoded_len() > maximum_request_bytes {
            return Err(ReceiveFailure::TransportLimitExceeded);
        }
        let claim = WorkClaim::tenant(attribution.tenant_id(), WorkKind::Ingest, RECEIVER_CAPACITY)
            .map_err(|_| ReceiveFailure::CapacityUnavailable)?;
        let capacity = governor
            .reserve(claim)
            .map_err(|_| ReceiveFailure::CapacityUnavailable)?;
        Ok(Self {
            attribution,
            payload,
            capacity: Some(capacity),
        })
    }

    #[cfg(any(test, fuzzing))]
    #[must_use]
    pub fn test_only_protobuf(attribution: TenantAttribution, protobuf: Vec<u8>) -> Self {
        Self {
            attribution,
            payload: OtlpPayload::Protobuf(protobuf),
            capacity: None,
        }
    }

    #[cfg(any(test, fuzzing))]
    #[must_use]
    pub fn test_only_gzip(attribution: TenantAttribution, gzip_protobuf: Vec<u8>) -> Self {
        Self {
            attribution,
            payload: OtlpPayload::GzipProtobuf(gzip_protobuf),
            capacity: None,
        }
    }
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
    ) {
        (
            self.event_time_unix_nanos,
            self.observed_time_unix_nanos,
            self.body,
            self.attributes,
        )
    }
}

/// One tenant-bound native batch after protocol mapping.
#[derive(Debug)]
pub struct NativeLogBatch {
    attribution: TenantAttribution,
    records: Vec<NativeLogCandidate>,
    value_limit_profile: ValueLimitProfile,
}

impl NativeLogBatch {
    #[must_use]
    pub const fn attribution(&self) -> TenantAttribution {
        self.attribution
    }

    #[must_use]
    pub fn records(&self) -> &[NativeLogCandidate] {
        &self.records
    }

    #[must_use]
    pub fn into_records(self) -> Vec<NativeLogCandidate> {
        self.records
    }

    #[must_use]
    pub const fn value_limit_profile(&self) -> ValueLimitProfile {
        self.value_limit_profile
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

    pub fn decode(
        &self,
        request: AuthenticatedOtlpLogsRequest,
    ) -> Result<NativeLogBatch, ReceiveFailure> {
        let AuthenticatedOtlpLogsRequest {
            attribution,
            payload,
            capacity,
        } = request;
        let _capacity = capacity;
        let protobuf = bounded_protobuf(payload, self.value_limit_profile)?;
        validate_record_count(&protobuf, self.value_limit_profile)?;
        let decoded = ExportLogsServiceRequest::decode(protobuf.as_slice())
            .map_err(|_| ReceiveFailure::MalformedPayload)?;
        let mut records = Vec::new();
        let mut attribute_count = 0_usize;
        let mut decoded_batch_bytes = 0_usize;
        let encoded_record_limit = usize::try_from(
            self.value_limit_profile
                .effective_limits()
                .record()
                .encoded_bytes()
                .value(),
        )
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
        let structural_nesting_depth = self
            .value_limit_profile
            .system_limits()
            .dynamic_value()
            .nesting_depth()
            .value();
        let structural_decoded_record_bytes = usize::try_from(
            self.value_limit_profile
                .system_limits()
                .record()
                .decoded_bytes()
                .value(),
        )
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
        let structural_decoded_batch_bytes = usize::try_from(
            self.value_limit_profile
                .system_limits()
                .request()
                .decompressed_bytes()
                .value(),
        )
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
        let structural_record_limit = usize::try_from(
            self.value_limit_profile
                .system_limits()
                .request()
                .records()
                .value(),
        )
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
        let structural_attribute_limit = usize::try_from(
            self.value_limit_profile
                .system_limits()
                .request()
                .aggregate_attributes()
                .value(),
        )
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
        for resource_logs in decoded.resource_logs {
            let resource = resource_logs
                .resource
                .map_or_else(Vec::new, |value| value.attributes);
            for scope_logs in resource_logs.scope_logs {
                let scope = scope_logs
                    .scope
                    .map_or_else(Vec::new, |value| value.attributes);
                for log in scope_logs.log_records {
                    if records.len() == structural_record_limit
                        || log.encoded_len() > encoded_record_limit
                    {
                        return Err(ReceiveFailure::ValueLimitExceeded);
                    }
                    let decoded_record_bytes = decoded_record_bytes(
                        &resource,
                        &scope,
                        &log,
                        structural_nesting_depth,
                        structural_decoded_record_bytes,
                    )?;
                    decoded_batch_bytes = decoded_batch_bytes
                        .checked_add(decoded_record_bytes)
                        .filter(|bytes| *bytes <= structural_decoded_batch_bytes)
                        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
                    attribute_count = attribute_count
                        .checked_add(resource.len())
                        .and_then(|count| count.checked_add(scope.len()))
                        .and_then(|count| count.checked_add(log.attributes.len()))
                        .filter(|count| *count <= structural_attribute_limit)
                        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
                    let body = log
                        .body
                        .map(|value| candidate_value(value, structural_nesting_depth))
                        .transpose()?;
                    let attributes = grouped_attributes(
                        &resource,
                        &scope,
                        &log.attributes,
                        structural_nesting_depth,
                    )?;
                    let event_time = Some(checked_timestamp(log.time_unix_nano)?);
                    let observed_time_unix_nanos =
                        Some(checked_timestamp(log.observed_time_unix_nano)?);
                    records.push(NativeLogCandidate {
                        event_time_unix_nanos: event_time,
                        observed_time_unix_nanos,
                        body,
                        attributes,
                    });
                }
            }
        }
        Ok(NativeLogBatch {
            attribution,
            records,
            value_limit_profile: self.value_limit_profile,
        })
    }
}

impl OtlpPayload {
    fn encoded_len(&self) -> usize {
        match self {
            Self::Protobuf(bytes) | Self::GzipProtobuf(bytes) => bytes.len(),
        }
    }
}
