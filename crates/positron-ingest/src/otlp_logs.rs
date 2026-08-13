use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use positron_domain::identity::TenantAttribution;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, CandidateKeyValue};
use positron_governance::AuthorizedContext;
use positron_kernel::{
    ResourceAmounts, ResourceGovernor, ResourceReservation, WorkClaim, WorkKind,
};
use prost::Message;

mod bounds;
mod transport;

use bounds::{MAX_DECODED_BATCH_BYTES, decoded_record_bytes};
use transport::bounded_protobuf;

const MAX_REQUEST_BYTES: usize = 1_048_576;
const MAX_RECORDS: usize = 1_024;
const MAX_ATTRIBUTES: usize = 4_096;
const MAX_NESTING_DEPTH: u16 = 16;
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
        if payload.encoded_len() > MAX_REQUEST_BYTES {
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
}

/// Minimal OTLP Logs Receiver Adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct OtlpLogsReceiver;

impl OtlpLogsReceiver {
    #[must_use]
    pub const fn new() -> Self {
        Self
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
        let protobuf = bounded_protobuf(payload)?;
        let decoded = ExportLogsServiceRequest::decode(protobuf.as_slice())
            .map_err(|_| ReceiveFailure::MalformedPayload)?;
        let mut records = Vec::new();
        let mut attribute_count = 0_usize;
        let mut decoded_batch_bytes = 0_usize;
        for resource_logs in decoded.resource_logs {
            let resource = resource_logs
                .resource
                .map_or_else(Vec::new, |value| value.attributes);
            for scope_logs in resource_logs.scope_logs {
                let scope = scope_logs
                    .scope
                    .map_or_else(Vec::new, |value| value.attributes);
                for log in scope_logs.log_records {
                    if records.len() == MAX_RECORDS || log.encoded_len() > MAX_REQUEST_BYTES {
                        return Err(ReceiveFailure::ValueLimitExceeded);
                    }
                    let decoded_record_bytes = decoded_record_bytes(&resource, &scope, &log)?;
                    decoded_batch_bytes = decoded_batch_bytes
                        .checked_add(decoded_record_bytes)
                        .filter(|bytes| *bytes <= MAX_DECODED_BATCH_BYTES)
                        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
                    attribute_count = attribute_count
                        .checked_add(resource.len())
                        .and_then(|count| count.checked_add(scope.len()))
                        .and_then(|count| count.checked_add(log.attributes.len()))
                        .filter(|count| *count <= MAX_ATTRIBUTES)
                        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
                    let body = log
                        .body
                        .map(|value| candidate_value(value, MAX_NESTING_DEPTH))
                        .transpose()?;
                    let attributes = grouped_attributes(&resource, &scope, &log.attributes)?;
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
        })
    }
}

fn checked_timestamp(value: u64) -> Result<i64, ReceiveFailure> {
    i64::try_from(value).map_err(|_| ReceiveFailure::TimestampOutOfRange)
}

impl OtlpPayload {
    fn encoded_len(&self) -> usize {
        match self {
            Self::Protobuf(bytes) | Self::GzipProtobuf(bytes) => bytes.len(),
        }
    }
}

fn grouped_attributes(
    resource: &[KeyValue],
    scope: &[KeyValue],
    record: &[KeyValue],
) -> Result<Vec<NativeLogAttribute>, ReceiveFailure> {
    let mut groups = BTreeMap::<(AttributeNamespace, String), Vec<CandidateAttributeValue>>::new();
    for (namespace, attributes) in [
        (AttributeNamespace::Resource, resource),
        (AttributeNamespace::InstrumentationScope, scope),
        (AttributeNamespace::Record, record),
    ] {
        for attribute in attributes {
            let candidate = match &attribute.value {
                Some(value) => candidate_value(value.clone(), MAX_NESTING_DEPTH)?,
                None => CandidateAttributeValue::null(),
            };
            groups
                .entry((namespace, attribute.key.clone()))
                .or_default()
                .push(candidate);
        }
    }
    Ok(groups
        .into_iter()
        .map(|((namespace, key), occurrences)| NativeLogAttribute {
            namespace,
            key,
            occurrences,
        })
        .collect())
}

fn candidate_value(
    value: AnyValue,
    remaining_depth: u16,
) -> Result<CandidateAttributeValue, ReceiveFailure> {
    let Some(value) = value.value else {
        return Ok(CandidateAttributeValue::null());
    };
    match value {
        any_value::Value::StringValue(value) => Ok(CandidateAttributeValue::string(value)),
        any_value::Value::BoolValue(value) => Ok(CandidateAttributeValue::boolean(value)),
        any_value::Value::IntValue(value) => Ok(CandidateAttributeValue::signed_integer(value)),
        any_value::Value::DoubleValue(value) => Ok(CandidateAttributeValue::floating_point_bits(
            value.to_bits(),
        )),
        any_value::Value::BytesValue(value) => Ok(CandidateAttributeValue::bytes(value)),
        any_value::Value::StringValueStrindex(_) => Err(ReceiveFailure::UnsupportedValue),
        any_value::Value::ArrayValue(value) => {
            let next = remaining_depth
                .checked_sub(1)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            value
                .values
                .into_iter()
                .map(|value| candidate_value(value, next))
                .collect::<Result<Vec<_>, _>>()
                .map(CandidateAttributeValue::array)
        },
        any_value::Value::KvlistValue(value) => {
            let next = remaining_depth
                .checked_sub(1)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            value
                .values
                .into_iter()
                .map(|entry| {
                    let value = entry.value.map_or_else(
                        || Ok(CandidateAttributeValue::null()),
                        |value| candidate_value(value, next),
                    )?;
                    Ok(CandidateKeyValue::new(entry.key, value))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(CandidateAttributeValue::key_value_list)
        },
    }
}
