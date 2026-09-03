use positron_domain::time::EventTime;
use positron_domain::value::{AttributeNamespace, AttributeOccurrenceSet, ValueLimitProfile};

use super::details::SpanObservationDetails;
use super::failure::TraceStoreFailure;
use super::types::release_1_limits;

/// The protocol-neutral OTLP span kind retained by the Trace Store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpanKind {
    /// The producer did not provide a span kind.
    Unspecified,
    /// An internal operation.
    Internal,
    /// A server-side operation.
    Server,
    /// A client-side operation.
    Client,
    /// A producer operation.
    Producer,
    /// A consumer operation.
    Consumer,
}

/// The producer's sampling decision, retained without inferring a decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SamplingDecision {
    /// Sampling was not specified by the producer.
    Unknown,
    /// The producer explicitly marked this span as not sampled.
    NotSampled,
    /// The producer explicitly marked this span as sampled.
    Sampled,
}

/// One immutable native Span Observation before logical-span consolidation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanObservation {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    name: String,
    start_time: EventTime,
    end_time: EventTime,
    attributes: Vec<AttributeOccurrenceSet>,
    kind: SpanKind,
    sampling: SamplingDecision,
    policy: positron_policy::PolicyProvenance,
    details: SpanObservationDetails,
}

impl SpanObservation {
    /// The maximum native span name size for Release 1.
    pub const MAX_NAME_BYTES: usize = ValueLimitProfile::release_1_system_maximum()
        .system_limits()
        .dynamic_value()
        .key_path_bytes()
        .value() as usize;

    /// Builds a native observation with explicit policy provenance and no
    /// protocol detail extensions.
    #[allow(clippy::too_many_arguments)]
    pub fn checked_native(
        trace_id: [u8; 16],
        span_id: [u8; 8],
        parent_span_id: Option<[u8; 8]>,
        name: String,
        start_time: EventTime,
        end_time: EventTime,
        attributes: Vec<AttributeOccurrenceSet>,
        kind: SpanKind,
        sampling: SamplingDecision,
        policy: positron_policy::PolicyProvenance,
    ) -> Result<Self, TraceStoreFailure> {
        Self::checked_native_with_details(
            trace_id,
            span_id,
            parent_span_id,
            name,
            start_time,
            end_time,
            attributes,
            kind,
            sampling,
            policy,
            SpanObservationDetails::default(),
        )
    }

    /// Builds a native observation with lossless OTLP span details.
    #[allow(clippy::too_many_arguments)]
    pub fn checked_native_with_details(
        trace_id: [u8; 16],
        span_id: [u8; 8],
        parent_span_id: Option<[u8; 8]>,
        name: String,
        start_time: EventTime,
        end_time: EventTime,
        attributes: Vec<AttributeOccurrenceSet>,
        kind: SpanKind,
        sampling: SamplingDecision,
        policy: positron_policy::PolicyProvenance,
        details: SpanObservationDetails,
    ) -> Result<Self, TraceStoreFailure> {
        let limits = release_1_limits()?;
        if trace_id.iter().all(|byte| *byte == 0)
            || span_id.iter().all(|byte| *byte == 0)
            || parent_span_id.is_some_and(|id| id.iter().all(|byte| *byte == 0))
            || name.is_empty()
            || name.len() > limits.key_path_bytes
        {
            return Err(TraceStoreFailure::invalid_input());
        }
        if start_time
            .instant()
            .zip(end_time.instant())
            .is_some_and(|(start, end)| end < start)
        {
            return Err(TraceStoreFailure::invalid_input());
        }
        if !attributes.is_empty() && attributes.len() > limits.attribute_sets {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        let mut occurrences_by_namespace = [0_usize; 3];
        let mut decoded_bytes = name.len();
        for attribute in &attributes {
            let namespace_index = namespace_index(attribute.namespace())?;
            occurrences_by_namespace[namespace_index] = occurrences_by_namespace[namespace_index]
                .checked_add(attribute.len())
                .filter(|count| *count <= limits.occurrences_per_namespace)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            decoded_bytes = decoded_bytes
                .checked_add(attribute.key().len())
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            for index in 0..attribute.len() {
                let value = attribute
                    .occurrence(index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                decoded_bytes = decoded_bytes
                    .checked_add(
                        value
                            .decoded_size_bytes()
                            .map_err(TraceStoreFailure::domain)?,
                    )
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            }
        }
        let detail_bytes = details.decoded_size_bytes(limits.decoded_bytes)?;
        if decoded_bytes
            .checked_add(detail_bytes)
            .is_none_or(|size| size > limits.decoded_bytes)
        {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        Ok(Self {
            trace_id,
            span_id,
            parent_span_id,
            name,
            start_time,
            end_time,
            attributes,
            kind,
            sampling,
            policy,
            details,
        })
    }

    /// Builds a native observation from the producer-neutral policy output.
    /// Policy attributes remain unvalidated until this transition, ensuring
    /// every accepted trace crosses the same Signal Store limits as other
    /// native producers.
    #[allow(clippy::too_many_arguments)]
    pub fn checked_native_with_policy_attributes(
        trace_id: [u8; 16],
        span_id: [u8; 8],
        parent_span_id: Option<[u8; 8]>,
        name: String,
        start_time: EventTime,
        end_time: EventTime,
        attributes: Vec<positron_policy::NativePolicyAttribute>,
        kind: SpanKind,
        sampling: SamplingDecision,
        policy: positron_policy::PolicyProvenance,
        details: SpanObservationDetails,
        profile: ValueLimitProfile,
    ) -> Result<Self, TraceStoreFailure> {
        let mut checked = Vec::new();
        checked
            .try_reserve_exact(attributes.len())
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        for attribute in attributes {
            let (namespace, key, occurrences) = attribute.into_parts();
            checked.push(
                positron_domain::value::AttributeOccurrenceSetCandidate::new(
                    namespace,
                    key,
                    occurrences,
                )
                .validate(profile)
                .map_err(TraceStoreFailure::domain)?,
            );
        }
        Self::checked_native_with_details(
            trace_id,
            span_id,
            parent_span_id,
            name,
            start_time,
            end_time,
            checked,
            kind,
            sampling,
            policy,
            details,
        )
    }

    #[must_use]
    pub const fn trace_id(&self) -> [u8; 16] {
        self.trace_id
    }

    #[must_use]
    pub const fn span_id(&self) -> [u8; 8] {
        self.span_id
    }

    #[must_use]
    pub const fn parent_span_id(&self) -> Option<[u8; 8]> {
        self.parent_span_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn start_time(&self) -> EventTime {
        self.start_time
    }

    #[must_use]
    pub const fn end_time(&self) -> EventTime {
        self.end_time
    }

    #[must_use]
    pub fn attributes(&self) -> &[AttributeOccurrenceSet] {
        &self.attributes
    }

    #[must_use]
    pub const fn kind(&self) -> SpanKind {
        self.kind
    }

    #[must_use]
    pub const fn sampling(&self) -> SamplingDecision {
        self.sampling
    }

    #[must_use]
    pub const fn policy_provenance(&self) -> &positron_policy::PolicyProvenance {
        &self.policy
    }

    /// Returns the immutable OTLP detail payload retained by this observation.
    #[must_use]
    pub const fn details(&self) -> &SpanObservationDetails {
        &self.details
    }

    /// Rebinds one observation to the authenticated active policy snapshot.
    /// The immutable OTLP fields are reconstructed byte-for-byte from the
    /// existing native value; only policy provenance changes.
    pub fn with_policy_provenance(
        self,
        policy: positron_policy::PolicyProvenance,
    ) -> Result<Self, TraceStoreFailure> {
        Self::checked_native_with_details(
            self.trace_id,
            self.span_id,
            self.parent_span_id,
            self.name,
            self.start_time,
            self.end_time,
            self.attributes,
            self.kind,
            self.sampling,
            policy,
            self.details,
        )
    }
}

fn namespace_index(namespace: AttributeNamespace) -> Result<usize, TraceStoreFailure> {
    match namespace {
        AttributeNamespace::Resource => Ok(0),
        AttributeNamespace::InstrumentationScope => Ok(1),
        AttributeNamespace::Record => Ok(2),
        AttributeNamespace::Stream => Err(TraceStoreFailure::invalid_input()),
    }
}
