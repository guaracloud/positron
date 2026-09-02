use positron_domain::time::EventTime;
use positron_domain::value::{AttributeOccurrenceSet, ValueLimitProfile};
use positron_kernel::{IngestTime, PreparedStoreBlock};

use super::failure::TraceStoreFailure;

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
///
/// The Trace Store deliberately stores observations rather than logical spans.
/// Duplicate and conflicting observations therefore remain available to the
/// later consolidation ticket and can never be overwritten at this seam.
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
}

impl SpanObservation {
    /// The maximum native span name size for Release 1.
    pub const MAX_NAME_BYTES: usize = ValueLimitProfile::release_1_system_maximum()
        .system_limits()
        .dynamic_value()
        .key_path_bytes()
        .value() as usize;

    /// Builds a native observation with an explicit policy provenance.
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
        let limits = release_1_limits()?;
        if trace_id.iter().all(|byte| *byte == 0)
            || span_id.iter().all(|byte| *byte == 0)
            || parent_span_id.is_some_and(|id| id.iter().all(|byte| *byte == 0))
            || name.is_empty()
            || name.len() > limits.key_path_bytes
        {
            return Err(TraceStoreFailure::invalid_input());
        }
        if attributes.is_empty() {
            // Empty attribute collections are valid native spans.
        } else if attributes.len() > limits.attribute_sets {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        let mut occurrences_by_namespace = [0_usize; 4];
        let mut decoded_bytes = name.len();
        for attribute in &attributes {
            let namespace_index = namespace_index(attribute.namespace());
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
        if decoded_bytes > limits.decoded_bytes {
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
        })
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
}

/// The one Release 1 native Trace profile used by both admission and decode.
/// Keeping these derived limits here prevents a wire decoder from silently
/// accepting a shape that native construction would reject.
pub(super) struct TraceLimits {
    pub(super) attribute_sets: usize,
    pub(super) occurrences_per_namespace: usize,
    pub(super) key_path_bytes: usize,
    pub(super) value_bytes: usize,
    pub(super) nesting_depth: u8,
    pub(super) array_entries: usize,
    pub(super) key_value_list_entries: usize,
    pub(super) decoded_bytes: usize,
}

pub(super) fn release_1_limits() -> Result<TraceLimits, TraceStoreFailure> {
    let profile = ValueLimitProfile::release_1_system_maximum().effective_limits();
    let dynamic = profile.dynamic_value();
    Ok(TraceLimits {
        attribute_sets: usize::try_from(
            dynamic
                .attributes_per_namespace()
                .value()
                .checked_mul(3)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?,
        )
        .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        occurrences_per_namespace: usize::try_from(dynamic.attributes_per_namespace().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        key_path_bytes: usize::try_from(dynamic.key_path_bytes().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        value_bytes: usize::try_from(dynamic.individual_value_bytes().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        nesting_depth: u8::try_from(dynamic.nesting_depth().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        array_entries: usize::try_from(dynamic.array_entries().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        key_value_list_entries: usize::try_from(dynamic.key_value_list_entries().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        decoded_bytes: usize::try_from(profile.record().decoded_bytes().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
    })
}

fn namespace_index(namespace: positron_domain::value::AttributeNamespace) -> usize {
    match namespace {
        positron_domain::value::AttributeNamespace::Stream => 0,
        positron_domain::value::AttributeNamespace::Resource => 1,
        positron_domain::value::AttributeNamespace::InstrumentationScope => 2,
        positron_domain::value::AttributeNamespace::Record => 3,
    }
}

/// One immutable observation after the kernel assigned Ingest Time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSpanObservation {
    observation: SpanObservation,
    ingest_time: IngestTime,
}

impl StoredSpanObservation {
    pub(super) const fn new(observation: SpanObservation, ingest_time: IngestTime) -> Self {
        Self {
            observation,
            ingest_time,
        }
    }

    #[must_use]
    pub const fn observation(&self) -> &SpanObservation {
        &self.observation
    }

    #[must_use]
    pub const fn trace_id(&self) -> [u8; 16] {
        self.observation.trace_id()
    }

    #[must_use]
    pub const fn span_id(&self) -> [u8; 8] {
        self.observation.span_id()
    }

    #[must_use]
    pub const fn ingest_time(&self) -> IngestTime {
        self.ingest_time
    }
}

/// Opaque checked Trace Store output accepted by the Storage Kernel ledger.
pub struct PreparedTraceBlock<'capacity> {
    pub(super) block: PreparedStoreBlock<'capacity>,
}

impl<'capacity> PreparedTraceBlock<'capacity> {
    pub(super) const fn new(block: PreparedStoreBlock<'capacity>) -> Self {
        Self { block }
    }

    /// Transfers the prepared block to the Storage Kernel for commit.
    #[must_use]
    pub fn into_store_block(self) -> PreparedStoreBlock<'capacity> {
        self.block
    }
}
