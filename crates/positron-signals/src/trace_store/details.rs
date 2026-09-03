use positron_domain::time::EventTime;
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSet, AttributeOccurrenceSetCandidate,
    CandidateAttributeValue, ValueLimitProfile,
};

use super::failure::TraceStoreFailure;
use super::types::release_1_limits;

pub(super) const MAX_DETAIL_COLLECTION: usize = 1_024;

/// The protocol-neutral status code retained for one span observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpanStatusCode {
    /// No status was supplied by the producer.
    Unset,
    /// The span completed successfully.
    Ok,
    /// The span contains an error.
    Error,
}

/// The final producer status attached to one span observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanStatus {
    code: SpanStatusCode,
    message: String,
}

impl SpanStatus {
    /// Builds a bounded native status value.
    pub fn checked(code: SpanStatusCode, message: String) -> Result<Self, TraceStoreFailure> {
        let limits = release_1_limits()?;
        if message.len() > limits.key_path_bytes {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        Ok(Self { code, message })
    }

    /// Returns the explicit status code.
    #[must_use]
    pub const fn code(&self) -> SpanStatusCode {
        self.code
    }

    /// Returns the producer's status message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    pub(super) fn unset() -> Self {
        Self {
            code: SpanStatusCode::Unset,
            message: String::new(),
        }
    }
}

/// One bounded typed event or link attribute occurrence set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanAttributeSet {
    occurrences: AttributeOccurrenceSet,
}

impl SpanAttributeSet {
    /// Validates one event or link attribute occurrence set.
    pub fn checked(
        key: String,
        occurrences: Vec<CandidateAttributeValue>,
        profile: ValueLimitProfile,
    ) -> Result<Self, TraceStoreFailure> {
        let occurrences =
            AttributeOccurrenceSetCandidate::new(AttributeNamespace::Record, key, occurrences)
                .validate(profile)
                .map_err(TraceStoreFailure::domain)?;
        Ok(Self { occurrences })
    }

    /// Returns the validated attribute key.
    #[must_use]
    pub fn key(&self) -> &str {
        self.occurrences.key()
    }

    /// Returns the number of preserved typed occurrences.
    #[must_use]
    pub fn len(&self) -> usize {
        self.occurrences.len()
    }

    /// Returns whether this set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.occurrences.is_empty()
    }

    /// Returns one typed occurrence by explicit optional index.
    #[must_use]
    pub fn occurrence(
        &self,
        index: usize,
    ) -> Option<&positron_domain::value::ValidatedAttributeValue> {
        self.occurrences.occurrence(index)
    }
}

/// A bounded, ordered event attached to a span observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanEvent {
    timestamp: EventTime,
    name: String,
    attributes: Vec<SpanAttributeSet>,
    dropped_attributes_count: u32,
}

impl SpanEvent {
    /// Validates one event without changing source order or timestamp quality.
    pub fn checked(
        timestamp: EventTime,
        name: String,
        attributes: Vec<SpanAttributeSet>,
        dropped_attributes_count: u32,
    ) -> Result<Self, TraceStoreFailure> {
        let limits = release_1_limits()?;
        validate_detail_name(&name, limits.key_path_bytes)?;
        validate_detail_attributes(&attributes, limits.occurrences_per_namespace)?;
        Ok(Self {
            timestamp,
            name,
            attributes,
            dropped_attributes_count,
        })
    }

    /// Returns the event timestamp and its source quality.
    #[must_use]
    pub const fn timestamp(&self) -> EventTime {
        self.timestamp
    }

    /// Returns the event name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns ordered typed event attributes.
    #[must_use]
    pub fn attributes(&self) -> &[SpanAttributeSet] {
        &self.attributes
    }

    /// Returns the producer's event-attribute drop count.
    #[must_use]
    pub const fn dropped_attributes_count(&self) -> u32 {
        self.dropped_attributes_count
    }
}

/// A bounded link to another span observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanLink {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    trace_state: String,
    flags: u32,
    attributes: Vec<SpanAttributeSet>,
    dropped_attributes_count: u32,
}

impl SpanLink {
    /// Validates one link while preserving its identity and context fields.
    pub fn checked(
        trace_id: [u8; 16],
        span_id: [u8; 8],
        trace_state: String,
        flags: u32,
        attributes: Vec<SpanAttributeSet>,
        dropped_attributes_count: u32,
    ) -> Result<Self, TraceStoreFailure> {
        let limits = release_1_limits()?;
        if trace_id.iter().all(|byte| *byte == 0)
            || span_id.iter().all(|byte| *byte == 0)
            || trace_state.len() > limits.key_path_bytes
        {
            return Err(TraceStoreFailure::invalid_input());
        }
        validate_detail_attributes(&attributes, limits.occurrences_per_namespace)?;
        Ok(Self {
            trace_id,
            span_id,
            trace_state,
            flags,
            attributes,
            dropped_attributes_count,
        })
    }

    /// Returns the linked trace identity.
    #[must_use]
    pub const fn trace_id(&self) -> [u8; 16] {
        self.trace_id
    }

    /// Returns the linked span identity.
    #[must_use]
    pub const fn span_id(&self) -> [u8; 8] {
        self.span_id
    }

    /// Returns the link's W3C trace state.
    #[must_use]
    pub fn trace_state(&self) -> &str {
        &self.trace_state
    }

    /// Returns the complete link flags bitfield.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns ordered typed link attributes.
    #[must_use]
    pub fn attributes(&self) -> &[SpanAttributeSet] {
        &self.attributes
    }

    /// Returns the producer's link-attribute drop count.
    #[must_use]
    pub const fn dropped_attributes_count(&self) -> u32 {
        self.dropped_attributes_count
    }
}

/// Resource metadata retained beside resource attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanResourceMetadata {
    dropped_attributes_count: u32,
    schema_url: String,
}

impl SpanResourceMetadata {
    /// Builds bounded resource metadata.
    pub fn checked(
        dropped_attributes_count: u32,
        schema_url: String,
    ) -> Result<Self, TraceStoreFailure> {
        let limits = release_1_limits()?;
        if schema_url.len() > limits.key_path_bytes {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        Ok(Self {
            dropped_attributes_count,
            schema_url,
        })
    }

    /// Returns the producer's resource-attribute drop count.
    #[must_use]
    pub const fn dropped_attributes_count(&self) -> u32 {
        self.dropped_attributes_count
    }

    /// Returns the resource schema URL, if supplied.
    #[must_use]
    pub fn schema_url(&self) -> &str {
        &self.schema_url
    }
}

/// Instrumentation scope metadata retained beside scope attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanScopeMetadata {
    name: String,
    version: String,
    dropped_attributes_count: u32,
    schema_url: String,
}

impl SpanScopeMetadata {
    /// Builds bounded instrumentation scope metadata.
    pub fn checked(
        name: String,
        version: String,
        dropped_attributes_count: u32,
        schema_url: String,
    ) -> Result<Self, TraceStoreFailure> {
        let limits = release_1_limits()?;
        for value in [&name, &version, &schema_url] {
            if value.len() > limits.key_path_bytes {
                return Err(TraceStoreFailure::limit_exceeded());
            }
        }
        Ok(Self {
            name,
            version,
            dropped_attributes_count,
            schema_url,
        })
    }

    /// Returns the instrumentation scope name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the instrumentation scope version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the producer's scope-attribute drop count.
    #[must_use]
    pub const fn dropped_attributes_count(&self) -> u32 {
        self.dropped_attributes_count
    }

    /// Returns the scope schema URL, if supplied.
    #[must_use]
    pub fn schema_url(&self) -> &str {
        &self.schema_url
    }
}

/// Additive span metadata retained by Trace Store v2 observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanObservationDetails {
    trace_state: String,
    flags: u32,
    status: SpanStatus,
    events: Vec<SpanEvent>,
    links: Vec<SpanLink>,
    dropped_attributes_count: u32,
    dropped_events_count: u32,
    dropped_links_count: u32,
    resource: SpanResourceMetadata,
    scope: SpanScopeMetadata,
}

impl Default for SpanObservationDetails {
    fn default() -> Self {
        Self {
            trace_state: String::new(),
            flags: 0,
            status: SpanStatus::unset(),
            events: Vec::new(),
            links: Vec::new(),
            dropped_attributes_count: 0,
            dropped_events_count: 0,
            dropped_links_count: 0,
            resource: SpanResourceMetadata {
                dropped_attributes_count: 0,
                schema_url: String::new(),
            },
            scope: SpanScopeMetadata {
                name: String::new(),
                version: String::new(),
                dropped_attributes_count: 0,
                schema_url: String::new(),
            },
        }
    }
}

impl SpanObservationDetails {
    /// Builds bounded, ordered span details from native fields.
    #[allow(clippy::too_many_arguments)]
    pub fn checked(
        trace_state: String,
        flags: u32,
        status: SpanStatus,
        events: Vec<SpanEvent>,
        links: Vec<SpanLink>,
        dropped_attributes_count: u32,
        dropped_events_count: u32,
        dropped_links_count: u32,
        resource: SpanResourceMetadata,
        scope: SpanScopeMetadata,
    ) -> Result<Self, TraceStoreFailure> {
        let limits = release_1_limits()?;
        if trace_state.len() > limits.key_path_bytes
            || events.len() > MAX_DETAIL_COLLECTION
            || links.len() > MAX_DETAIL_COLLECTION
        {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        let mut decoded_bytes = trace_state
            .len()
            .checked_add(status.message.len())
            .and_then(|size| size.checked_add(resource.schema_url.len()))
            .and_then(|size| size.checked_add(scope.name.len()))
            .and_then(|size| size.checked_add(scope.version.len()))
            .and_then(|size| size.checked_add(scope.schema_url.len()))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        for event in &events {
            decoded_bytes = detail_decoded_bytes(
                decoded_bytes,
                event.name.len(),
                &event.attributes,
                limits.decoded_bytes,
            )?;
        }
        for link in &links {
            decoded_bytes = detail_decoded_bytes(
                decoded_bytes,
                link.trace_state.len(),
                &link.attributes,
                limits.decoded_bytes,
            )?;
        }
        if decoded_bytes > limits.decoded_bytes {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        Ok(Self {
            trace_state,
            flags,
            status,
            events,
            links,
            dropped_attributes_count,
            dropped_events_count,
            dropped_links_count,
            resource,
            scope,
        })
    }

    /// Returns the span's W3C trace state.
    #[must_use]
    pub fn trace_state(&self) -> &str {
        &self.trace_state
    }

    /// Returns the complete span flags bitfield.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the final producer status.
    #[must_use]
    pub fn status(&self) -> &SpanStatus {
        &self.status
    }

    /// Returns ordered events.
    #[must_use]
    pub fn events(&self) -> &[SpanEvent] {
        &self.events
    }

    /// Returns ordered links.
    #[must_use]
    pub fn links(&self) -> &[SpanLink] {
        &self.links
    }

    /// Returns the producer's span-attribute drop count.
    #[must_use]
    pub const fn dropped_attributes_count(&self) -> u32 {
        self.dropped_attributes_count
    }

    /// Returns the producer's event drop count.
    #[must_use]
    pub const fn dropped_events_count(&self) -> u32 {
        self.dropped_events_count
    }

    /// Returns the producer's link drop count.
    #[must_use]
    pub const fn dropped_links_count(&self) -> u32 {
        self.dropped_links_count
    }

    /// Returns resource metadata.
    #[must_use]
    pub const fn resource(&self) -> &SpanResourceMetadata {
        &self.resource
    }

    /// Returns instrumentation scope metadata.
    #[must_use]
    pub const fn scope(&self) -> &SpanScopeMetadata {
        &self.scope
    }

    pub(super) fn decoded_size_bytes(&self, limit: usize) -> Result<usize, TraceStoreFailure> {
        let initial = self
            .trace_state
            .len()
            .checked_add(self.status.message.len())
            .and_then(|size| size.checked_add(self.resource.schema_url.len()))
            .and_then(|size| size.checked_add(self.scope.name.len()))
            .and_then(|size| size.checked_add(self.scope.version.len()))
            .and_then(|size| size.checked_add(self.scope.schema_url.len()))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let with_events = self.events.iter().try_fold(initial, |total, event| {
            detail_decoded_bytes(total, event.name.len(), &event.attributes, limit)
        })?;
        self.links.iter().try_fold(with_events, |total, link| {
            detail_decoded_bytes(total, link.trace_state.len(), &link.attributes, limit)
        })
    }
}

fn validate_detail_name(name: &str, limit: usize) -> Result<(), TraceStoreFailure> {
    if name.is_empty() || name.len() > limit {
        Err(TraceStoreFailure::invalid_input())
    } else {
        Ok(())
    }
}

fn validate_detail_attributes(
    attributes: &[SpanAttributeSet],
    occurrence_limit: usize,
) -> Result<(), TraceStoreFailure> {
    if attributes.len() > MAX_DETAIL_COLLECTION {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    let mut occurrences = 0_usize;
    for attribute in attributes {
        occurrences = occurrences
            .checked_add(attribute.len())
            .filter(|count| *count <= occurrence_limit)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    }
    Ok(())
}

fn detail_decoded_bytes(
    current: usize,
    name_bytes: usize,
    attributes: &[SpanAttributeSet],
    limit: usize,
) -> Result<usize, TraceStoreFailure> {
    let mut decoded = current
        .checked_add(name_bytes)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    for attribute in attributes {
        decoded = decoded
            .checked_add(attribute.key().len())
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        for index in 0..attribute.len() {
            let value = attribute
                .occurrence(index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            decoded = decoded
                .checked_add(
                    value
                        .decoded_size_bytes()
                        .map_err(TraceStoreFailure::domain)?,
                )
                .filter(|size| *size <= limit)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        }
    }
    Ok(decoded)
}
