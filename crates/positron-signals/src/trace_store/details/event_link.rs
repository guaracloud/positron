use positron_domain::time::EventTime;
use positron_domain::value::ValueLimitProfile;

use super::{SpanAttributeSet, TraceStoreFailure, detail_limits};

/// A bounded, ordered event attached to a span observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanEvent {
    pub(super) timestamp: EventTime,
    pub(super) name: String,
    pub(super) attributes: Vec<SpanAttributeSet>,
    pub(super) dropped_attributes_count: u32,
}

impl SpanEvent {
    /// Validates one event without changing source order or timestamp quality.
    pub fn checked(
        timestamp: EventTime,
        name: String,
        attributes: Vec<SpanAttributeSet>,
        dropped_attributes_count: u32,
    ) -> Result<Self, TraceStoreFailure> {
        let profile = ValueLimitProfile::release_1_system_maximum();
        Self::checked_with_profile(
            timestamp,
            name,
            attributes,
            dropped_attributes_count,
            &profile,
        )
    }

    /// Validates one event under the pinned profile.
    pub fn checked_with_profile(
        timestamp: EventTime,
        name: String,
        attributes: Vec<SpanAttributeSet>,
        dropped_attributes_count: u32,
        profile: &ValueLimitProfile,
    ) -> Result<Self, TraceStoreFailure> {
        let (key_path_bytes, occurrences_per_namespace) = detail_limits(profile)?;
        super::validate_detail_name(&name, key_path_bytes)?;
        super::validate_detail_attributes(&attributes, occurrences_per_namespace)?;
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
    pub(super) trace_id: [u8; 16],
    pub(super) span_id: [u8; 8],
    pub(super) trace_state: String,
    pub(super) flags: u32,
    pub(super) attributes: Vec<SpanAttributeSet>,
    pub(super) dropped_attributes_count: u32,
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
        let profile = ValueLimitProfile::release_1_system_maximum();
        Self::checked_with_profile(
            trace_id,
            span_id,
            trace_state,
            flags,
            attributes,
            dropped_attributes_count,
            &profile,
        )
    }

    /// Validates one link under the pinned profile.
    pub fn checked_with_profile(
        trace_id: [u8; 16],
        span_id: [u8; 8],
        trace_state: String,
        flags: u32,
        attributes: Vec<SpanAttributeSet>,
        dropped_attributes_count: u32,
        profile: &ValueLimitProfile,
    ) -> Result<Self, TraceStoreFailure> {
        let (key_path_bytes, occurrences_per_namespace) = detail_limits(profile)?;
        if trace_id.iter().all(|byte| *byte == 0)
            || span_id.iter().all(|byte| *byte == 0)
            || trace_state.len() > key_path_bytes
        {
            return Err(TraceStoreFailure::invalid_input());
        }
        super::validate_detail_attributes(&attributes, occurrences_per_namespace)?;
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
