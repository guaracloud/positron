use positron_domain::value::ValueLimitProfile;

use super::failure::TraceStoreFailure;

mod accounting;
mod attributes;
mod event_link;
mod metadata;
mod status;
mod validation;

pub use attributes::SpanAttributeSet;
pub use event_link::{SpanEvent, SpanLink};
pub use metadata::{SpanResourceMetadata, SpanScopeMetadata};
pub use status::{SpanStatus, SpanStatusCode};
pub(super) use validation::{
    detail_decoded_bytes, detail_limits, validate_detail_attributes, validate_detail_name,
};

pub(super) const MAX_DETAIL_COLLECTION: usize = 1_024;

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
        let profile = ValueLimitProfile::release_1_system_maximum();
        Self::checked_with_profile(
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
            &profile,
        )
    }

    /// Builds complete span details under the pinned profile.
    #[allow(clippy::too_many_arguments)]
    pub fn checked_with_profile(
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
        profile: &ValueLimitProfile,
    ) -> Result<Self, TraceStoreFailure> {
        let (key_path_bytes, _) = detail_limits(profile)?;
        let decoded_bytes_limit = profile
            .effective_limits()
            .record()
            .decoded_bytes()
            .value()
            .try_into()
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        if trace_state.len() > key_path_bytes
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
                decoded_bytes_limit,
            )?;
        }
        for link in &links {
            decoded_bytes = detail_decoded_bytes(
                decoded_bytes,
                link.trace_state.len(),
                &link.attributes,
                decoded_bytes_limit,
            )?;
        }
        if decoded_bytes > decoded_bytes_limit {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        let details = Self {
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
        };
        details.validate_with_profile(profile)?;
        Ok(details)
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
