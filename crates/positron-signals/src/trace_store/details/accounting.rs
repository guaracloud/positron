use super::{SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails, SpanStatus};
use crate::trace_store::failure::TraceStoreFailure;

impl SpanAttributeSet {
    pub(crate) fn retained_heap_bytes(&self) -> Result<usize, TraceStoreFailure> {
        self.occurrences
            .retained_heap_bytes()
            .map_err(TraceStoreFailure::domain)
    }

    pub(crate) fn validate_with_profile(
        &self,
        profile: &positron_domain::value::ValueLimitProfile,
    ) -> Result<(), TraceStoreFailure> {
        self.occurrences
            .validate_with_profile(*profile)
            .map_err(TraceStoreFailure::domain)
    }
}

impl SpanObservationDetails {
    pub(crate) fn validate_with_profile(
        &self,
        profile: &positron_domain::value::ValueLimitProfile,
    ) -> Result<(), TraceStoreFailure> {
        let key_path_bytes = usize::try_from(
            profile
                .effective_limits()
                .dynamic_value()
                .key_path_bytes()
                .value(),
        )
        .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        if self.trace_state.len() > key_path_bytes
            || self.status.message.len() > key_path_bytes
            || self.resource.schema_url.len() > key_path_bytes
            || self.scope.name.len() > key_path_bytes
            || self.scope.version.len() > key_path_bytes
            || self.scope.schema_url.len() > key_path_bytes
            || self.events.len() > super::MAX_DETAIL_COLLECTION
            || self.links.len() > super::MAX_DETAIL_COLLECTION
        {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        for event in &self.events {
            if event.name.is_empty() || event.name.len() > key_path_bytes {
                return Err(TraceStoreFailure::limit_exceeded());
            }
            for attribute in &event.attributes {
                attribute.validate_with_profile(profile)?;
            }
        }
        for link in &self.links {
            if link.trace_id.iter().all(|byte| *byte == 0)
                || link.span_id.iter().all(|byte| *byte == 0)
                || link.trace_state.len() > key_path_bytes
            {
                return Err(TraceStoreFailure::limit_exceeded());
            }
            for attribute in &link.attributes {
                attribute.validate_with_profile(profile)?;
            }
        }
        Ok(())
    }

    pub(crate) fn retained_heap_bytes(&self) -> Result<usize, TraceStoreFailure> {
        let mut retained = self
            .trace_state
            .capacity()
            .checked_add(std::mem::size_of::<SpanStatus>())
            .and_then(|size| size.checked_add(self.status.message.capacity()))
            .and_then(|size| {
                size.checked_add(
                    self.events
                        .capacity()
                        .checked_mul(std::mem::size_of::<SpanEvent>())?,
                )
            })
            .and_then(|size| {
                size.checked_add(
                    self.links
                        .capacity()
                        .checked_mul(std::mem::size_of::<SpanLink>())?,
                )
            })
            .and_then(|size| size.checked_add(self.resource.schema_url.capacity()))
            .and_then(|size| size.checked_add(self.scope.name.capacity()))
            .and_then(|size| size.checked_add(self.scope.version.capacity()))
            .and_then(|size| size.checked_add(self.scope.schema_url.capacity()))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        for event in &self.events {
            retained = retained
                .checked_add(event.name.capacity())
                .and_then(|size| {
                    size.checked_add(
                        event
                            .attributes
                            .capacity()
                            .checked_mul(std::mem::size_of::<SpanAttributeSet>())?,
                    )
                })
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            for attribute in &event.attributes {
                retained = retained
                    .checked_add(attribute.retained_heap_bytes()?)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            }
        }
        for link in &self.links {
            retained = retained
                .checked_add(link.trace_state.capacity())
                .and_then(|size| {
                    size.checked_add(
                        link.attributes
                            .capacity()
                            .checked_mul(std::mem::size_of::<SpanAttributeSet>())?,
                    )
                })
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            for attribute in &link.attributes {
                retained = retained
                    .checked_add(attribute.retained_heap_bytes()?)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            }
        }
        Ok(retained)
    }
}
