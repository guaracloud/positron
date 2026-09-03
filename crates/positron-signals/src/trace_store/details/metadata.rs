use positron_domain::value::ValueLimitProfile;

use super::{TraceStoreFailure, detail_limits};

/// Resource metadata retained beside resource attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanResourceMetadata {
    pub(super) dropped_attributes_count: u32,
    pub(super) schema_url: String,
}

impl SpanResourceMetadata {
    /// Builds bounded resource metadata.
    pub fn checked(
        dropped_attributes_count: u32,
        schema_url: String,
    ) -> Result<Self, TraceStoreFailure> {
        let profile = ValueLimitProfile::release_1_system_maximum();
        Self::checked_with_profile(dropped_attributes_count, schema_url, &profile)
    }

    /// Builds resource metadata under the pinned profile.
    pub fn checked_with_profile(
        dropped_attributes_count: u32,
        schema_url: String,
        profile: &ValueLimitProfile,
    ) -> Result<Self, TraceStoreFailure> {
        if schema_url.len() > detail_limits(profile)?.0 {
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
    pub(super) name: String,
    pub(super) version: String,
    pub(super) dropped_attributes_count: u32,
    pub(super) schema_url: String,
}

impl SpanScopeMetadata {
    /// Builds bounded instrumentation scope metadata.
    pub fn checked(
        name: String,
        version: String,
        dropped_attributes_count: u32,
        schema_url: String,
    ) -> Result<Self, TraceStoreFailure> {
        let profile = ValueLimitProfile::release_1_system_maximum();
        Self::checked_with_profile(
            name,
            version,
            dropped_attributes_count,
            schema_url,
            &profile,
        )
    }

    /// Builds scope metadata under the pinned profile.
    pub fn checked_with_profile(
        name: String,
        version: String,
        dropped_attributes_count: u32,
        schema_url: String,
        profile: &ValueLimitProfile,
    ) -> Result<Self, TraceStoreFailure> {
        let key_path_bytes = detail_limits(profile)?.0;
        for value in [&name, &version, &schema_url] {
            if value.len() > key_path_bytes {
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
