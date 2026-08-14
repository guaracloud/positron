use super::LogStoreFailure;

/// Native log metadata preserved independently of dynamic attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogMetadata {
    severity_number: i32,
    severity_text: String,
    event_name: String,
    trace_id: Option<[u8; 16]>,
    span_id: Option<[u8; 8]>,
    flags: u32,
    dropped_attributes_count: u32,
    resource_dropped_attributes_count: u32,
    resource_schema_url: String,
    scope_name: String,
    scope_version: String,
    scope_dropped_attributes_count: u32,
    scope_schema_url: String,
}

impl LogMetadata {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        severity_number: i32,
        severity_text: String,
        trace_id: Option<[u8; 16]>,
        span_id: Option<[u8; 8]>,
        flags: u32,
        dropped_attributes_count: u32,
        resource_dropped_attributes_count: u32,
        resource_schema_url: String,
        scope_name: String,
        scope_version: String,
        scope_dropped_attributes_count: u32,
        scope_schema_url: String,
    ) -> Self {
        Self::new_with_event_name(
            severity_number,
            severity_text,
            String::new(),
            trace_id,
            span_id,
            flags,
            dropped_attributes_count,
            resource_dropped_attributes_count,
            resource_schema_url,
            scope_name,
            scope_version,
            scope_dropped_attributes_count,
            scope_schema_url,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new_with_event_name(
        severity_number: i32,
        severity_text: String,
        event_name: String,
        trace_id: Option<[u8; 16]>,
        span_id: Option<[u8; 8]>,
        flags: u32,
        dropped_attributes_count: u32,
        resource_dropped_attributes_count: u32,
        resource_schema_url: String,
        scope_name: String,
        scope_version: String,
        scope_dropped_attributes_count: u32,
        scope_schema_url: String,
    ) -> Self {
        Self {
            severity_number,
            severity_text,
            event_name,
            trace_id,
            span_id,
            flags,
            dropped_attributes_count,
            resource_dropped_attributes_count,
            resource_schema_url,
            scope_name,
            scope_version,
            scope_dropped_attributes_count,
            scope_schema_url,
        }
    }

    #[must_use]
    pub const fn empty() -> Self {
        Self::new(
            0,
            String::new(),
            None,
            None,
            0,
            0,
            0,
            String::new(),
            String::new(),
            String::new(),
            0,
            String::new(),
        )
    }

    #[must_use]
    pub const fn severity_number(&self) -> i32 {
        self.severity_number
    }

    #[must_use]
    pub fn severity_text(&self) -> &str {
        &self.severity_text
    }

    #[must_use]
    pub fn event_name(&self) -> &str {
        &self.event_name
    }

    #[must_use]
    pub const fn trace_id(&self) -> Option<[u8; 16]> {
        self.trace_id
    }

    #[must_use]
    pub const fn span_id(&self) -> Option<[u8; 8]> {
        self.span_id
    }

    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    #[must_use]
    pub const fn dropped_attributes_count(&self) -> u32 {
        self.dropped_attributes_count
    }

    #[must_use]
    pub const fn resource_dropped_attributes_count(&self) -> u32 {
        self.resource_dropped_attributes_count
    }

    #[must_use]
    pub fn resource_schema_url(&self) -> &str {
        &self.resource_schema_url
    }

    #[must_use]
    pub fn scope_name(&self) -> &str {
        &self.scope_name
    }

    #[must_use]
    pub fn scope_version(&self) -> &str {
        &self.scope_version
    }

    #[must_use]
    pub const fn scope_dropped_attributes_count(&self) -> u32 {
        self.scope_dropped_attributes_count
    }

    #[must_use]
    pub fn scope_schema_url(&self) -> &str {
        &self.scope_schema_url
    }

    pub(super) fn decoded_size_bytes(&self) -> Result<usize, LogStoreFailure> {
        [
            self.severity_text.len(),
            self.event_name.len(),
            self.resource_schema_url.len(),
            self.scope_name.len(),
            self.scope_version.len(),
            self.scope_schema_url.len(),
        ]
        .into_iter()
        .try_fold(0_usize, |total, bytes| {
            total
                .checked_add(bytes)
                .ok_or_else(LogStoreFailure::limit_exceeded)
        })
    }
}

impl Default for LogMetadata {
    fn default() -> Self {
        Self::empty()
    }
}
