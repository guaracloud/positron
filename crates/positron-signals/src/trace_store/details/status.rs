use positron_domain::value::ValueLimitProfile;

use super::{TraceStoreFailure, detail_limits};

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
    pub(super) code: SpanStatusCode,
    pub(super) message: String,
}

impl SpanStatus {
    /// Builds a bounded native status value.
    pub fn checked(code: SpanStatusCode, message: String) -> Result<Self, TraceStoreFailure> {
        let profile = ValueLimitProfile::release_1_system_maximum();
        Self::checked_with_profile(code, message, &profile)
    }

    /// Builds a bounded native status value under the pinned profile.
    pub fn checked_with_profile(
        code: SpanStatusCode,
        message: String,
        profile: &ValueLimitProfile,
    ) -> Result<Self, TraceStoreFailure> {
        let key_path_bytes = detail_limits(profile)?.0;
        if message.len() > key_path_bytes {
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
