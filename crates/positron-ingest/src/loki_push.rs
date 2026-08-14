//! Authenticated Loki Push conversion into Positron native Log candidates.

use positron_domain::value::ValueLimitProfile;

mod mapping;
mod proto;
mod request;

pub use request::{AuthenticatedLokiPushRequest, LokiPushRequestEncoding};

use crate::{NativeLogBatch, ReceiveFailure};

/// Loki Push Receiver Adapter.
#[derive(Clone, Copy, Debug)]
pub struct LokiPushReceiver {
    value_limit_profile: ValueLimitProfile,
}

impl Default for LokiPushReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl LokiPushReceiver {
    #[must_use]
    pub const fn new() -> Self {
        Self::with_value_limit_profile(ValueLimitProfile::release_1_system_maximum())
    }

    /// Binds one validated profile snapshot to transport and semantic decode.
    #[must_use]
    pub const fn with_value_limit_profile(value_limit_profile: ValueLimitProfile) -> Self {
        Self {
            value_limit_profile,
        }
    }

    pub fn decode<'authority>(
        &self,
        request: AuthenticatedLokiPushRequest<'authority>,
    ) -> Result<NativeLogBatch<'authority>, ReceiveFailure> {
        let request::AuthenticatedLokiPushRequest {
            attribution,
            payload,
            capacity,
        } = request;
        match payload.bounded(self.value_limit_profile)? {
            request::BoundedLokiPayload::Json(json) => {
                mapping::json_batch(attribution, json, self.value_limit_profile, capacity)
            },
            request::BoundedLokiPayload::Protobuf(protobuf) => {
                mapping::protobuf_batch(attribution, protobuf, self.value_limit_profile, capacity)
            },
        }
    }
}
