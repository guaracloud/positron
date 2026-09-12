use positron_api::tenant_quotas::{TenantQuotaUpdateRequest, TenantQuotaUpdateResponse};
use positron_domain::identity::{PrincipalId, TenantId};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};

use crate::{BootstrapFailureCode, ServiceHandle};

pub(crate) enum TenantQuotaHttpFailure {
    Code(u16, &'static str),
    StaleGeneration(positron_governance::TenantQuotaGenerationConflict),
}

impl ServiceHandle {
    pub(crate) fn administer_tenant_quota(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<TenantQuotaUpdateResponse, TenantQuotaHttpFailure> {
        let actor = self
            .instance
            .attribute(
                PresentedCredential::parse(bearer)
                    .map_err(|_| TenantQuotaHttpFailure::Code(401, "authentication_rejected"))?,
                RequestedIntent::TenantAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| TenantQuotaHttpFailure::Code(401, "authentication_rejected"))?;
        let request = TenantQuotaUpdateRequest::decode(body)
            .map_err(|_| TenantQuotaHttpFailure::Code(400, "invalid_request"))?;
        let tenant = TenantId::parse_canonical(request.tenant())
            .map_err(|_| TenantQuotaHttpFailure::Code(400, "invalid_request"))?;
        let expected = ResourceGeneration::new(request.expected_generation())
            .map_err(|_| TenantQuotaHttpFailure::Code(400, "invalid_request"))?;
        let idempotency = PrincipalId::parse_canonical(request.idempotency_key())
            .map_err(|_| TenantQuotaHttpFailure::Code(400, "invalid_request"))?;
        let idempotency = AdministrativeIdempotencyKey::new(idempotency.to_bytes())
            .map_err(|_| TenantQuotaHttpFailure::Code(400, "invalid_request"))?;
        let update = self
            .instance
            .update_tenant_quota(
                actor,
                tenant,
                expected,
                idempotency,
                request.weight(),
                request.resource_values(),
            )
            .map_err(map_failure)?;
        Ok(TenantQuotaUpdateResponse {
            resource_generation: update.resource_generation().get(),
        })
    }
}

fn map_failure(failure: crate::BootstrapFailure) -> TenantQuotaHttpFailure {
    match failure.code() {
        BootstrapFailureCode::TenantQuotaUnauthorized => {
            TenantQuotaHttpFailure::Code(401, "authentication_rejected")
        },
        BootstrapFailureCode::TenantQuotaStaleGeneration => failure
            .quota_generation_conflict_detail()
            .map(TenantQuotaHttpFailure::StaleGeneration)
            .unwrap_or(TenantQuotaHttpFailure::Code(
                503,
                "administration_unavailable",
            )),
        BootstrapFailureCode::TenantQuotaIdempotencyConflict => {
            TenantQuotaHttpFailure::Code(409, "idempotency_conflict")
        },
        BootstrapFailureCode::CatalogUnavailable
        | BootstrapFailureCode::KeyCustodyUnavailable
        | BootstrapFailureCode::ResourceUnavailable => {
            TenantQuotaHttpFailure::Code(503, "administration_unavailable")
        },
        BootstrapFailureCode::StorageUnavailable
        | BootstrapFailureCode::CorruptState
        | BootstrapFailureCode::IdentityMismatch
        | BootstrapFailureCode::InvalidRoots
        | BootstrapFailureCode::InconsistentRoots
        | BootstrapFailureCode::AlreadyInitialized
        | BootstrapFailureCode::LedgerUnavailable
        | BootstrapFailureCode::ClaimUnavailable
        | BootstrapFailureCode::ClaimDestructionFailed
        | BootstrapFailureCode::EntropyUnavailable
        | BootstrapFailureCode::ApiKeyUnauthorized
        | BootstrapFailureCode::ApiKeyStaleGeneration
        | BootstrapFailureCode::ApiKeyIdempotencyConflict
        | BootstrapFailureCode::ApiKeyUnavailable
        | BootstrapFailureCode::TenantLifecycleUnauthorized
        | BootstrapFailureCode::TenantLifecycleStaleGeneration
        | BootstrapFailureCode::TenantLifecycleIdempotencyConflict
        | BootstrapFailureCode::TenantLifecycleInvalidTransition
        | BootstrapFailureCode::TenantLifecyclePurgeCompletionUnavailable
        | BootstrapFailureCode::TenantLifecycleUnknownTenant => {
            TenantQuotaHttpFailure::Code(503, "administration_unavailable")
        },
    }
}
