use positron_api::tenant_aliases::{TenantAliasBindRequest, TenantAliasBindResponse};
use positron_domain::identity::{ExternalTenantAlias, PrincipalId, TenantId};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};

use crate::{BootstrapFailureCode, ServiceHandle};

pub(crate) enum TenantAliasHttpFailure {
    Code(u16, &'static str),
}

impl ServiceHandle {
    /// Authorizes before decoding the alias body so malformed input cannot
    /// probe tenant identity or administration reachability.
    pub(crate) fn bind_tenant_alias(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<TenantAliasBindResponse, TenantAliasHttpFailure> {
        let actor = self
            .instance
            .attribute(
                PresentedCredential::parse(bearer)
                    .map_err(|_| TenantAliasHttpFailure::Code(401, "authentication_rejected"))?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| TenantAliasHttpFailure::Code(401, "authentication_rejected"))?;
        let request = TenantAliasBindRequest::decode(body)
            .map_err(|_| TenantAliasHttpFailure::Code(400, "invalid_request"))?;
        let tenant = TenantId::parse_canonical(request.tenant())
            .map_err(|_| TenantAliasHttpFailure::Code(400, "invalid_request"))?;
        let alias = ExternalTenantAlias::parse(request.external_alias())
            .map_err(|_| TenantAliasHttpFailure::Code(400, "invalid_request"))?;
        let expected = ResourceGeneration::new(request.expected_generation())
            .map_err(|_| TenantAliasHttpFailure::Code(400, "invalid_request"))?;
        let id = PrincipalId::parse_canonical(request.idempotency_key())
            .map_err(|_| TenantAliasHttpFailure::Code(400, "invalid_request"))?;
        let binding = self
            .instance
            .bind_tenant_alias(
                actor,
                tenant,
                alias,
                expected,
                AdministrativeIdempotencyKey::new(id.to_bytes())
                    .map_err(|_| TenantAliasHttpFailure::Code(400, "invalid_request"))?,
            )
            .map_err(map_failure)?;
        Ok(TenantAliasBindResponse {
            tenant: binding.tenant_id().to_canonical_text(),
            alias_generation: binding.alias_generation().get(),
            audit_position: binding.audit_position(),
            audit_ingest_time_unix_seconds: binding.audit_ingest_time_unix_seconds(),
        })
    }
}

fn map_failure(failure: crate::BootstrapFailure) -> TenantAliasHttpFailure {
    match failure.code() {
        BootstrapFailureCode::TenantAliasUnauthorized => {
            TenantAliasHttpFailure::Code(401, "authentication_rejected")
        },
        BootstrapFailureCode::TenantAliasUnknownTenant => {
            TenantAliasHttpFailure::Code(404, "tenant_unavailable")
        },
        BootstrapFailureCode::TenantAliasAlreadyBound => {
            TenantAliasHttpFailure::Code(409, "alias_already_bound")
        },
        BootstrapFailureCode::TenantAliasConflict => {
            TenantAliasHttpFailure::Code(409, "alias_conflict")
        },
        BootstrapFailureCode::TenantAliasStaleGeneration => {
            TenantAliasHttpFailure::Code(409, "stale_generation")
        },
        BootstrapFailureCode::TenantAliasIdempotencyConflict => {
            TenantAliasHttpFailure::Code(409, "idempotency_conflict")
        },
        _ => TenantAliasHttpFailure::Code(503, "administration_unavailable"),
    }
}
