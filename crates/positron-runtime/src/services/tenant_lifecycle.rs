use positron_api::tenant_lifecycle::{
    TenantLifecycleState, TenantLifecycleTransitionRequest, TenantLifecycleTransitionResponse,
};
use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::lifecycle::TenantLifecycleState as DomainState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};

use crate::{BootstrapFailureCode, ServiceHandle};

pub(crate) enum TenantLifecycleHttpFailure {
    Code(u16, &'static str),
    StaleGeneration {
        conflict: positron_governance::TenantLifecycleGenerationConflict,
        semantic_diff: &'static str,
    },
}

impl ServiceHandle {
    pub(crate) fn administer_tenant_lifecycle(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<TenantLifecycleTransitionResponse, TenantLifecycleHttpFailure> {
        let actor = self
            .instance
            .attribute(
                PresentedCredential::parse(bearer).map_err(|_| {
                    TenantLifecycleHttpFailure::Code(401, "authentication_rejected")
                })?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| TenantLifecycleHttpFailure::Code(401, "authentication_rejected"))?;
        let request = TenantLifecycleTransitionRequest::decode(body)
            .map_err(|_| TenantLifecycleHttpFailure::Code(400, "invalid_request"))?;
        let tenant = TenantId::parse_canonical(request.tenant())
            .map_err(|_| TenantLifecycleHttpFailure::Code(400, "invalid_request"))?;
        let expected = ResourceGeneration::new(request.expected_generation())
            .map_err(|_| TenantLifecycleHttpFailure::Code(400, "invalid_request"))?;
        let principal = PrincipalId::parse_canonical(request.idempotency_key())
            .map_err(|_| TenantLifecycleHttpFailure::Code(400, "invalid_request"))?;
        let idempotency = AdministrativeIdempotencyKey::new(principal.to_bytes())
            .map_err(|_| TenantLifecycleHttpFailure::Code(400, "invalid_request"))?;
        let target = domain_state(request.target());
        let transition = self
            .instance
            .transition_tenant_lifecycle(actor, tenant, target, expected, idempotency)
            .map_err(|failure| map_failure(failure, target))?;
        Ok(TenantLifecycleTransitionResponse {
            tenant: transition.tenant_id().to_canonical_text(),
            from: wire_state(transition.from()),
            to: wire_state(transition.to()),
            lifecycle_generation: transition.resource_generation().get(),
            audit_position: transition.audit_position(),
            audit_ingest_time_unix_seconds: transition.audit_ingest_time_unix_seconds(),
        })
    }
}
fn domain_state(state: TenantLifecycleState) -> DomainState {
    match state {
        TenantLifecycleState::Active => DomainState::Active,
        TenantLifecycleState::ReadOnly => DomainState::ReadOnly,
        TenantLifecycleState::Suspended => DomainState::Suspended,
        TenantLifecycleState::Purging => DomainState::Purging,
        TenantLifecycleState::Purged => DomainState::Purged,
    }
}
fn wire_state(state: DomainState) -> TenantLifecycleState {
    match state {
        DomainState::Active => TenantLifecycleState::Active,
        DomainState::ReadOnly => TenantLifecycleState::ReadOnly,
        DomainState::Suspended => TenantLifecycleState::Suspended,
        DomainState::Purging => TenantLifecycleState::Purging,
        DomainState::Purged => TenantLifecycleState::Purged,
    }
}
fn map_failure(
    failure: crate::BootstrapFailure,
    target: DomainState,
) -> TenantLifecycleHttpFailure {
    match failure.code() {
        BootstrapFailureCode::TenantLifecycleUnauthorized => {
            TenantLifecycleHttpFailure::Code(401, "authentication_rejected")
        },
        BootstrapFailureCode::TenantLifecycleUnknownTenant => {
            TenantLifecycleHttpFailure::Code(404, "tenant_unavailable")
        },
        BootstrapFailureCode::TenantLifecycleStaleGeneration => failure
            .lifecycle_generation_conflict()
            .map(|conflict| TenantLifecycleHttpFailure::StaleGeneration {
                semantic_diff: if conflict.current_state() == target {
                    "lifecycle generation changed"
                } else {
                    "lifecycle state changed"
                },
                conflict,
            })
            .unwrap_or(TenantLifecycleHttpFailure::Code(
                503,
                "administration_unavailable",
            )),
        BootstrapFailureCode::TenantLifecycleIdempotencyConflict => {
            TenantLifecycleHttpFailure::Code(409, "idempotency_conflict")
        },
        BootstrapFailureCode::TenantLifecycleInvalidTransition => {
            TenantLifecycleHttpFailure::Code(409, "invalid_transition")
        },
        BootstrapFailureCode::TenantLifecyclePurgeCompletionUnavailable => {
            TenantLifecycleHttpFailure::Code(409, "purge_completion_unavailable")
        },
        _ => TenantLifecycleHttpFailure::Code(503, "administration_unavailable"),
    }
}
