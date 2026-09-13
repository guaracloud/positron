use positron_api::tenant_service::{
    TenantCreateRequest, TenantCreateResponse, TenantDescriptor, TenantDisplayNameUpdateRequest,
    TenantDisplayNameUpdateResponse, TenantInspectRequest, TenantInspectResponse,
    TenantLifecycleState, TenantListRequest, TenantListResponse,
};
use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState as DomainLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};

use crate::{BootstrapFailure, BootstrapFailureCode, ServiceHandle};

pub(crate) enum TenantServiceHttpFailure {
    Code(u16, &'static str),
    StaleDisplayGeneration {
        generation: u64,
        semantic_diff: &'static str,
    },
}

impl ServiceHandle {
    pub(crate) fn create_tenant_service(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<TenantCreateResponse, TenantServiceHttpFailure> {
        let actor = system_actor(self, bearer)?;
        let request = TenantCreateRequest::decode(body).map_err(invalid)?;
        let tenant = TenantId::parse_canonical(request.tenant()).map_err(invalid)?;
        let slug = TenantSlug::parse_canonical(request.slug()).map_err(invalid)?;
        let created = self
            .instance
            .create_tenant(
                actor,
                tenant,
                positron_governance::TenantCreateConfiguration::new(
                    slug,
                    request.display_name(),
                    request.retention_seconds(),
                    request.weight(),
                    request.resources(),
                ),
                idempotency(request.idempotency_key())?,
            )
            .map_err(map_create_failure)?;
        Ok(TenantCreateResponse {
            tenant: created.tenant_id().to_canonical_text(),
            resource_generation: created.resource_generation().get(),
            audit_position: created.audit_position(),
        })
    }

    pub(crate) fn inspect_tenant_service(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<TenantInspectResponse, TenantServiceHttpFailure> {
        let actor = system_actor(self, bearer)?;
        let request = TenantInspectRequest::decode(body).map_err(invalid)?;
        let tenant = TenantId::parse_canonical(request.tenant()).map_err(invalid)?;
        let inspection = self
            .instance
            .inspect_tenant(actor, tenant)
            .map_err(|failure| {
                if failure.code() == BootstrapFailureCode::ApiKeyUnauthorized {
                    TenantServiceHttpFailure::Code(404, "tenant_unavailable")
                } else {
                    unavailable(failure)
                }
            })?;
        Ok(TenantInspectResponse {
            tenant: descriptor(&inspection),
        })
    }

    pub(crate) fn list_tenants_service(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<TenantListResponse, TenantServiceHttpFailure> {
        let actor = system_actor(self, bearer)?;
        TenantListRequest::decode(body).map_err(invalid)?;
        let inspections = self.instance.list_tenants(actor).map_err(unavailable)?;
        let mut tenants = Vec::new();
        tenants
            .try_reserve(inspections.len())
            .map_err(|_| TenantServiceHttpFailure::Code(503, "administration_unavailable"))?;
        for inspection in &inspections {
            tenants.push(descriptor(inspection));
        }
        Ok(TenantListResponse { tenants })
    }

    pub(crate) fn update_tenant_display_name_service(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<TenantDisplayNameUpdateResponse, TenantServiceHttpFailure> {
        let actor = system_actor(self, bearer)?;
        let request = TenantDisplayNameUpdateRequest::decode(body).map_err(invalid)?;
        let tenant = TenantId::parse_canonical(request.tenant()).map_err(invalid)?;
        let expected =
            ResourceGeneration::new(request.expected_display_generation()).map_err(invalid)?;
        let update = self
            .instance
            .update_tenant_display_name(
                actor,
                tenant,
                expected,
                request.display_name(),
                idempotency(request.idempotency_key())?,
            )
            .map_err(map_display_failure)?;
        Ok(TenantDisplayNameUpdateResponse {
            tenant: tenant.to_canonical_text(),
            display_generation: update.resource_generation().get(),
            audit_position: update.audit_position(),
        })
    }
}

fn system_actor(
    services: &ServiceHandle,
    bearer: &str,
) -> Result<positron_governance::AuthorizedContext, TenantServiceHttpFailure> {
    services
        .instance
        .attribute(
            PresentedCredential::parse(bearer)
                .map_err(|_| TenantServiceHttpFailure::Code(401, "authentication_rejected"))?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
        .map_err(|_| TenantServiceHttpFailure::Code(401, "authentication_rejected"))
}
fn idempotency(value: &str) -> Result<AdministrativeIdempotencyKey, TenantServiceHttpFailure> {
    let principal = PrincipalId::parse_canonical(value).map_err(invalid)?;
    AdministrativeIdempotencyKey::new(principal.to_bytes()).map_err(invalid)
}
fn descriptor(inspection: &positron_governance::TenantInspection) -> TenantDescriptor {
    TenantDescriptor {
        tenant: inspection.tenant_id().to_canonical_text(),
        slug: inspection.slug().to_owned(),
        display_name: inspection.display_name().to_owned(),
        retention_seconds: inspection.retention_seconds(),
        display_generation: inspection.display_generation().get(),
        retention_generation: inspection.retention_generation().get(),
        lifecycle: lifecycle(inspection.lifecycle()),
    }
}
fn lifecycle(state: DomainLifecycleState) -> TenantLifecycleState {
    match state {
        DomainLifecycleState::Active => TenantLifecycleState::Active,
        DomainLifecycleState::ReadOnly => TenantLifecycleState::ReadOnly,
        DomainLifecycleState::Suspended => TenantLifecycleState::Suspended,
        DomainLifecycleState::Purging => TenantLifecycleState::Purging,
        DomainLifecycleState::Purged => TenantLifecycleState::Purged,
    }
}
fn invalid<T>(_: T) -> TenantServiceHttpFailure {
    TenantServiceHttpFailure::Code(400, "invalid_request")
}
fn map_create_failure(failure: BootstrapFailure) -> TenantServiceHttpFailure {
    match failure.code() {
        BootstrapFailureCode::TenantCreateConflict => {
            TenantServiceHttpFailure::Code(409, "tenant_conflict")
        },
        BootstrapFailureCode::ApiKeyIdempotencyConflict => {
            TenantServiceHttpFailure::Code(409, "idempotency_conflict")
        },
        _ => unavailable(failure),
    }
}
fn map_display_failure(failure: BootstrapFailure) -> TenantServiceHttpFailure {
    match failure.code() {
        BootstrapFailureCode::TenantDisplayNameIdempotencyConflict => {
            TenantServiceHttpFailure::Code(409, "idempotency_conflict")
        },
        BootstrapFailureCode::TenantDisplayNameStaleGeneration => failure
            .display_generation_conflict()
            .map(
                |conflict| TenantServiceHttpFailure::StaleDisplayGeneration {
                    generation: conflict.current_generation().get(),
                    semantic_diff: conflict.semantic_diff(),
                },
            )
            .unwrap_or_else(|| unavailable(failure)),
        _ => unavailable(failure),
    }
}
fn unavailable(_: BootstrapFailure) -> TenantServiceHttpFailure {
    TenantServiceHttpFailure::Code(503, "administration_unavailable")
}
