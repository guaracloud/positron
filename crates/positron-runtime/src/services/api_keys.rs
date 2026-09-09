use positron_api::api_keys::{ApiKeyRequest, ApiKeyResponse, KeyAction, KeyDescriptor, KeyScope};
use positron_domain::identity::{PrincipalId, Scope};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};

use crate::{BootstrapFailureCode, ServiceHandle};

impl ServiceHandle {
    pub(crate) fn administer_api_keys(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<ApiKeyResponse, (u16, &'static str)> {
        let actor = self
            .instance
            .attribute(
                PresentedCredential::parse(bearer).map_err(|_| (401, "authentication_rejected"))?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| (401, "authentication_rejected"))?;
        let request = ApiKeyRequest::decode(body).map_err(|_| (400, "invalid_request"))?;
        let mut response = ApiKeyResponse {
            keys: Vec::new(),
            principal: None,
            secret: None,
        };
        if matches!(request.action(), KeyAction::List | KeyAction::ScopeInspect) {
            let keys = self
                .instance
                .list_api_keys(actor)
                .map_err(|error| map_failure(error.code()))?;
            response.keys = keys
                .into_iter()
                .filter(|key| {
                    request
                        .principal()
                        .is_none_or(|principal| key.principal_id().to_canonical_text() == principal)
                })
                .map(|key| KeyDescriptor {
                    principal: key.principal_id().to_canonical_text(),
                    scope: wire_scope(key.scope()).into(),
                    active: key.is_active(),
                    expires_at_unix_seconds: key.expires_at_unix_seconds(),
                    generation: key.generation().get(),
                })
                .collect();
            return Ok(response);
        }
        let expected = ResourceGeneration::new(
            request
                .expected_generation()
                .ok_or((400, "invalid_request"))?,
        )
        .map_err(|_| (400, "invalid_request"))?;
        let idempotency = PrincipalId::parse_canonical(
            request.idempotency_key().ok_or((400, "invalid_request"))?,
        )
        .map_err(|_| (400, "invalid_request"))?;
        let idempotency = AdministrativeIdempotencyKey::new(idempotency.to_bytes())
            .map_err(|_| (400, "invalid_request"))?;
        let created = match request.action() {
            KeyAction::Create => Some(
                self.instance
                    .create_api_key(
                        actor,
                        domain_scope(request.scope().ok_or((400, "invalid_request"))?)?,
                        request.expiry(),
                        expected,
                        idempotency,
                    )
                    .map_err(|error| map_failure(error.code()))?,
            ),
            KeyAction::Rotate | KeyAction::Revoke => {
                let principal = PrincipalId::parse_canonical(
                    request.principal().ok_or((400, "invalid_request"))?,
                )
                .map_err(|_| (400, "invalid_request"))?;
                if request.action() == KeyAction::Rotate {
                    Some(
                        self.instance
                            .rotate_api_key(actor, principal, expected, idempotency)
                            .map_err(|error| map_failure(error.code()))?,
                    )
                } else {
                    self.instance
                        .revoke_api_key(actor, principal, expected, idempotency)
                        .map_err(|error| map_failure(error.code()))?;
                    response.principal = Some(principal.to_canonical_text());
                    None
                }
            },
            KeyAction::Unspecified | KeyAction::List | KeyAction::ScopeInspect => {
                return Err((400, "invalid_request"));
            },
        };
        if let Some(created) = created {
            response.principal = Some(created.principal_id().to_canonical_text());
            response.secret = created.secret().map(ToOwned::to_owned);
        }
        Ok(response)
    }
}

fn map_failure(code: BootstrapFailureCode) -> (u16, &'static str) {
    match code {
        BootstrapFailureCode::ApiKeyUnauthorized => (401, "authentication_rejected"),
        BootstrapFailureCode::ApiKeyStaleGeneration => (409, "stale_generation"),
        BootstrapFailureCode::ApiKeyIdempotencyConflict => (409, "idempotency_conflict"),
        BootstrapFailureCode::ApiKeyUnavailable => (404, "key_unavailable"),
        _ => (503, "administration_unavailable"),
    }
}
fn domain_scope(scope: KeyScope) -> Result<Scope, (u16, &'static str)> {
    Ok(match scope {
        KeyScope::Unspecified => return Err((400, "invalid_request")),
        KeyScope::Ingest => Scope::Ingest,
        KeyScope::Query => Scope::Query,
        KeyScope::TenantAdministration => Scope::TenantAdministration,
        KeyScope::SystemAdministration => Scope::SystemAdministration,
    })
}
fn wire_scope(scope: Scope) -> KeyScope {
    match scope {
        Scope::Ingest => KeyScope::Ingest,
        Scope::Query => KeyScope::Query,
        Scope::TenantAdministration => KeyScope::TenantAdministration,
        Scope::SystemAdministration => KeyScope::SystemAdministration,
    }
}
