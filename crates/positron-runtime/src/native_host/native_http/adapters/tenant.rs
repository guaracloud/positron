use super::super::io::Response;

use crate::ServiceHandle;

pub(in crate::native_host::native_http) fn tenant_alias_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.bind_tenant_alias(bearer, body) {
        Ok(response) => Ok(Response {
            status: 200,
            content_type: "application/json",
            body: serde_json::to_vec(&response).map_err(|_| Response::empty(500))?,
            retry_after_seconds: None,
        }),
        Err(crate::services::tenant_aliases::TenantAliasHttpFailure::Code(status, code)) => {
            Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}")))
        },
    }
}

pub(in crate::native_host::native_http) fn tenant_service_response<T>(
    result: Result<T, crate::services::tenant_service::TenantServiceHttpFailure>,
    encode: fn(&T) -> Result<Vec<u8>, positron_api::tenant_service::TenantServiceWireFailure>,
) -> Result<Response, Response> {
    match result {
        Ok(response) => Ok(Response {
            status: 200,
            content_type: "application/json",
            body: encode(&response).map_err(|_| {
                Response::json(503, "{\"code\":\"administration_unavailable\"}".to_owned())
            })?,
            retry_after_seconds: None,
        }),
        Err(crate::services::tenant_service::TenantServiceHttpFailure::Code(status, code)) => {
            Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}")))
        },
        Err(
            crate::services::tenant_service::TenantServiceHttpFailure::StaleDisplayGeneration {
                generation,
                semantic_diff,
            },
        ) => Ok(Response::json(
            409,
            format!(
                "{{\"code\":\"stale_display_generation\",\"display_generation\":{generation},\"semantic_diff\":\"{semantic_diff}\"}}"
            ),
        )),
    }
}

pub(in crate::native_host::native_http) fn tenant_lifecycle_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.administer_tenant_lifecycle(bearer, body) {
        Ok(response) => Ok(Response {
            status: 200,
            content_type: "application/json",
            body: serde_json::to_vec(&response).map_err(|_| Response::empty(500))?,
            retry_after_seconds: None,
        }),
        Err(crate::services::tenant_lifecycle::TenantLifecycleHttpFailure::Code(status, code)) => {
            Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}")))
        },
        Err(crate::services::tenant_lifecycle::TenantLifecycleHttpFailure::StaleGeneration {
            conflict,
            semantic_diff,
        }) => Ok(Response::json(
            409,
            format!(
                "{{\"code\":\"stale_generation\",\"lifecycle_generation\":{},\"semantic_diff\":\"{semantic_diff}\"}}",
                conflict.current_generation().get()
            ),
        )),
    }
}

pub(in crate::native_host::native_http) fn tenant_retention_preview_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.preview_tenant_retention(bearer, body) {
        Ok(response) => Ok(Response {
            status: 200,
            content_type: "application/json",
            body: response.encode().map_err(|_| {
                Response::json(503, "{\"code\":\"administration_unavailable\"}".to_owned())
            })?,
            retry_after_seconds: None,
        }),
        Err(crate::services::tenant_retention::TenantRetentionHttpFailure::Code(status, code)) => {
            Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}")))
        },
        Err(crate::services::tenant_retention::TenantRetentionHttpFailure::StaleGeneration {
            generation,
            semantic_diff,
        }) => Ok(Response::json(
            409,
            format!(
                "{{\"code\":\"stale_generation\",\"retention_generation\":{generation},\"semantic_diff\":\"{semantic_diff}\"}}"
            ),
        )),
    }
}

pub(in crate::native_host::native_http) fn tenant_retention_update_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.update_tenant_retention_service(bearer, body) {
        Ok(response) => Ok(Response {
            status: 200,
            content_type: "application/json",
            body: response.encode().map_err(|_| {
                Response::json(503, "{\"code\":\"administration_unavailable\"}".to_owned())
            })?,
            retry_after_seconds: None,
        }),
        Err(crate::services::tenant_retention::TenantRetentionHttpFailure::Code(status, code)) => {
            Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}")))
        },
        Err(crate::services::tenant_retention::TenantRetentionHttpFailure::StaleGeneration {
            generation,
            semantic_diff,
        }) => Ok(Response::json(
            409,
            format!(
                "{{\"code\":\"stale_generation\",\"retention_generation\":{generation},\"semantic_diff\":\"{semantic_diff}\"}}"
            ),
        )),
    }
}

pub(in crate::native_host::native_http) fn tenant_quota_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.administer_tenant_quota(bearer, body) {
        Ok(response) => Ok(Response {
            status: 200,
            content_type: "application/json",
            body: serde_json::to_vec(&response).map_err(|_| Response::empty(500))?,
            retry_after_seconds: None,
        }),
        Err(crate::services::tenant_quotas::TenantQuotaHttpFailure::Code(status, code)) => {
            Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}")))
        },
        Err(crate::services::tenant_quotas::TenantQuotaHttpFailure::StaleGeneration(conflict)) => {
            Ok(Response::json(
                409,
                format!(
                    "{{\"code\":\"stale_generation\",\"resource_generation\":{},\"semantic_diff\":{}}}",
                    conflict.current_generation().get(),
                    serde_json::to_string(&conflict.semantic_diff())
                        .map_err(|_| Response::empty(500))?,
                ),
            ))
        },
    }
}
