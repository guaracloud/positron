use super::super::io::Response;

use crate::ServiceHandle;

macro_rules! bounded_json_response {
    ($value:expr, $limit:expr) => {{
        let body = serde_json::to_vec($value).map_err(|_| {
            Response::json(503, "{\"code\":\"administration_unavailable\"}".to_owned())
        })?;
        if body.len() > $limit {
            Err(Response::json(
                503,
                "{\"code\":\"administration_unavailable\"}".to_owned(),
            ))
        } else {
            Ok(Response {
                status: 200,
                content_type: "application/json",
                body,
                retry_after_seconds: None,
            })
        }
    }};
}

pub(in crate::native_host::native_http) fn policy_validation_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.validate_ingest_policy(bearer, body) {
        Ok(response) => bounded_json_response!(&response, 1024),
        Err((status, code)) => Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}"))),
    }
}

pub(in crate::native_host::native_http) fn policy_test_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.test_ingest_policy(bearer, body) {
        Ok(response) => bounded_json_response!(&response, 1024),
        Err((status, code)) => Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}"))),
    }
}

pub(in crate::native_host::native_http) fn policy_diff_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.diff_ingest_policy(bearer, body) {
        Ok(response) => bounded_json_response!(&response, 8192),
        Err((status, code)) => Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}"))),
    }
}

pub(in crate::native_host::native_http) fn policy_explain_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.explain_ingest_policy(bearer, body) {
        Ok(response) => bounded_json_response!(&response, 8192),
        Err((status, code)) => Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}"))),
    }
}

pub(in crate::native_host::native_http) fn policy_activate_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.activate_ingest_policy_http(bearer, body) {
        Ok(response) => Ok(Response {
            status: 200,
            content_type: "application/json",
            body: serde_json::to_vec(&response).map_err(|_| Response::empty(500))?,
            retry_after_seconds: None,
        }),
        Err(crate::services::policy::PolicyActivateHttpFailure::Code(status, code)) => {
            Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}")))
        },
        Err(crate::services::policy::PolicyActivateHttpFailure::StaleGeneration(generation)) => {
            Ok(Response::json(
                409,
                format!(
                    "{{\"code\":\"stale_generation\",\"resource_generation\":{},\"semantic_diff\":\"policy generation changed\"}}",
                    generation.get()
                ),
            ))
        },
    }
}
