use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use positron_api::generated::{ApiError, CapabilityResponse};
use positron_governance::CompatibilityHints;
use zeroize::{Zeroize, Zeroizing};

use super::TrustedProxy;
use crate::{HealthState, HealthWarning, ListenerRole, Liveness, Readiness, ServiceHandle};

const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_API_BODY_BYTES: usize = positron_api::generated::MAX_PUBLIC_REQUEST_BYTES;

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

pub(super) fn serve_connection(
    stream: &mut TcpStream,
    role: ListenerRole,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<(), ConnectionFailure> {
    if stream.set_nonblocking(false).is_err()
        || stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .is_err()
        || stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .is_err()
    {
        return Err(ConnectionFailure);
    }
    let result = serve_checked(stream, role, peer, trusted_proxy, health, services);
    if let Err(response) = result {
        write_response(stream, response).map_err(|_| ConnectionFailure)?;
    }
    Ok(())
}

pub(super) struct ConnectionFailure;

pub(super) fn serve_tls_api_connection<S: Read + Write>(
    stream: &mut S,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<(), ConnectionFailure> {
    let result = (|| {
        let head = read_head(stream)?;
        let response = route_tls_api(stream, head, health, services)?;
        write_response(stream, response).map_err(|_| Response::empty(500))
    })();
    if let Err(response) = result {
        write_response(stream, response).map_err(|_| ConnectionFailure)?;
    }
    Ok(())
}

fn route_tls_api<S: Read + Write>(
    stream: &mut S,
    mut head: RequestHead,
    _health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<Response, Response> {
    match (head.method.as_str(), head.path.as_str()) {
        ("POST", positron_api::api_keys::HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::api_keys::MAX_REQUEST_BYTES,
            )?;
            match services.administer_api_keys(&bearer, &body) {
                Ok(response) => Ok(Response {
                    status: 200,
                    content_type: "application/json",
                    body: response.encode().map_err(|_| Response::empty(500))?,
                    retry_after_seconds: None,
                }),
                Err((status, code)) => {
                    Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}")))
                },
            }
        },
        ("POST", positron_api::tenant_quotas::HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_quotas::MAX_REQUEST_BYTES,
            )?;
            tenant_quota_response(services, &bearer, &body)
        },
        ("POST", positron_api::tenant_lifecycle::HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_lifecycle::MAX_REQUEST_BYTES,
            )?;
            tenant_lifecycle_response(services, &bearer, &body)
        },
        ("POST", positron_api::tenant_retention::PREVIEW_HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_retention::MAX_REQUEST_BYTES,
            )?;
            tenant_retention_preview_response(services, &bearer, &body)
        },
        ("POST", positron_api::tenant_retention::UPDATE_HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_retention::MAX_REQUEST_BYTES,
            )?;
            tenant_retention_update_response(services, &bearer, &body)
        },
        ("POST", positron_api::tenant_aliases::HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_aliases::MAX_REQUEST_BYTES,
            )?;
            tenant_alias_response(services, &bearer, &body)
        },
        ("POST", positron_api::tenant_service::CREATE_HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_service::MAX_REQUEST_BYTES,
            )?;
            tenant_service_response(
                services.create_tenant_service(&bearer, &body),
                positron_api::tenant_service::TenantCreateResponse::encode,
            )
        },
        ("POST", positron_api::tenant_service::INSPECT_HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_service::MAX_REQUEST_BYTES,
            )?;
            tenant_service_response(
                services.inspect_tenant_service(&bearer, &body),
                positron_api::tenant_service::TenantInspectResponse::encode,
            )
        },
        ("POST", positron_api::tenant_service::LIST_HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_service::MAX_REQUEST_BYTES,
            )?;
            tenant_service_response(
                services.list_tenants_service(&bearer, &body),
                positron_api::tenant_service::TenantListResponse::encode,
            )
        },
        ("POST", positron_api::tenant_service::UPDATE_DISPLAY_NAME_HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_service::MAX_REQUEST_BYTES,
            )?;
            tenant_service_response(
                services.update_tenant_display_name_service(&bearer, &body),
                positron_api::tenant_service::TenantDisplayNameUpdateResponse::encode,
            )
        },
        ("POST", positron_api::policy::HTTP_VALIDATE_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::policy::MAX_REQUEST_BYTES,
            )?;
            policy_validation_response(services, &bearer, &body)
        },
        ("POST", positron_api::policy::HTTP_TEST_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::policy::MAX_TEST_REQUEST_BYTES,
            )?;
            policy_test_response(services, &bearer, &body)
        },
        ("POST", positron_api::policy::HTTP_DIFF_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::policy::MAX_DIFF_REQUEST_BYTES,
            )?;
            policy_diff_response(services, &bearer, &body)
        },
        ("POST", positron_api::policy::HTTP_EXPLAIN_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::policy::MAX_EXPLAIN_REQUEST_BYTES,
            )?;
            policy_explain_response(services, &bearer, &body)
        },
        ("POST", positron_api::policy::HTTP_ACTIVATE_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::policy::MAX_ACTIVATE_REQUEST_BYTES,
            )?;
            policy_activate_response(services, &bearer, &body)
        },
        ("POST", "/v1/capabilities:negotiate") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let body = read_body(stream, head.content_length, MAX_API_BODY_BYTES)?;
            Ok(capability_response(services.negotiate_capability(&body)))
        },
        (
            _,
            positron_api::api_keys::HTTP_PATH
            | positron_api::tenant_quotas::HTTP_PATH
            | positron_api::tenant_lifecycle::HTTP_PATH
            | positron_api::tenant_retention::PREVIEW_HTTP_PATH
            | positron_api::tenant_retention::UPDATE_HTTP_PATH
            | positron_api::tenant_aliases::HTTP_PATH
            | positron_api::tenant_service::CREATE_HTTP_PATH
            | positron_api::tenant_service::INSPECT_HTTP_PATH
            | positron_api::tenant_service::LIST_HTTP_PATH
            | positron_api::tenant_service::UPDATE_DISPLAY_NAME_HTTP_PATH
            | positron_api::policy::HTTP_VALIDATE_PATH
            | positron_api::policy::HTTP_TEST_PATH
            | positron_api::policy::HTTP_DIFF_PATH
            | positron_api::policy::HTTP_EXPLAIN_PATH
            | positron_api::policy::HTTP_ACTIVATE_PATH
            | "/v1/capabilities:negotiate",
        ) => Ok(Response::empty(405)),
        _ => Ok(Response::empty(404)),
    }
}

fn serve_checked(
    stream: &mut TcpStream,
    role: ListenerRole,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<(), Response> {
    let head = read_head(stream)?;
    let response = route(stream, role, peer, trusted_proxy, head, health, services)?;
    write_response(stream, response).map_err(|_| Response::empty(500))
}

fn route(
    stream: &mut TcpStream,
    role: ListenerRole,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    mut head: RequestHead,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<Response, Response> {
    match (role, head.method.as_str(), head.path.as_str()) {
        (ListenerRole::Api, "POST", positron_api::api_keys::HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::api_keys::MAX_REQUEST_BYTES,
            )?;
            match services.administer_api_keys(&bearer, &body) {
                Ok(response) => {
                    let body = response.encode().map_err(|_| Response::empty(500))?;
                    Ok(Response {
                        status: 200,
                        content_type: "application/json",
                        body,
                        retry_after_seconds: None,
                    })
                },
                Err((status, code)) => {
                    Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}")))
                },
            }
        },
        (ListenerRole::Api, "POST", positron_api::tenant_quotas::HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_quotas::MAX_REQUEST_BYTES,
            )?;
            tenant_quota_response(services, &bearer, &body)
        },
        (ListenerRole::Api, "POST", positron_api::tenant_lifecycle::HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_lifecycle::MAX_REQUEST_BYTES,
            )?;
            tenant_lifecycle_response(services, &bearer, &body)
        },
        (ListenerRole::Api, "POST", positron_api::tenant_retention::PREVIEW_HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_retention::MAX_REQUEST_BYTES,
            )?;
            tenant_retention_preview_response(services, &bearer, &body)
        },
        (ListenerRole::Api, "POST", positron_api::tenant_retention::UPDATE_HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_retention::MAX_REQUEST_BYTES,
            )?;
            tenant_retention_update_response(services, &bearer, &body)
        },
        (ListenerRole::Api, "POST", positron_api::tenant_aliases::HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_aliases::MAX_REQUEST_BYTES,
            )?;
            tenant_alias_response(services, &bearer, &body)
        },
        (ListenerRole::Api, "POST", positron_api::tenant_service::CREATE_HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_service::MAX_REQUEST_BYTES,
            )?;
            tenant_service_response(
                services.create_tenant_service(&bearer, &body),
                positron_api::tenant_service::TenantCreateResponse::encode,
            )
        },
        (ListenerRole::Api, "POST", positron_api::tenant_service::INSPECT_HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_service::MAX_REQUEST_BYTES,
            )?;
            tenant_service_response(
                services.inspect_tenant_service(&bearer, &body),
                positron_api::tenant_service::TenantInspectResponse::encode,
            )
        },
        (ListenerRole::Api, "POST", positron_api::tenant_service::LIST_HTTP_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_service::MAX_REQUEST_BYTES,
            )?;
            tenant_service_response(
                services.list_tenants_service(&bearer, &body),
                positron_api::tenant_service::TenantListResponse::encode,
            )
        },
        (
            ListenerRole::Api,
            "POST",
            positron_api::tenant_service::UPDATE_DISPLAY_NAME_HTTP_PATH,
        ) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::tenant_service::MAX_REQUEST_BYTES,
            )?;
            tenant_service_response(
                services.update_tenant_display_name_service(&bearer, &body),
                positron_api::tenant_service::TenantDisplayNameUpdateResponse::encode,
            )
        },
        (ListenerRole::Api, "POST", positron_api::policy::HTTP_VALIDATE_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::policy::MAX_REQUEST_BYTES,
            )?;
            policy_validation_response(services, &bearer, &body)
        },
        (ListenerRole::Api, "POST", positron_api::policy::HTTP_TEST_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::policy::MAX_TEST_REQUEST_BYTES,
            )?;
            policy_test_response(services, &bearer, &body)
        },
        (ListenerRole::Api, "POST", positron_api::policy::HTTP_DIFF_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::policy::MAX_DIFF_REQUEST_BYTES,
            )?;
            policy_diff_response(services, &bearer, &body)
        },
        (ListenerRole::Api, "POST", positron_api::policy::HTTP_EXPLAIN_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::policy::MAX_EXPLAIN_REQUEST_BYTES,
            )?;
            policy_explain_response(services, &bearer, &body)
        },
        (ListenerRole::Api, "POST", positron_api::policy::HTTP_ACTIVATE_PATH) => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            let body = read_body(
                stream,
                head.content_length,
                positron_api::policy::MAX_ACTIVATE_REQUEST_BYTES,
            )?;
            policy_activate_response(services, &bearer, &body)
        },
        (ListenerRole::Operations, "GET", "/health/live") => Ok(health_response(
            health.liveness() == Liveness::Live,
            "live",
            health.security_warning(),
        )),
        (ListenerRole::Operations, "GET", "/health/ready") => Ok(health_response(
            health.readiness() == Readiness::Ready,
            "ready",
            health.security_warning(),
        )),
        (ListenerRole::Api, "POST", "/v1/capabilities:negotiate") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let body = read_body(stream, head.content_length, MAX_API_BODY_BYTES)?;
            Ok(capability_response(services.negotiate_capability(&body)))
        },
        (ListenerRole::OtlpHttp, "POST", "/v1/logs") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            super::otlp_http::receive_from(stream, head, peer, trusted_proxy, services)
        },
        (ListenerRole::OtlpHttp, "POST", "/v1/traces") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            super::otlp_http::receive_traces_from(stream, head, peer, trusted_proxy, services)
        },
        (ListenerRole::LokiPush, "POST", "/loki/api/v1/push") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            super::loki_http::receive_push(stream, head, peer, trusted_proxy, services)
        },
        (ListenerRole::LokiPush, "POST", "/otlp/v1/logs") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            super::otlp_http::receive_from(stream, head, peer, trusted_proxy, services)
        },
        (ListenerRole::Operations, _, "/health/live" | "/health/ready")
        | (ListenerRole::Api, _, "/v1/capabilities:negotiate")
        | (ListenerRole::Api, _, positron_api::api_keys::HTTP_PATH)
        | (ListenerRole::Api, _, positron_api::tenant_quotas::HTTP_PATH)
        | (ListenerRole::Api, _, positron_api::tenant_retention::PREVIEW_HTTP_PATH)
        | (ListenerRole::Api, _, positron_api::tenant_retention::UPDATE_HTTP_PATH)
        | (ListenerRole::Api, _, positron_api::tenant_aliases::HTTP_PATH)
        | (ListenerRole::Api, _, positron_api::tenant_service::CREATE_HTTP_PATH)
        | (ListenerRole::Api, _, positron_api::tenant_service::INSPECT_HTTP_PATH)
        | (ListenerRole::Api, _, positron_api::tenant_service::LIST_HTTP_PATH)
        | (ListenerRole::Api, _, positron_api::tenant_service::UPDATE_DISPLAY_NAME_HTTP_PATH)
        | (ListenerRole::Api, _, positron_api::policy::HTTP_VALIDATE_PATH)
        | (ListenerRole::Api, _, positron_api::policy::HTTP_TEST_PATH)
        | (ListenerRole::Api, _, positron_api::policy::HTTP_DIFF_PATH)
        | (ListenerRole::Api, _, positron_api::policy::HTTP_EXPLAIN_PATH)
        | (ListenerRole::Api, _, positron_api::policy::HTTP_ACTIVATE_PATH)
        | (ListenerRole::OtlpHttp, _, "/v1/logs" | "/v1/traces") => Ok(Response::empty(405)),
        (ListenerRole::LokiPush, _, "/loki/api/v1/push" | "/otlp/v1/logs") => {
            Ok(Response::empty(405))
        },
        (ListenerRole::Control, _, _) | (_, _, _) => Ok(Response::empty(404)),
    }
}

fn tenant_alias_response(
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

fn tenant_service_response<T>(
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

fn tenant_lifecycle_response(
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

fn tenant_retention_preview_response(
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

fn tenant_retention_update_response(
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

fn tenant_quota_response(
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

fn policy_validation_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.validate_ingest_policy(bearer, body) {
        Ok(response) => bounded_json_response!(&response, 1024),
        Err((status, code)) => Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}"))),
    }
}

fn policy_test_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.test_ingest_policy(bearer, body) {
        Ok(response) => bounded_json_response!(&response, 1024),
        Err((status, code)) => Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}"))),
    }
}

fn policy_diff_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.diff_ingest_policy(bearer, body) {
        Ok(response) => bounded_json_response!(&response, 8192),
        Err((status, code)) => Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}"))),
    }
}

fn policy_explain_response(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<Response, Response> {
    match services.explain_ingest_policy(bearer, body) {
        Ok(response) => bounded_json_response!(&response, 8192),
        Err((status, code)) => Ok(Response::json(status, format!("{{\"code\":\"{code}\"}}"))),
    }
}

fn policy_activate_response(
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

pub(super) struct RequestHead {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) content_length: usize,
    pub(super) bearer: Option<String>,
    pub(super) content_type: Option<String>,
    pub(super) content_encoding: Option<String>,
    pub(super) tenant_hint: Option<String>,
    pub(super) forwarded_for: Option<String>,
    pub(super) forwarded_actor: Option<String>,
}

impl RequestHead {
    pub(super) fn compatibility_hints(
        &self,
        peer: std::net::SocketAddr,
        trusted_proxy: Option<TrustedProxy>,
    ) -> Result<CompatibilityHints, ()> {
        let forwarded = self.forwarded_for.is_some() || self.forwarded_actor.is_some();
        match trusted_proxy {
            Some(policy) if forwarded => {
                if !policy.validates(peer, self.forwarded_for.as_deref()) {
                    return Err(());
                }
                CompatibilityHints::trusted_proxy(
                    self.tenant_hint.as_deref(),
                    self.forwarded_actor.as_deref(),
                )
                .map_err(|_| ())
            },
            Some(_) | None => self
                .tenant_hint
                .as_deref()
                .map(CompatibilityHints::external_tenant_alias)
                .transpose()
                .map_err(|_| ())
                .map(|hints| hints.unwrap_or_else(CompatibilityHints::none)),
        }
    }
}

fn read_head<S: Read>(stream: &mut S) -> Result<RequestHead, Response> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(512));
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == MAX_HEADER_BYTES {
            return Err(Response::empty(431));
        }
        stream
            .read_exact(&mut byte)
            .map_err(|_| Response::empty(400))?;
        bytes.push(byte[0]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Response::empty(400))?;
    let mut lines = text.split("\r\n");
    let mut request = lines.next().ok_or_else(|| Response::empty(400))?.split(' ');
    let method = request.next().ok_or_else(|| Response::empty(400))?;
    let path = request.next().ok_or_else(|| Response::empty(400))?;
    if request.next() != Some("HTTP/1.1") || request.next().is_some() {
        return Err(Response::empty(400));
    }
    let mut content_length = None;
    let mut bearer = None;
    let mut authorization_seen = false;
    let mut content_type = None;
    let mut content_encoding = None;
    let mut tenant_hint = None;
    let mut forwarded_for = None;
    let mut forwarded_actor = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| Response::empty(400))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(Response::empty(400));
            }
            content_length = Some(value.parse().map_err(|_| Response::empty(400))?);
        } else if name.eq_ignore_ascii_case("authorization") {
            if authorization_seen {
                return Err(Response::empty(400));
            }
            authorization_seen = true;
            bearer = value.strip_prefix("Bearer ").map(ToOwned::to_owned);
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() {
                return Err(Response::empty(400));
            }
            content_type = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("content-encoding") {
            if content_encoding.is_some() {
                return Err(Response::empty(400));
            }
            content_encoding = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("x-scope-orgid") {
            if tenant_hint.is_some() {
                return Err(Response::empty(400));
            }
            tenant_hint = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("x-forwarded-for") {
            if forwarded_for.is_some() {
                return Err(Response::empty(400));
            }
            forwarded_for = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("x-forwarded-user")
            || name.eq_ignore_ascii_case("x-forwarded-service")
        {
            if forwarded_actor.is_some() {
                return Err(Response::empty(400));
            }
            forwarded_actor = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Response::empty(400));
        }
    }
    Ok(RequestHead {
        method: method.to_owned(),
        path: path.to_owned(),
        content_length: content_length.unwrap_or(0),
        bearer,
        content_type,
        content_encoding,
        tenant_hint,
        forwarded_for,
        forwarded_actor,
    })
}

pub(super) fn read_body<S: Read>(
    stream: &mut S,
    length: usize,
    maximum: usize,
) -> Result<Vec<u8>, Response> {
    if length > maximum {
        return Err(Response::empty(413));
    }
    let mut body = vec![0_u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|_| Response::empty(400))?;
    Ok(body)
}

fn health_response(healthy: bool, label: &'static str, warning: Option<HealthWarning>) -> Response {
    let warnings = match warning {
        Some(HealthWarning::PublicPlaintextApi) => "[\"public_plaintext_api\"]",
        None => "[]",
    };
    if healthy {
        Response::json(
            200,
            format!("{{\"status\":\"{label}\",\"warnings\":{warnings}}}"),
        )
    } else {
        Response::json(
            503,
            format!("{{\"status\":\"not_{label}\",\"warnings\":{warnings}}}"),
        )
    }
}

fn capability_response(result: Result<CapabilityResponse, ApiError>) -> Response {
    match result {
        Ok(response) => {
            let refusal = response.refusal().map_or_else(
                || "null".to_owned(),
                |error| {
                    format!(
                        "{{\"code\":{},\"retry_class\":{},\"completion_state\":{},\"source\":{},\"safe_detail\":{}}}",
                        error.code() as u32,
                        error.retry_class() as u32,
                        error.completion_state() as u32,
                        error.source() as u32,
                        error.safe_detail() as u32
                    )
                },
            );
            Response::json(
                200,
                format!(
                    "{{\"api_major\":{},\"schema_digest\":\"{}\",\"availability\":{},\"refusal\":{},\"deprecation\":{},\"capability\":{}}}",
                    response.api_major().major(),
                    response.schema_digest().as_str(),
                    response.availability() as u32,
                    refusal,
                    response.deprecation() as u32,
                    response.capability() as u32
                ),
            )
        },
        Err(error) => Response::json(400, format!("{{\"code\":{}}}", error.code() as u32)),
    }
}

pub(super) struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    retry_after_seconds: Option<u32>,
}

impl Drop for Response {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl Response {
    pub(super) fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: Vec::new(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into_bytes(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn protobuf(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/x-protobuf",
            body,
            retry_after_seconds: None,
        }
    }

    pub(super) const fn with_retry_after(mut self, seconds: u32) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }

    #[cfg(test)]
    pub(super) const fn status(&self) -> u16 {
        self.status
    }

    #[cfg(test)]
    pub(super) const fn content_type(&self) -> &'static str {
        self.content_type
    }

    #[cfg(test)]
    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }

    #[cfg(test)]
    pub(super) const fn retry_after_seconds(&self) -> Option<u32> {
        self.retry_after_seconds
    }
}

fn write_response<S: Write>(stream: &mut S, response: Response) -> Result<(), std::io::Error> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let retry_after = response
        .retry_after_seconds
        .map_or_else(String::new, |seconds| format!("Retry-After: {seconds}\r\n"));
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len(),
        retry_after
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&response.body)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use super::serve_tls_api_connection;

    struct MemoryStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl MemoryStream {
        fn request(path: &str) -> Self {
            Self {
                input: Cursor::new(
                    format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n")
                        .into_bytes(),
                ),
                output: Vec::new(),
            }
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
            self.input.read(buffer)
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, buffer: &[u8]) -> Result<usize, std::io::Error> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    #[test]
    fn tls_api_dispatch_reaches_each_existing_authenticated_route() {
        let health = crate::health::ProcessState::starting().health();
        for path in [
            positron_api::tenant_aliases::HTTP_PATH,
            positron_api::policy::HTTP_EXPLAIN_PATH,
            positron_api::policy::HTTP_ACTIVATE_PATH,
        ] {
            let mut stream = MemoryStream::request(path);
            assert!(serve_tls_api_connection(&mut stream, &health, None).is_ok());
            let response = std::str::from_utf8(&stream.output).expect("HTTP response");
            assert!(
                response.starts_with("HTTP/1.1 503 Service Unavailable"),
                "TLS dispatcher did not reach {path}: {response}"
            );
        }
    }
}
