use std::io::{Read, Write};
use std::net::TcpStream;

use zeroize::Zeroizing;

use super::super::TrustedProxy;
use super::adapters::policy::{
    policy_activate_response, policy_diff_response, policy_explain_response, policy_test_response,
    policy_validation_response,
};
use super::adapters::tenant::{
    tenant_alias_response, tenant_lifecycle_response, tenant_quota_response,
    tenant_retention_preview_response, tenant_retention_update_response, tenant_service_response,
};
use super::io::{
    RequestHead, Response, capability_response, configuration_status_response, health_response,
    read_body,
};
use crate::{HealthState, ListenerRole, Liveness, Readiness, ServiceHandle};

const MAX_API_BODY_BYTES: usize = positron_api::generated::MAX_PUBLIC_REQUEST_BYTES;

pub(super) fn route_tls_api<S: Read + Write>(
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

pub(super) fn route(
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
        (ListenerRole::Operations, "GET", "/status") => {
            let bearer = Zeroizing::new(head.bearer.take().ok_or_else(|| {
                Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
            })?);
            health
                .authorize_configuration_status(&bearer)
                .map_err(|_| {
                    Response::json(401, "{\"code\":\"authentication_rejected\"}".to_owned())
                })?;
            health
                .configuration_status()
                .map_err(|_| Response::empty(503))?
                .map_or_else(
                    || Ok(Response::empty(503)),
                    |status| Ok(configuration_status_response(health.phase(), &status)),
                )
        },
        (ListenerRole::Api, "POST", "/v1/capabilities:negotiate") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let body = read_body(stream, head.content_length, MAX_API_BODY_BYTES)?;
            Ok(capability_response(services.negotiate_capability(&body)))
        },
        (ListenerRole::OtlpHttp, "POST", "/v1/logs") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            super::super::otlp_http::receive_from(stream, head, peer, trusted_proxy, services)
        },
        (ListenerRole::OtlpHttp, "POST", "/v1/traces") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            super::super::otlp_http::receive_traces_from(
                stream,
                head,
                peer,
                trusted_proxy,
                services,
            )
        },
        (ListenerRole::LokiPush, "POST", "/loki/api/v1/push") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            super::super::loki_http::receive_push(stream, head, peer, trusted_proxy, services)
        },
        (ListenerRole::LokiPush, "POST", "/otlp/v1/logs") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            super::super::otlp_http::receive_from(stream, head, peer, trusted_proxy, services)
        },
        (ListenerRole::Operations, _, "/health/live" | "/health/ready" | "/status")
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
