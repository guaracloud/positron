//! Exact-origin CORS policy for the native API listener.

use http::{HeaderMap, HeaderValue, Method, Response, StatusCode, header};

use super::api_http::ApiResponseBody;
use super::native_http;

const ALLOWED_REQUEST_HEADERS: &str = "authorization, content-type";
const VARY_ORIGIN: &str = "Origin";
const VARY_PREFLIGHT: &str =
    "Origin, Access-Control-Request-Method, Access-Control-Request-Headers";

pub(super) fn preflight(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    configured: &[String],
) -> Option<Response<ApiResponseBody>> {
    if method != Method::OPTIONS {
        return None;
    }
    if !headers.contains_key(header::ORIGIN)
        && !headers.contains_key("access-control-request-method")
    {
        return None;
    }
    let Some(origin) = allowed_origin(headers, configured) else {
        return Some(empty_response(StatusCode::NO_CONTENT));
    };
    let Some(requested_method) = single_header(headers, "access-control-request-method")
        .and_then(|value| value.to_str().ok())
    else {
        return Some(empty_response(StatusCode::NO_CONTENT));
    };
    if !native_http::api_supports(requested_method, path)
        || !requested_headers_are_supported(headers)
    {
        return Some(empty_response(StatusCode::NO_CONTENT));
    }
    let mut response = empty_response(StatusCode::NO_CONTENT);
    let response_headers = response.headers_mut();
    response_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    response_headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST"),
    );
    response_headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(ALLOWED_REQUEST_HEADERS),
    );
    response_headers.insert(header::VARY, HeaderValue::from_static(VARY_PREFLIGHT));
    Some(response)
}

pub(super) fn decorate(
    response: &mut Response<ApiResponseBody>,
    headers: &HeaderMap,
    configured: &[String],
) {
    let Some(origin) = allowed_origin(headers, configured) else {
        return;
    };
    response
        .headers_mut()
        .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static(VARY_ORIGIN));
}

fn allowed_origin(headers: &HeaderMap, configured: &[String]) -> Option<HeaderValue> {
    let origin = single_header(headers, header::ORIGIN)?.to_str().ok()?;
    configured
        .iter()
        .any(|configured| configured == origin)
        .then(|| HeaderValue::from_str(origin).ok())
        .flatten()
}

fn requested_headers_are_supported(headers: &HeaderMap) -> bool {
    let Some(requested) = single_header(headers, "access-control-request-headers") else {
        return true;
    };
    let Ok(requested) = requested.to_str() else {
        return false;
    };
    requested.split(',').all(|name| {
        matches!(
            name.trim().to_ascii_lowercase().as_str(),
            "authorization" | "content-type"
        )
    })
}

fn single_header(
    headers: &HeaderMap,
    name: impl http::header::AsHeaderName,
) -> Option<&HeaderValue> {
    let values = headers.get_all(name);
    (values.iter().count() == 1)
        .then(|| values.iter().next())
        .flatten()
}

fn empty_response(status: StatusCode) -> Response<ApiResponseBody> {
    let mut response = Response::new(ApiResponseBody::empty());
    *response.status_mut() = status;
    response
}
