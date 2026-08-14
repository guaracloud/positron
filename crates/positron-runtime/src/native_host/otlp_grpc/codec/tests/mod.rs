use super::unimplemented_response;

#[test]
fn unknown_otlp_logs_route_has_the_canonical_unimplemented_response() {
    let response = unimplemented_response();

    assert_eq!(
        response.headers().get(tonic::Status::GRPC_STATUS),
        Some(&(tonic::Code::Unimplemented as i32).into())
    );
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("application/grpc"))
    );
}
