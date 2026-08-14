use super::ServiceFailure;

#[test]
fn service_diagnostics_are_stable_and_secret_free() {
    assert_eq!(
        ServiceFailure::Unauthorized.to_string(),
        "runtime service request failed"
    );
}
