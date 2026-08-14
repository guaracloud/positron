use std::error::Error;

use positron_runtime::ListenerRole;

use super::support;

#[test]
fn loki_routes_are_owned_only_by_the_loki_push_listener() -> Result<(), Box<dyn Error>> {
    let harness = support::LiveLokiHarness::start("route-ownership")?;
    let protobuf = [("Content-Type", "application/x-protobuf")];

    for path in ["/loki/api/v1/push", "/otlp/v1/logs"] {
        support::assert_status(
            harness.http(ListenerRole::LokiPush, "POST", path, &protobuf, &[])?,
            401,
        );
        support::assert_status(
            harness.http(ListenerRole::OtlpHttp, "POST", path, &[], &[])?,
            404,
        );
        support::assert_status(
            harness.http(ListenerRole::Api, "POST", path, &[], &[])?,
            404,
        );
        support::assert_status(
            harness.http(ListenerRole::LokiPush, "GET", path, &[], &[])?,
            405,
        );
    }
    Ok(())
}
