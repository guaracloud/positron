use std::error::Error;

use positron_runtime::ListenerRole;

use super::support;

#[test]
fn loki_tenant_attribution_precedes_body_bounds_and_decode() -> Result<(), Box<dyn Error>> {
    let harness = support::LiveLokiHarness::start("auth-order")?;
    let json = [("Content-Type", "application/json")];

    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &json,
            b"{not-json}",
        )?,
        401,
    );
    support::assert_status(
        harness.http_with_advertised_length(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", &format!("Bearer {}", harness.bearer())),
                ("Content-Type", "application/json"),
                ("X-Scope-OrgID", "other-tenant"),
            ],
            1_048_577,
        )?,
        401,
    );
    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", &format!("Bearer {}", harness.bearer())),
                ("Content-Type", "application/json"),
            ],
            b"{not-json}",
        )?,
        400,
    );
    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", &format!("Bearer {}", harness.bearer())),
                ("Content-Type", "application/json"),
            ],
            br#"{"streams":[]}"#,
        )?,
        204,
    );
    Ok(())
}
