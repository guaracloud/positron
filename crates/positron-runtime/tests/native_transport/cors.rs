use super::*;

use h2::client;
use http::Request;
use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};
use tokio::net::TcpStream;

fn cors_configuration(
    roots: &TestRoots,
) -> Result<positron_config::EffectiveConfiguration, Box<dyn std::error::Error>> {
    let document = format!(
        "schema_version = 1\n[listener]\ncontrol_path = \"{}\"\noperations_bind_address = \"127.0.0.1:0\"\napi_bind_address = \"127.0.0.1:0\"\notlp_grpc_bind_address = \"127.0.0.1:0\"\notlp_http_bind_address = \"127.0.0.1:0\"\nloki_push_bind_address = \"127.0.0.1:0\"\noperations_transport = \"plaintext\"\napi_transport = \"plaintext\"\notlp_grpc_transport = \"plaintext\"\notlp_http_transport = \"plaintext\"\nloki_push_transport = \"plaintext\"\n[listener.api]\ncors_allowed_origins = [\"https://console.example\"]\n",
        roots.parent.join("cors-control.sock").display()
    );
    let inputs = ConfigurationInputs::try_new(
        Some(&document),
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?;
    Ok(resolve(inputs)?)
}

#[test]
fn api_cors_preflight_and_actual_responses_are_exact_origin_scoped()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("api-cors")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let effective = cors_configuration(&roots)?;
    let host = NativeHost::new(NativeBindings::from_effective(&effective)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly)
            .with_effective_configuration(std::sync::Arc::new(effective)),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;

    let preflight = http(
        api,
        "OPTIONS",
        positron_api::api_keys::HTTP_PATH,
        &[
            ("Origin", "https://console.example"),
            ("Access-Control-Request-Method", "POST"),
            (
                "Access-Control-Request-Headers",
                "Authorization, Content-Type",
            ),
        ],
        &[],
    )?;
    assert_status(preflight.clone(), 204);
    assert!(preflight.contains("access-control-allow-origin: https://console.example\r\n"));
    assert!(preflight.contains("access-control-allow-methods: POST\r\n"));
    assert!(preflight.contains("access-control-allow-headers: authorization, content-type\r\n"));
    assert!(preflight.contains(
        "vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers\r\n"
    ));
    assert!(
        !preflight
            .to_ascii_lowercase()
            .contains("access-control-allow-credentials")
    );

    let authentication_error = http(
        api,
        "POST",
        positron_api::api_keys::HTTP_PATH,
        &[("Origin", "https://console.example")],
        &[],
    )?;
    assert_status(authentication_error.clone(), 401);
    assert!(
        authentication_error.contains("access-control-allow-origin: https://console.example\r\n")
    );

    let authorization = format!("Bearer {}", claim.secret());
    let list = positron_api::api_keys::ApiKeyRequest::list().encode()?;
    let authenticated = http(
        api,
        "POST",
        positron_api::api_keys::HTTP_PATH,
        &[
            ("Origin", "https://console.example"),
            ("Authorization", &authorization),
            ("Content-Type", "application/json"),
        ],
        &list,
    )?;
    assert_status(authenticated.clone(), 200);
    assert!(authenticated.contains("access-control-allow-origin: https://console.example\r\n"));

    for (path, method, headers) in [
        (
            "/v1/unknown",
            "OPTIONS",
            vec![
                ("Origin", "https://console.example"),
                ("Access-Control-Request-Method", "POST"),
            ],
        ),
        (
            positron_api::api_keys::HTTP_PATH,
            "OPTIONS",
            vec![
                ("Origin", "https://console.example"),
                ("Access-Control-Request-Method", "DELETE"),
            ],
        ),
        (
            positron_api::api_keys::HTTP_PATH,
            "OPTIONS",
            vec![
                ("Origin", "https://console.example"),
                ("Access-Control-Request-Method", "POST"),
                ("Access-Control-Request-Headers", "X-Not-Supported"),
            ],
        ),
    ] {
        let response = http(api, method, path, &headers, &[])?;
        assert!(
            !response
                .to_ascii_lowercase()
                .contains("access-control-allow-origin")
        );
    }
    let disallowed = http(
        api,
        "POST",
        positron_api::api_keys::HTTP_PATH,
        &[("Origin", "https://other.example")],
        &[],
    )?;
    assert!(
        !disallowed
            .to_ascii_lowercase()
            .contains("access-control-allow-origin")
    );
    let duplicate_origin = http(
        api,
        "OPTIONS",
        positron_api::api_keys::HTTP_PATH,
        &[
            ("Origin", "https://console.example"),
            ("Origin", "https://console.example"),
            ("Access-Control-Request-Method", "POST"),
        ],
        &[],
    )?;
    assert!(
        !duplicate_origin
            .to_ascii_lowercase()
            .contains("access-control-allow-origin")
    );
    let duplicate_preflight_method = http(
        api,
        "OPTIONS",
        positron_api::api_keys::HTTP_PATH,
        &[
            ("Origin", "https://console.example"),
            ("Access-Control-Request-Method", "POST"),
            ("Access-Control-Request-Method", "POST"),
        ],
        &[],
    )?;
    assert!(
        !duplicate_preflight_method
            .to_ascii_lowercase()
            .contains("access-control-allow-origin"),
        "unexpected CORS permission for duplicate preflight method: {duplicate_preflight_method}"
    );

    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn api_cors_is_off_for_unconfigured_native_bindings() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("api-cors-off")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    drop(InstanceBootstrap::claim(&paths)?);
    let host = NativeHost::new(bindings(&roots, "api-cors-off")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let response = http(
        api,
        "OPTIONS",
        positron_api::api_keys::HTTP_PATH,
        &[
            ("Origin", "https://console.example"),
            ("Access-Control-Request-Method", "POST"),
        ],
        &[],
    )?;
    assert!(
        !response
            .to_ascii_lowercase()
            .contains("access-control-allow-origin")
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn api_cors_applies_the_same_policy_over_http2() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let roots = TestRoots::new("api-cors-http2")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let effective = cors_configuration(&roots)?;
    let host = NativeHost::new(NativeBindings::from_effective(&effective)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly)
            .with_effective_configuration(std::sync::Arc::new(effective)),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let (mut client, connection) = client::handshake(TcpStream::connect(api).await?).await?;
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let preflight = Request::builder()
        .method("OPTIONS")
        .uri(format!(
            "http://localhost{}",
            positron_api::api_keys::HTTP_PATH
        ))
        .header("origin", "https://console.example")
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "authorization, content-type",
        )
        .body(())?;
    let (response, _) = client.send_request(preflight, true)?;
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), response).await??;
    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://console.example")
    );
    assert!(
        response
            .headers()
            .get("access-control-allow-credentials")
            .is_none()
    );

    let actual = Request::builder()
        .method("POST")
        .uri(format!(
            "http://localhost{}",
            positron_api::api_keys::HTTP_PATH
        ))
        .header("origin", "https://console.example")
        .body(())?;
    let (response, _) = client.send_request(actual, true)?;
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), response).await??;
    assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://console.example")
    );
    let authorization = format!("Bearer {}", claim.secret());
    let list = positron_api::api_keys::ApiKeyRequest::list().encode()?;
    let actual = Request::builder()
        .method("POST")
        .uri(format!(
            "http://localhost{}",
            positron_api::api_keys::HTTP_PATH
        ))
        .header("origin", "https://console.example")
        .header("authorization", authorization)
        .header("content-type", "application/json")
        .body(())?;
    let (response, mut body) = client.send_request(actual, false)?;
    body.send_data(bytes::Bytes::from(list), true)?;
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), response).await??;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://console.example")
    );
    drop(client);
    connection.abort();
    let _ = connection.await;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}
