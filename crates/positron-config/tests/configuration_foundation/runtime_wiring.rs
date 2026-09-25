#[test]
fn runtime_endpoints_and_key_path_are_explicit_typed_configuration() {
    let effective = inputs(
        Some(
            "schema_version = 1\n\
             [listener]\n\
             control_path = \"/tmp/positron-explicit.sock\"\n\
             operations_bind_address = \"127.0.0.1:19101\"\n\
             api_bind_address = \"127.0.0.1:19102\"\n\
             otlp_grpc_bind_address = \"127.0.0.1:19103\"\n\
             otlp_http_bind_address = \"127.0.0.1:19104\"\n\
             [storage]\n\
             data_directory = \"/srv/positron\"\n\
             secrets_directory = \"/srv/positron-secrets\"\n\
             [security]\n\
             local_key_file = \"/srv/positron-secrets/local-root-key.v1\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)
    .expect("explicit runtime wiring resolves");

    assert_eq!(effective.control_path(), "/tmp/positron-explicit.sock");
    assert_eq!(
        effective.operations_bind_address().to_string(),
        "127.0.0.1:19101"
    );
    assert_eq!(effective.api_bind_address().to_string(), "127.0.0.1:19102");
    assert_eq!(
        effective.otlp_grpc_bind_address().to_string(),
        "127.0.0.1:19103"
    );
    assert_eq!(
        effective.otlp_http_bind_address().to_string(),
        "127.0.0.1:19104"
    );
    assert_eq!(
        effective.local_key_file().as_path().to_str(),
        Some("/srv/positron-secrets/local-root-key.v1")
    );
}

#[test]
fn runtime_registered_tenant_capacity_is_explicit_typed_configuration() {
    let effective = inputs(
        Some(
            "schema_version = 1\n\
             [runtime]\n\
             max_registered_tenants = 3\n",
        ),
        [],
        [],
    )
    .and_then(resolve)
    .expect("registered tenant capacity resolves");

    assert_eq!(effective.max_registered_tenants(), 3);
    assert_eq!(
        effective.source_for("runtime.max_registered_tenants"),
        Some(SettingSource::ConfigurationFile)
    );
    assert!(
        effective
            .redacted_reference()
            .contains("max_registered_tenants = 3")
    );
}

#[test]
fn api_transport_profile_allows_explicit_public_tls_and_plaintext() {
    let tls = inputs(
        Some(
            "schema_version = 1\n[listener]\napi_bind_address = \"192.0.2.1:8443\"\napi_transport = \"tls\"\napi_tls_certificate_file = \"/secrets/cert.pem\"\napi_tls_private_key_file = \"/secrets/key.pem\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)
    .expect("public TLS profile resolves");
    assert_eq!(tls.api_bind_address().to_string(), "192.0.2.1:8443");
    assert_eq!(tls.api_transport(), positron_config::ApiTransport::Tls);
    assert!(tls.security_warnings().is_empty());
    assert_eq!(
        tls.api_tls_certificate_file().as_path().to_str(),
        Some("/secrets/cert.pem")
    );

    let plaintext = inputs(
        Some("schema_version = 1\n[listener]\napi_bind_address = \"192.0.2.1:8080\"\napi_transport = \"plaintext\"\n"),
        [],
        [],
    )
    .and_then(resolve)
    .expect("explicit public plaintext profile resolves");
    assert_eq!(
        plaintext.api_transport(),
        positron_config::ApiTransport::PlaintextOptOut
    );
    assert_eq!(
        plaintext.security_warnings(),
        [positron_config::ConfigurationWarning::PublicPlaintextApi]
    );
    assert_eq!(
        plaintext
            .public_plaintext_api_configuration()
            .expect("configuration-file plaintext opt-out")
            .api_bind_address()
            .to_string(),
        "192.0.2.1:8080"
    );
    assert!(
        plaintext
            .redacted_reference()
            .contains("public API transport is plaintext")
    );
    let unused_server_trust = inputs(
        Some("schema_version = 1\n[listener]\napi_tls_trust_file = \"/secrets/ca.pem\"\n"),
        [],
        [],
    )
    .and_then(resolve);
    assert!(
        unused_server_trust.is_err(),
        "server configuration must not accept an unused trust file"
    );
}

#[test]
fn api_cors_allowed_origins_is_an_explicit_file_only_drain_and_reload_setting() {
    let definition = setting_definition(Setting::ListenerApiCorsAllowedOrigins);
    assert_eq!(definition.path(), "listener.api.cors_allowed_origins");
    assert_eq!(definition.default_value(), "[]");
    assert_eq!(definition.provenance(), ProvenancePolicy::ConfigurationFileOnly);
    assert_eq!(definition.mutability(), MutabilityClass::DrainAndReload);
}

#[test]
fn api_cors_allowed_origins_accept_only_bounded_exact_web_origins() {
    let effective = inputs(
        Some(
            "schema_version = 1\n[listener.api]\ncors_allowed_origins = [\"https://console.example\", \"http://[2001:db8::1]:8080\"]\n",
        ),
        [],
        [],
    )
    .and_then(resolve)
    .expect("exact configured origins resolve");
    let profile = effective
        .network_listener_profile(positron_config::NetworkListenerRole::Api)
        .expect("API profile");
    assert_eq!(
        profile
            .cors_allowed_origins()
            .expect("API CORS setting")
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["https://console.example", "http://[2001:db8::1]:8080"]
    );

    for invalid in [
        "*",
        "null",
        "https://user@example.test",
        "https://example.test/path",
        "https://example.test?query",
        "https://example.test#fragment",
        "https://example.test\\r\\nInjected: value",
        "https://[2001:0db8::1]",
        "https://example.test:080",
    ] {
        let document = format!(
            "schema_version = 1\n[listener.api]\ncors_allowed_origins = [\"{invalid}\"]\n"
        );
        assert!(
            inputs(Some(&document), [], []).and_then(resolve).is_err(),
            "must reject {invalid:?}"
        );
    }
    assert!(inputs(
        Some("schema_version = 1\n[listener.api]\ncors_allowed_origins = [\"https://console.example\", \"https://console.example\"]\n"),
        [],
        [],
    )
    .and_then(resolve)
    .is_err());
}

#[test]
fn complete_listener_profiles_keep_public_plaintext_an_explicit_visible_role_choice() {
    let effective = inputs(
        Some(
            "schema_version = 1\n[listener]\n\
             otlp_grpc_bind_address = \"192.0.2.9:4317\"\n\
             otlp_grpc_transport = \"plaintext\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)
    .expect("an explicit per-role plaintext opt-out resolves");

    let profile = effective
        .network_listener_profile(positron_config::NetworkListenerRole::OtlpGrpc)
        .expect("OTLP gRPC profile");
    assert_eq!(profile.bind_address().to_string(), "192.0.2.9:4317");
    assert_eq!(profile.transport(), positron_config::NetworkTransport::PlaintextOptOut);
    assert!(effective.security_warnings().contains(
        &positron_config::ConfigurationWarning::PublicPlaintextListener(
            positron_config::NetworkListenerRole::OtlpGrpc
        )
    ));
    assert!(effective
        .redacted_reference()
        .contains("OTLP gRPC transport is plaintext"));
}

fn assert_document_rejection<T>(
    result: Result<T, ConfigurationFailure>,
    code: ConfigurationFailureCode,
) {
    assert!(matches!(
        result,
        Err(error)
            if error.code() == code
                && error.source() == FailureSource::ConfigurationDocument
                && error.retry_class() == RetryClass::AfterInputCorrection
                && error.completion_state() == CompletionState::Rejected
    ));
}

fn inputs(
    file: Option<&str>,
    environment_pairs: impl IntoIterator<Item = (&'static str, &'static str)>,
    command_line_pairs: impl IntoIterator<Item = (&'static str, &'static str)>,
) -> Result<ConfigurationInputs, ConfigurationFailure> {
    let environment = EnvironmentOverrides::try_from_pairs(environment_pairs)?;
    let command_line = CommandLineOverrides::try_from_pairs(command_line_pairs)?;
    ConfigurationInputs::try_new(file, environment, command_line)
}
