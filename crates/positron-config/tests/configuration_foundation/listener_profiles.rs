#[test]
fn canonical_listener_profiles_keep_role_owned_mtls_identity_and_trust()
-> Result<(), Box<dyn Error>> {
    use positron_config::{NetworkListenerRole, NetworkTransport};

    let effective = inputs(
        Some(
            "schema_version = 1\n\
             [listener]\n\
             operations_transport = \"mtls\"\n\
             operations_tls_certificate_file = \"/secrets/operations-cert.pem\"\n\
             operations_tls_private_key_file = \"/secrets/operations-key.pem\"\n\
             operations_tls_client_ca_file = \"/secrets/operations-ca.pem\"\n\
             api_transport = \"mtls\"\n\
             api_tls_certificate_file = \"/secrets/api-cert.pem\"\n\
             api_tls_private_key_file = \"/secrets/api-key.pem\"\n\
             api_tls_client_ca_file = \"/secrets/api-ca.pem\"\n\
             otlp_grpc_transport = \"mtls\"\n\
             otlp_grpc_tls_certificate_file = \"/secrets/grpc-cert.pem\"\n\
             otlp_grpc_tls_private_key_file = \"/secrets/grpc-key.pem\"\n\
             otlp_grpc_tls_client_ca_file = \"/secrets/grpc-ca.pem\"\n\
             otlp_http_transport = \"mtls\"\n\
             otlp_http_tls_certificate_file = \"/secrets/http-cert.pem\"\n\
             otlp_http_tls_private_key_file = \"/secrets/http-key.pem\"\n\
             otlp_http_tls_client_ca_file = \"/secrets/http-ca.pem\"\n\
             loki_push_transport = \"mtls\"\n\
             loki_push_tls_certificate_file = \"/secrets/loki-cert.pem\"\n\
             loki_push_tls_private_key_file = \"/secrets/loki-key.pem\"\n\
             loki_push_tls_client_ca_file = \"/secrets/loki-ca.pem\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;

    for (role, certificate, private_key, client_ca) in [
        (
            NetworkListenerRole::Operations,
            "/secrets/operations-cert.pem",
            "/secrets/operations-key.pem",
            "/secrets/operations-ca.pem",
        ),
        (
            NetworkListenerRole::Api,
            "/secrets/api-cert.pem",
            "/secrets/api-key.pem",
            "/secrets/api-ca.pem",
        ),
        (
            NetworkListenerRole::OtlpGrpc,
            "/secrets/grpc-cert.pem",
            "/secrets/grpc-key.pem",
            "/secrets/grpc-ca.pem",
        ),
        (
            NetworkListenerRole::OtlpHttp,
            "/secrets/http-cert.pem",
            "/secrets/http-key.pem",
            "/secrets/http-ca.pem",
        ),
        (
            NetworkListenerRole::LokiPush,
            "/secrets/loki-cert.pem",
            "/secrets/loki-key.pem",
            "/secrets/loki-ca.pem",
        ),
    ] {
        let profile = effective
            .network_listener_profile(role)
            .ok_or("network listener profile missing")?;
        assert_eq!(profile.transport(), NetworkTransport::MutualTls);
        assert_eq!(profile.tls_certificate_file().as_path().to_str(), Some(certificate));
        assert_eq!(profile.tls_private_key_file().as_path().to_str(), Some(private_key));
        assert_eq!(
            profile
                .tls_client_ca_file()
                .and_then(|reference| reference.as_path().to_str()),
            Some(client_ca)
        );
    }
    Ok(())
}

#[test]
fn network_listener_profile_resolves_role_owned_accepted_socket_limits()
-> Result<(), Box<dyn Error>> {
    use positron_config::NetworkListenerRole;

    let effective = inputs(
        Some(
            "schema_version = 1\n\
             [listener]\n\
             otlp_grpc_accepted_socket_limit = 48\n\
             otlp_grpc_per_address_accepted_socket_limit = 6\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;

    let grpc = effective
        .network_listener_profile(NetworkListenerRole::OtlpGrpc)
        .ok_or("OTLP gRPC listener profile missing")?
        .connection_admission();
    assert_eq!(grpc.global_accepted_socket_limit().get(), 48);
    assert_eq!(grpc.per_address_accepted_socket_limit().get(), 6);

    let api = effective
        .network_listener_profile(NetworkListenerRole::Api)
        .ok_or("API listener profile missing")?
        .connection_admission();
    assert_eq!(api.global_accepted_socket_limit().get(), 128);
    assert_eq!(api.per_address_accepted_socket_limit().get(), 16);
    Ok(())
}
