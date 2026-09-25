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

#[test]
fn network_listener_profile_resolves_role_owned_connection_protection()
-> Result<(), Box<dyn Error>> {
    use positron_config::NetworkListenerRole;

    let effective = inputs(
        Some(
            "schema_version = 1\n\
             [listener]\n\
             api_tls_handshake_limit = 8\n\
             api_tls_handshake_deadline_seconds = 3\n\
             api_header_deadline_seconds = 4\n\
             api_body_deadline_seconds = 5\n\
             api_request_deadline_seconds = 6\n\
             api_idle_deadline_seconds = 7\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;

    let api = effective
        .network_listener_profile(NetworkListenerRole::Api)
        .ok_or("API listener profile missing")?
        .connection_protection();
    assert_eq!(api.tls_handshake_limit().get(), 8);
    assert_eq!(api.tls_handshake_deadline().as_secs(), 3);
    assert_eq!(api.header_deadline().as_secs(), 4);
    assert_eq!(api.body_deadline().as_secs(), 5);
    assert_eq!(api.request_deadline().as_secs(), 6);
    assert_eq!(api.idle_deadline().as_secs(), 7);

    let operations = effective
        .network_listener_profile(NetworkListenerRole::Operations)
        .ok_or("Operations listener profile missing")?
        .connection_protection();
    assert_eq!(operations.tls_handshake_limit().get(), 16);
    assert_eq!(operations.tls_handshake_deadline().as_secs(), 2);
    assert_eq!(operations.header_deadline().as_secs(), 2);
    assert_eq!(operations.body_deadline().as_secs(), 2);
    assert_eq!(operations.request_deadline().as_secs(), 30);
    assert_eq!(operations.idle_deadline().as_secs(), 30);
    Ok(())
}

#[test]
fn http2_listener_profiles_resolve_only_their_role_owned_bounds()
-> Result<(), Box<dyn Error>> {
    use positron_config::NetworkListenerRole;

    let effective = inputs(
        Some(
            "schema_version = 1\n\
             [listener]\n\
             api_http2_max_concurrent_streams = 3\n\
             api_http2_initial_stream_window_bytes = 65536\n\
             api_http2_initial_connection_window_bytes = 65537\n\
             api_http2_max_frame_bytes = 32768\n\
             api_http2_max_header_list_bytes = 16384\n\
             api_http2_minimum_ping_interval_seconds = 4\n\
             otlp_grpc_http2_max_concurrent_streams = 5\n\
             otlp_grpc_http2_initial_stream_window_bytes = 65538\n\
             otlp_grpc_http2_initial_connection_window_bytes = 65539\n\
             otlp_grpc_http2_max_frame_bytes = 49152\n\
             otlp_grpc_http2_max_header_list_bytes = 32768\n\
             otlp_grpc_http2_minimum_ping_interval_seconds = 6\n\
             otlp_grpc_max_message_bytes = 1048576\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;

    let api = effective
        .network_listener_profile(NetworkListenerRole::Api)
        .ok_or("API listener profile missing")?
        .http2_profile()
        .ok_or("API HTTP/2 profile missing")?;
    assert_eq!(api.max_concurrent_streams().get(), 3);
    assert_eq!(api.initial_stream_window_bytes().get(), 65_536);
    assert_eq!(api.initial_connection_window_bytes().get(), 65_537);
    assert_eq!(api.max_frame_bytes().get(), 32_768);
    assert_eq!(api.max_header_list_bytes().get(), 16_384);
    assert_eq!(api.minimum_ping_interval().as_secs(), 4);
    assert_eq!(api.max_grpc_message_bytes(), None);

    let grpc = effective
        .network_listener_profile(NetworkListenerRole::OtlpGrpc)
        .ok_or("OTLP gRPC listener profile missing")?
        .http2_profile()
        .ok_or("OTLP gRPC HTTP/2 profile missing")?;
    assert_eq!(grpc.max_concurrent_streams().get(), 5);
    assert_eq!(grpc.initial_stream_window_bytes().get(), 65_538);
    assert_eq!(grpc.initial_connection_window_bytes().get(), 65_539);
    assert_eq!(grpc.max_frame_bytes().get(), 49_152);
    assert_eq!(grpc.max_header_list_bytes().get(), 32_768);
    assert_eq!(grpc.minimum_ping_interval().as_secs(), 6);
    assert_eq!(grpc.max_grpc_message_bytes().map(NonZeroU32::get), Some(1_048_576));

    assert!(effective
        .network_listener_profile(NetworkListenerRole::Operations)
        .ok_or("Operations listener profile missing")?
        .http2_profile()
        .is_none());
    Ok(())
}
use std::num::NonZeroU32;
