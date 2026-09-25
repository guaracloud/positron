//! Rust-owned canonical setting declarations.
//!
//! Keep each `define_settings!` declaration on one line so the canonical
//! setting table remains easy to review alongside its reference documentation.

use super::{
    MutabilityClass, ProvenancePolicy, SecrecyClass, Setting, SettingDefinition, SettingKind,
    ValueDomain,
};

macro_rules! define_settings {
    ($(
        $setting:ident | $path:literal | $kind:ident | $default:literal |
        $domain:ident ( $($domain_value:expr),+ ) |
        $secrecy:ident | $provenance:ident | $mutability:ident;
    )+) => {
        [
            $(
                SettingDefinition {
                    setting: Setting::$setting,
                    path: $path,
                    kind: SettingKind::$kind,
                    default_value: $default,
                    domain: ValueDomain::$domain($($domain_value),+),
                    secrecy: SecrecyClass::$secrecy,
                    provenance: ProvenancePolicy::$provenance,
                    mutability: MutabilityClass::$mutability,
                },
            )+
        ]
    };
}

pub(crate) const SETTING_DEFINITIONS: [SettingDefinition; 84] = define_settings! {
    SchemaVersion | "schema_version" | Integer | "1" | ExactUnsignedInteger(1) | Public | ConfigurationFileOnly | ImmutableAfterInitialization;
    DiagnosticsLogLevel | "diagnostics.log_level" | String | "info" | StringEnumeration(&["error", "warn", "info", "debug"]) | Public | NonSecretOverrides | LiveReloadable;
    RuntimeShutdownGraceSeconds | "runtime.shutdown_grace_seconds" | Integer | "30" | UnsignedIntegerRange(1, 3600) | Public | NonSecretOverrides | RestartRequired;
    RuntimeMaxRegisteredTenants | "runtime.max_registered_tenants" | Integer | "2" | UnsignedIntegerRange(1, 1024) | Public | NonSecretOverrides | RestartRequired;
    ListenerControlPath | "listener.control_path" | String | "/var/run/positron/control.sock" | AbsolutePath(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerOperationsBindAddress | "listener.operations_bind_address" | String | "127.0.0.1:13133" | SocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerOperationsTransport | "listener.operations_transport" | String | "tls" | StringEnumeration(&["tls", "mtls", "plaintext"]) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsAcceptedSocketLimit | "listener.operations_accepted_socket_limit" | Integer | "128" | UnsignedIntegerRange(1, 4096) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsPerAddressAcceptedSocketLimit | "listener.operations_per_address_accepted_socket_limit" | Integer | "16" | UnsignedIntegerRange(1, 4096) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsTlsHandshakeLimit | "listener.operations_tls_handshake_limit" | Integer | "16" | UnsignedIntegerRange(1, 128) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsTlsHandshakeDeadlineSeconds | "listener.operations_tls_handshake_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsHeaderDeadlineSeconds | "listener.operations_header_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsBodyDeadlineSeconds | "listener.operations_body_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsRequestDeadlineSeconds | "listener.operations_request_deadline_seconds" | Integer | "30" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsIdleDeadlineSeconds | "listener.operations_idle_deadline_seconds" | Integer | "30" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsTlsCertificateFile | "listener.operations_tls_certificate_file" | String | "/var/lib/positron-secrets/operations-certificate.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerOperationsTlsPrivateKeyFile | "listener.operations_tls_private_key_file" | String | "/var/lib/positron-secrets/operations-private-key.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerOperationsTlsClientCaFile | "listener.operations_tls_client_ca_file" | String | "/var/lib/positron-secrets/operations-client-ca.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerOperationsTrustedProxyCidrs | "listener.operations.trusted_proxy_cidrs" | TrustedProxyCidrs | "disabled" | TrustedProxyCidrs(16, 64) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsForwardedHops | "listener.operations.forwarded_hops" | Integer | "0" | UnsignedIntegerRange(0, 255) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiBindAddress | "listener.api_bind_address" | String | "127.0.0.1:8080" | SocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerApiTransport | "listener.api_transport" | String | "tls" | StringEnumeration(&["tls", "mtls", "plaintext"]) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiAcceptedSocketLimit | "listener.api_accepted_socket_limit" | Integer | "128" | UnsignedIntegerRange(1, 4096) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiPerAddressAcceptedSocketLimit | "listener.api_per_address_accepted_socket_limit" | Integer | "16" | UnsignedIntegerRange(1, 4096) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiTlsHandshakeLimit | "listener.api_tls_handshake_limit" | Integer | "16" | UnsignedIntegerRange(1, 128) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiTlsHandshakeDeadlineSeconds | "listener.api_tls_handshake_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiHeaderDeadlineSeconds | "listener.api_header_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiBodyDeadlineSeconds | "listener.api_body_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiRequestDeadlineSeconds | "listener.api_request_deadline_seconds" | Integer | "30" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiIdleDeadlineSeconds | "listener.api_idle_deadline_seconds" | Integer | "30" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiTrustedProxyCidrs | "listener.api.trusted_proxy_cidrs" | TrustedProxyCidrs | "disabled" | TrustedProxyCidrs(16, 64) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiForwardedHops | "listener.api.forwarded_hops" | Integer | "0" | UnsignedIntegerRange(0, 255) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiTlsCertificateFile | "listener.api_tls_certificate_file" | String | "/var/lib/positron-secrets/api-certificate.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerApiTlsPrivateKeyFile | "listener.api_tls_private_key_file" | String | "/var/lib/positron-secrets/api-private-key.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerApiTlsClientCaFile | "listener.api_tls_client_ca_file" | String | "/var/lib/positron-secrets/api-client-ca.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcBindAddress | "listener.otlp_grpc_bind_address" | String | "127.0.0.1:4317" | SocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerOtlpGrpcTransport | "listener.otlp_grpc_transport" | String | "tls" | StringEnumeration(&["tls", "mtls", "plaintext"]) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcAcceptedSocketLimit | "listener.otlp_grpc_accepted_socket_limit" | Integer | "128" | UnsignedIntegerRange(1, 4096) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcPerAddressAcceptedSocketLimit | "listener.otlp_grpc_per_address_accepted_socket_limit" | Integer | "16" | UnsignedIntegerRange(1, 4096) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcTlsHandshakeLimit | "listener.otlp_grpc_tls_handshake_limit" | Integer | "16" | UnsignedIntegerRange(1, 128) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcTlsHandshakeDeadlineSeconds | "listener.otlp_grpc_tls_handshake_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcHeaderDeadlineSeconds | "listener.otlp_grpc_header_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcBodyDeadlineSeconds | "listener.otlp_grpc_body_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcRequestDeadlineSeconds | "listener.otlp_grpc_request_deadline_seconds" | Integer | "30" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcIdleDeadlineSeconds | "listener.otlp_grpc_idle_deadline_seconds" | Integer | "30" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcTlsCertificateFile | "listener.otlp_grpc_tls_certificate_file" | String | "/var/lib/positron-secrets/otlp-grpc-certificate.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcTlsPrivateKeyFile | "listener.otlp_grpc_tls_private_key_file" | String | "/var/lib/positron-secrets/otlp-grpc-private-key.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcTlsClientCaFile | "listener.otlp_grpc_tls_client_ca_file" | String | "/var/lib/positron-secrets/otlp-grpc-client-ca.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcTrustedProxyCidrs | "listener.otlp_grpc.trusted_proxy_cidrs" | TrustedProxyCidrs | "disabled" | TrustedProxyCidrs(16, 64) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcForwardedHops | "listener.otlp_grpc.forwarded_hops" | Integer | "0" | UnsignedIntegerRange(0, 255) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpBindAddress | "listener.otlp_http_bind_address" | String | "127.0.0.1:4318" | SocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerOtlpHttpTransport | "listener.otlp_http_transport" | String | "tls" | StringEnumeration(&["tls", "mtls", "plaintext"]) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpAcceptedSocketLimit | "listener.otlp_http_accepted_socket_limit" | Integer | "128" | UnsignedIntegerRange(1, 4096) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpPerAddressAcceptedSocketLimit | "listener.otlp_http_per_address_accepted_socket_limit" | Integer | "16" | UnsignedIntegerRange(1, 4096) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpTlsHandshakeLimit | "listener.otlp_http_tls_handshake_limit" | Integer | "16" | UnsignedIntegerRange(1, 128) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpTlsHandshakeDeadlineSeconds | "listener.otlp_http_tls_handshake_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpHeaderDeadlineSeconds | "listener.otlp_http_header_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpBodyDeadlineSeconds | "listener.otlp_http_body_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpRequestDeadlineSeconds | "listener.otlp_http_request_deadline_seconds" | Integer | "30" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpIdleDeadlineSeconds | "listener.otlp_http_idle_deadline_seconds" | Integer | "30" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpTlsCertificateFile | "listener.otlp_http_tls_certificate_file" | String | "/var/lib/positron-secrets/otlp-http-certificate.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpTlsPrivateKeyFile | "listener.otlp_http_tls_private_key_file" | String | "/var/lib/positron-secrets/otlp-http-private-key.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpTlsClientCaFile | "listener.otlp_http_tls_client_ca_file" | String | "/var/lib/positron-secrets/otlp-http-client-ca.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpTrustedProxyCidrs | "listener.otlp_http.trusted_proxy_cidrs" | TrustedProxyCidrs | "disabled" | TrustedProxyCidrs(16, 64) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpForwardedHops | "listener.otlp_http.forwarded_hops" | Integer | "0" | UnsignedIntegerRange(0, 255) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushBindAddress | "listener.loki_push_bind_address" | String | "127.0.0.1:3100" | SocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerLokiPushTransport | "listener.loki_push_transport" | String | "tls" | StringEnumeration(&["tls", "mtls", "plaintext"]) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushAcceptedSocketLimit | "listener.loki_push_accepted_socket_limit" | Integer | "128" | UnsignedIntegerRange(1, 4096) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushPerAddressAcceptedSocketLimit | "listener.loki_push_per_address_accepted_socket_limit" | Integer | "16" | UnsignedIntegerRange(1, 4096) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushTlsHandshakeLimit | "listener.loki_push_tls_handshake_limit" | Integer | "16" | UnsignedIntegerRange(1, 128) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushTlsHandshakeDeadlineSeconds | "listener.loki_push_tls_handshake_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushHeaderDeadlineSeconds | "listener.loki_push_header_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushBodyDeadlineSeconds | "listener.loki_push_body_deadline_seconds" | Integer | "2" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushRequestDeadlineSeconds | "listener.loki_push_request_deadline_seconds" | Integer | "30" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushIdleDeadlineSeconds | "listener.loki_push_idle_deadline_seconds" | Integer | "30" | UnsignedIntegerRange(1, 300) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushTlsCertificateFile | "listener.loki_push_tls_certificate_file" | String | "/var/lib/positron-secrets/loki-push-certificate.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushTlsPrivateKeyFile | "listener.loki_push_tls_private_key_file" | String | "/var/lib/positron-secrets/loki-push-private-key.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushTlsClientCaFile | "listener.loki_push_tls_client_ca_file" | String | "/var/lib/positron-secrets/loki-push-client-ca.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushTrustedProxyCidrs | "listener.loki_push.trusted_proxy_cidrs" | TrustedProxyCidrs | "disabled" | TrustedProxyCidrs(16, 64) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushForwardedHops | "listener.loki_push.forwarded_hops" | Integer | "0" | UnsignedIntegerRange(0, 255) | Public | ConfigurationFileOnly | DrainAndReload;
    StorageDataDirectory | "storage.data_directory" | String | "/var/lib/positron" | AbsolutePath(256) | Public | ConfigurationFileOnly | ImmutableAfterInitialization;
    StorageSecretsDirectory | "storage.secrets_directory" | String | "/var/lib/positron-secrets" | AbsolutePath(256) | Public | ConfigurationFileOnly | ImmutableAfterInitialization;
    SecurityLocalKeyFile | "security.local_key_file" | String | "/var/lib/positron-secrets/local-root-key.v1" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | ImmutableAfterInitialization;
    ExportDestinations | "export.destination" | ExportDestinations | "disabled" | ExportDestinations(8, 63, 8) | Public | ConfigurationFileOnly | ImmutableAfterInitialization;
};
