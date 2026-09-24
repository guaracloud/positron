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

pub(crate) const SETTING_DEFINITIONS: [SettingDefinition; 32] = define_settings! {
    SchemaVersion | "schema_version" | Integer | "1" | ExactUnsignedInteger(1) | Public | ConfigurationFileOnly | ImmutableAfterInitialization;
    DiagnosticsLogLevel | "diagnostics.log_level" | String | "info" | StringEnumeration(&["error", "warn", "info", "debug"]) | Public | NonSecretOverrides | LiveReloadable;
    RuntimeShutdownGraceSeconds | "runtime.shutdown_grace_seconds" | Integer | "30" | UnsignedIntegerRange(1, 3600) | Public | NonSecretOverrides | RestartRequired;
    RuntimeMaxRegisteredTenants | "runtime.max_registered_tenants" | Integer | "2" | UnsignedIntegerRange(1, 1024) | Public | NonSecretOverrides | RestartRequired;
    ListenerControlPath | "listener.control_path" | String | "/var/run/positron/control.sock" | AbsolutePath(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerOperationsBindAddress | "listener.operations_bind_address" | String | "127.0.0.1:13133" | SocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerOperationsTransport | "listener.operations_transport" | String | "tls" | StringEnumeration(&["tls", "mtls", "plaintext"]) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsTrustedProxyCidrs | "listener.operations.trusted_proxy_cidrs" | TrustedProxyCidrs | "disabled" | TrustedProxyCidrs(16, 64) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOperationsForwardedHops | "listener.operations.forwarded_hops" | Integer | "0" | UnsignedIntegerRange(0, 255) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiBindAddress | "listener.api_bind_address" | String | "127.0.0.1:8080" | SocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerApiTransport | "listener.api_transport" | String | "tls" | StringEnumeration(&["tls", "plaintext"]) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiTrustedProxyCidrs | "listener.api.trusted_proxy_cidrs" | TrustedProxyCidrs | "disabled" | TrustedProxyCidrs(16, 64) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiForwardedHops | "listener.api.forwarded_hops" | Integer | "0" | UnsignedIntegerRange(0, 255) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerApiTlsCertificateFile | "listener.api_tls_certificate_file" | String | "/var/lib/positron-secrets/api-certificate.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerApiTlsPrivateKeyFile | "listener.api_tls_private_key_file" | String | "/var/lib/positron-secrets/api-private-key.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerTlsClientCaFile | "listener.tls_client_ca_file" | String | "/var/lib/positron-secrets/client-ca.pem" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcBindAddress | "listener.otlp_grpc_bind_address" | String | "127.0.0.1:4317" | SocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerOtlpGrpcTransport | "listener.otlp_grpc_transport" | String | "tls" | StringEnumeration(&["tls", "mtls", "plaintext"]) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcTrustedProxyCidrs | "listener.otlp_grpc.trusted_proxy_cidrs" | TrustedProxyCidrs | "disabled" | TrustedProxyCidrs(16, 64) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpGrpcForwardedHops | "listener.otlp_grpc.forwarded_hops" | Integer | "0" | UnsignedIntegerRange(0, 255) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpBindAddress | "listener.otlp_http_bind_address" | String | "127.0.0.1:4318" | SocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerOtlpHttpTransport | "listener.otlp_http_transport" | String | "tls" | StringEnumeration(&["tls", "mtls", "plaintext"]) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpTrustedProxyCidrs | "listener.otlp_http.trusted_proxy_cidrs" | TrustedProxyCidrs | "disabled" | TrustedProxyCidrs(16, 64) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerOtlpHttpForwardedHops | "listener.otlp_http.forwarded_hops" | Integer | "0" | UnsignedIntegerRange(0, 255) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushBindAddress | "listener.loki_push_bind_address" | String | "127.0.0.1:3100" | SocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerLokiPushTransport | "listener.loki_push_transport" | String | "tls" | StringEnumeration(&["tls", "mtls", "plaintext"]) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushTrustedProxyCidrs | "listener.loki_push.trusted_proxy_cidrs" | TrustedProxyCidrs | "disabled" | TrustedProxyCidrs(16, 64) | Public | ConfigurationFileOnly | DrainAndReload;
    ListenerLokiPushForwardedHops | "listener.loki_push.forwarded_hops" | Integer | "0" | UnsignedIntegerRange(0, 255) | Public | ConfigurationFileOnly | DrainAndReload;
    StorageDataDirectory | "storage.data_directory" | String | "/var/lib/positron" | AbsolutePath(256) | Public | ConfigurationFileOnly | ImmutableAfterInitialization;
    StorageSecretsDirectory | "storage.secrets_directory" | String | "/var/lib/positron-secrets" | AbsolutePath(256) | Public | ConfigurationFileOnly | ImmutableAfterInitialization;
    SecurityLocalKeyFile | "security.local_key_file" | String | "/var/lib/positron-secrets/local-root-key.v1" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | ImmutableAfterInitialization;
    ExportDestinations | "export.destination" | ExportDestinations | "disabled" | ExportDestinations(8, 63, 8) | Public | ConfigurationFileOnly | ImmutableAfterInitialization;
};
