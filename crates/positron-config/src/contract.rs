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

pub(crate) const SETTING_DEFINITIONS: [SettingDefinition; 10] = define_settings! {
    SchemaVersion | "schema_version" | Integer | "1" | ExactUnsignedInteger(1) | Public | ConfigurationFileOnly | ImmutableAfterInitialization;
    DiagnosticsLogLevel | "diagnostics.log_level" | String | "info" | StringEnumeration(&["error", "warn", "info", "debug"]) | Public | NonSecretOverrides | LiveReloadable;
    RuntimeShutdownGraceSeconds | "runtime.shutdown_grace_seconds" | Integer | "30" | UnsignedIntegerRange(1, 3600) | Public | NonSecretOverrides | RestartRequired;
    ListenerControlPath | "listener.control_path" | String | "/var/run/positron/control.sock" | AbsolutePath(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerOperationsBindAddress | "listener.operations_bind_address" | String | "127.0.0.1:13133" | LoopbackSocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerApiBindAddress | "listener.api_bind_address" | String | "127.0.0.1:8080" | LoopbackSocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    ListenerOtlpHttpBindAddress | "listener.otlp_http_bind_address" | String | "127.0.0.1:4318" | LoopbackSocketAddress(256) | Public | NonSecretOverrides | DrainAndReload;
    StorageDataDirectory | "storage.data_directory" | String | "/var/lib/positron" | AbsolutePath(256) | Public | ConfigurationFileOnly | ImmutableAfterInitialization;
    StorageSecretsDirectory | "storage.secrets_directory" | String | "/var/lib/positron-secrets" | AbsolutePath(256) | Public | ConfigurationFileOnly | ImmutableAfterInitialization;
    SecurityLocalKeyFile | "security.local_key_file" | String | "/var/lib/positron-secrets/local-root-key.v1" | ProtectedAbsolutePath(256) | SecretBearing | ProtectedConfigurationFileOnly | ImmutableAfterInitialization;
};
