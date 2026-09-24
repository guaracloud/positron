use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::Path;

use super::{Setting, ValueDomain, setting_definition, validate_path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiTransport {
    Tls,
    MutualTls,
    PlaintextOptOut,
}

/// Transport selected explicitly for one network listener role.
///
/// Plaintext is never a fallback: its setting is configuration-file-only and
/// is surfaced by the resolved configuration as a durable warning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkTransport {
    Tls,
    MutualTls,
    PlaintextOptOut,
}

impl NetworkTransport {
    pub(crate) fn parse(value: &str, source: FailureSource) -> Result<Self, ConfigurationFailure> {
        match value {
            "tls" => Ok(Self::Tls),
            "mtls" => Ok(Self::MutualTls),
            "plaintext" => Ok(Self::PlaintextOptOut),
            _ => Err(ConfigurationFailure::unsupported_value(source)),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::MutualTls => "mtls",
            Self::PlaintextOptOut => "plaintext",
        }
    }
}

/// The closed network-facing listener roles configured by the contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkListenerRole {
    Operations,
    Api,
    OtlpGrpc,
    OtlpHttp,
    LokiPush,
}

impl NetworkListenerRole {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Operations => "operations",
            Self::Api => "API",
            Self::OtlpGrpc => "OTLP gRPC",
            Self::OtlpHttp => "OTLP HTTP",
            Self::LokiPush => "Loki push",
        }
    }
}

impl ApiTransport {
    pub(crate) fn parse(value: &str) -> Result<Self, ConfigurationFailure> {
        match value {
            "tls" => Ok(Self::Tls),
            "mtls" => Ok(Self::MutualTls),
            "plaintext" => Ok(Self::PlaintextOptOut),
            _ => Err(ConfigurationFailure::unsupported_value(
                FailureSource::ListenerApiTransport,
            )),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::MutualTls => "mtls",
            Self::PlaintextOptOut => "plaintext",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    pub(crate) fn parse(value: &str) -> Result<Self, ConfigurationFailure> {
        let ValueDomain::StringEnumeration(allowed) =
            setting_definition(Setting::DiagnosticsLogLevel).domain()
        else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::Malformed,
                FailureSource::DiagnosticsLogLevel,
            ));
        };
        if !allowed.contains(&value) {
            return Err(ConfigurationFailure::unsupported_value(
                FailureSource::DiagnosticsLogLevel,
            ));
        }
        match value {
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            _ => Err(ConfigurationFailure::unsupported_value(
                FailureSource::DiagnosticsLogLevel,
            )),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedFileReference {
    pub(crate) path: String,
}

impl ProtectedFileReference {
    pub(crate) fn parse(value: &str, setting: Setting) -> Result<Self, ConfigurationFailure> {
        validate_path(value, setting)?;
        Ok(Self {
            path: value.to_owned(),
        })
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.path)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationFailureCode {
    Malformed,
    MissingSchemaVersion,
    UnknownSetting,
    UnsupportedValue,
    UnsafeCombination,
    ConflictingSetting,
    SecretOverrideNotAllowed,
    ResourceLimit,
    ImmutableSettingChanged,
}

impl ConfigurationFailureCode {
    /// Stable machine-readable classification for an operator finding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::MissingSchemaVersion => "missing_schema_version",
            Self::UnknownSetting => "unknown_setting",
            Self::UnsupportedValue => "unsupported_value",
            Self::UnsafeCombination => "unsafe_combination",
            Self::ConflictingSetting => "conflicting_setting",
            Self::SecretOverrideNotAllowed => "secret_override_not_allowed",
            Self::ResourceLimit => "resource_limit",
            Self::ImmutableSettingChanged => "immutable_setting_changed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClass {
    Never,
    AfterInputCorrection,
}

impl RetryClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::AfterInputCorrection => "after_input_correction",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionState {
    Rejected,
}

impl CompletionState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureSource {
    ConfigurationDocument,
    EnvironmentOverride,
    CommandLineOverride,
    SchemaVersion,
    DiagnosticsLogLevel,
    RuntimeShutdownGraceSeconds,
    RuntimeMaxRegisteredTenants,
    ListenerControlPath,
    ListenerOperationsBindAddress,
    ListenerOperationsTransport,
    ListenerOperationsAcceptedSocketLimit,
    ListenerOperationsPerAddressAcceptedSocketLimit,
    ListenerOperationsTlsCertificateFile,
    ListenerOperationsTlsPrivateKeyFile,
    ListenerOperationsTlsClientCaFile,
    ListenerOperationsTrustedProxyCidrs,
    ListenerOperationsForwardedHops,
    ListenerApiBindAddress,
    ListenerApiTransport,
    ListenerApiAcceptedSocketLimit,
    ListenerApiPerAddressAcceptedSocketLimit,
    ListenerApiTrustedProxyCidrs,
    ListenerApiForwardedHops,
    ListenerApiTlsCertificateFile,
    ListenerApiTlsPrivateKeyFile,
    ListenerApiTlsClientCaFile,
    ListenerOtlpGrpcBindAddress,
    ListenerOtlpGrpcTransport,
    ListenerOtlpGrpcAcceptedSocketLimit,
    ListenerOtlpGrpcPerAddressAcceptedSocketLimit,
    ListenerOtlpGrpcTlsCertificateFile,
    ListenerOtlpGrpcTlsPrivateKeyFile,
    ListenerOtlpGrpcTlsClientCaFile,
    ListenerOtlpGrpcTrustedProxyCidrs,
    ListenerOtlpGrpcForwardedHops,
    ListenerOtlpHttpBindAddress,
    ListenerOtlpHttpTransport,
    ListenerOtlpHttpAcceptedSocketLimit,
    ListenerOtlpHttpPerAddressAcceptedSocketLimit,
    ListenerOtlpHttpTlsCertificateFile,
    ListenerOtlpHttpTlsPrivateKeyFile,
    ListenerOtlpHttpTlsClientCaFile,
    ListenerOtlpHttpTrustedProxyCidrs,
    ListenerOtlpHttpForwardedHops,
    ListenerLokiPushBindAddress,
    ListenerLokiPushTransport,
    ListenerLokiPushAcceptedSocketLimit,
    ListenerLokiPushPerAddressAcceptedSocketLimit,
    ListenerLokiPushTlsCertificateFile,
    ListenerLokiPushTlsPrivateKeyFile,
    ListenerLokiPushTlsClientCaFile,
    ListenerLokiPushTrustedProxyCidrs,
    ListenerLokiPushForwardedHops,
    StorageDataDirectory,
    StorageSecretsDirectory,
    SecurityLocalKeyFile,
    ExportDestinations,
}

impl FailureSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfigurationDocument => "configuration_document",
            Self::EnvironmentOverride => "environment_override",
            Self::CommandLineOverride => "command_line_override",
            Self::SchemaVersion => "schema_version",
            Self::DiagnosticsLogLevel => "diagnostics.log_level",
            Self::RuntimeShutdownGraceSeconds => "runtime.shutdown_grace_seconds",
            Self::RuntimeMaxRegisteredTenants => "runtime.max_registered_tenants",
            Self::ListenerControlPath => "listener.control_path",
            Self::ListenerOperationsBindAddress => "listener.operations_bind_address",
            Self::ListenerOperationsTransport => "listener.operations_transport",
            Self::ListenerOperationsAcceptedSocketLimit => {
                "listener.operations_accepted_socket_limit"
            },
            Self::ListenerOperationsPerAddressAcceptedSocketLimit => {
                "listener.operations_per_address_accepted_socket_limit"
            },
            Self::ListenerOperationsTlsCertificateFile => {
                "listener.operations_tls_certificate_file"
            },
            Self::ListenerOperationsTlsPrivateKeyFile => "listener.operations_tls_private_key_file",
            Self::ListenerOperationsTlsClientCaFile => "listener.operations_tls_client_ca_file",
            Self::ListenerOperationsTrustedProxyCidrs => "listener.operations.trusted_proxy_cidrs",
            Self::ListenerOperationsForwardedHops => "listener.operations.forwarded_hops",
            Self::ListenerApiBindAddress => "listener.api_bind_address",
            Self::ListenerApiTransport => "listener.api_transport",
            Self::ListenerApiAcceptedSocketLimit => "listener.api_accepted_socket_limit",
            Self::ListenerApiPerAddressAcceptedSocketLimit => {
                "listener.api_per_address_accepted_socket_limit"
            },
            Self::ListenerApiTrustedProxyCidrs => "listener.api.trusted_proxy_cidrs",
            Self::ListenerApiForwardedHops => "listener.api.forwarded_hops",
            Self::ListenerApiTlsCertificateFile => "listener.api_tls_certificate_file",
            Self::ListenerApiTlsPrivateKeyFile => "listener.api_tls_private_key_file",
            Self::ListenerApiTlsClientCaFile => "listener.api_tls_client_ca_file",
            Self::ListenerOtlpGrpcBindAddress => "listener.otlp_grpc_bind_address",
            Self::ListenerOtlpGrpcTransport => "listener.otlp_grpc_transport",
            Self::ListenerOtlpGrpcAcceptedSocketLimit => "listener.otlp_grpc_accepted_socket_limit",
            Self::ListenerOtlpGrpcPerAddressAcceptedSocketLimit => {
                "listener.otlp_grpc_per_address_accepted_socket_limit"
            },
            Self::ListenerOtlpGrpcTlsCertificateFile => "listener.otlp_grpc_tls_certificate_file",
            Self::ListenerOtlpGrpcTlsPrivateKeyFile => "listener.otlp_grpc_tls_private_key_file",
            Self::ListenerOtlpGrpcTlsClientCaFile => "listener.otlp_grpc_tls_client_ca_file",
            Self::ListenerOtlpGrpcTrustedProxyCidrs => "listener.otlp_grpc.trusted_proxy_cidrs",
            Self::ListenerOtlpGrpcForwardedHops => "listener.otlp_grpc.forwarded_hops",
            Self::ListenerOtlpHttpBindAddress => "listener.otlp_http_bind_address",
            Self::ListenerOtlpHttpTransport => "listener.otlp_http_transport",
            Self::ListenerOtlpHttpAcceptedSocketLimit => "listener.otlp_http_accepted_socket_limit",
            Self::ListenerOtlpHttpPerAddressAcceptedSocketLimit => {
                "listener.otlp_http_per_address_accepted_socket_limit"
            },
            Self::ListenerOtlpHttpTlsCertificateFile => "listener.otlp_http_tls_certificate_file",
            Self::ListenerOtlpHttpTlsPrivateKeyFile => "listener.otlp_http_tls_private_key_file",
            Self::ListenerOtlpHttpTlsClientCaFile => "listener.otlp_http_tls_client_ca_file",
            Self::ListenerOtlpHttpTrustedProxyCidrs => "listener.otlp_http.trusted_proxy_cidrs",
            Self::ListenerOtlpHttpForwardedHops => "listener.otlp_http.forwarded_hops",
            Self::ListenerLokiPushBindAddress => "listener.loki_push_bind_address",
            Self::ListenerLokiPushTransport => "listener.loki_push_transport",
            Self::ListenerLokiPushAcceptedSocketLimit => "listener.loki_push_accepted_socket_limit",
            Self::ListenerLokiPushPerAddressAcceptedSocketLimit => {
                "listener.loki_push_per_address_accepted_socket_limit"
            },
            Self::ListenerLokiPushTlsCertificateFile => "listener.loki_push_tls_certificate_file",
            Self::ListenerLokiPushTlsPrivateKeyFile => "listener.loki_push_tls_private_key_file",
            Self::ListenerLokiPushTlsClientCaFile => "listener.loki_push_tls_client_ca_file",
            Self::ListenerLokiPushTrustedProxyCidrs => "listener.loki_push.trusted_proxy_cidrs",
            Self::ListenerLokiPushForwardedHops => "listener.loki_push.forwarded_hops",
            Self::StorageDataDirectory => "storage.data_directory",
            Self::StorageSecretsDirectory => "storage.secrets_directory",
            Self::SecurityLocalKeyFile => "security.local_key_file",
            Self::ExportDestinations => "export.destination",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationFailure {
    code: ConfigurationFailureCode,
    retry_class: RetryClass,
    completion_state: CompletionState,
    source: FailureSource,
}

impl ConfigurationFailure {
    pub(crate) const fn new(code: ConfigurationFailureCode, source: FailureSource) -> Self {
        Self {
            code,
            retry_class: RetryClass::AfterInputCorrection,
            completion_state: CompletionState::Rejected,
            source,
        }
    }

    pub(crate) const fn unsupported_value(source: FailureSource) -> Self {
        Self::new(ConfigurationFailureCode::UnsupportedValue, source)
    }

    #[must_use]
    pub const fn code(self) -> ConfigurationFailureCode {
        self.code
    }

    #[must_use]
    pub const fn retry_class(self) -> RetryClass {
        self.retry_class
    }

    #[must_use]
    pub const fn completion_state(self) -> CompletionState {
        self.completion_state
    }

    #[must_use]
    pub const fn source(self) -> FailureSource {
        self.source
    }
}

impl Display for ConfigurationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.code {
            ConfigurationFailureCode::Malformed => "malformed canonical configuration",
            ConfigurationFailureCode::MissingSchemaVersion => {
                "configuration schema version is required"
            },
            ConfigurationFailureCode::UnknownSetting => "unknown configuration setting",
            ConfigurationFailureCode::UnsupportedValue => "unsupported configuration value",
            ConfigurationFailureCode::UnsafeCombination => "unsafe configuration combination",
            ConfigurationFailureCode::ConflictingSetting => "conflicting configuration setting",
            ConfigurationFailureCode::SecretOverrideNotAllowed => {
                "secret configuration override is not allowed"
            },
            ConfigurationFailureCode::ResourceLimit => "configuration resource limit exceeded",
            ConfigurationFailureCode::ImmutableSettingChanged => {
                "immutable initialized configuration changed"
            },
        })
    }
}

impl Error for ConfigurationFailure {}
