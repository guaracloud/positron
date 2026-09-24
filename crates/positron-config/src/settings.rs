use super::contract;

/// A source supplied to the Configuration Contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingSource {
    /// A compiled default selected no external input.
    CompiledDefault,
    /// The selected canonical TOML document.
    ConfigurationFile,
    /// A non-secret `POSITRON__SECTION__FIELD` override.
    Environment,
    /// A non-secret explicit command-line override.
    CommandLine,
}

impl SettingSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompiledDefault => "compiled_default",
            Self::ConfigurationFile => "configuration_file",
            Self::Environment => "environment",
            Self::CommandLine => "command_line",
        }
    }
}

/// Whether a setting is visible in diagnostics and generated references.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecrecyClass {
    /// The setting can be rendered as an ordinary configuration value.
    Public,
    /// The setting can only be rendered as a redaction marker.
    SecretBearing,
}

impl SecrecyClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::SecretBearing => "secret_bearing",
        }
    }
}

/// The only lifecycle treatment a setting may request after validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutabilityClass {
    /// The setting may be atomically published without Drain.
    LiveReloadable,
    /// The setting requires bounded Drain before publication.
    DrainAndReload,
    /// The setting remains pending until an explicit restart.
    RestartRequired,
    /// The setting requires an explicit migration or restore workflow.
    ImmutableAfterInitialization,
}

impl MutabilityClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LiveReloadable => "live_reloadable",
            Self::DrainAndReload => "drain_and_reload",
            Self::RestartRequired => "restart_required",
            Self::ImmutableAfterInitialization => "immutable_after_initialization",
        }
    }
}

/// The TOML scalar shape owned by one setting definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingKind {
    /// A canonical unsigned integer.
    Integer,
    /// A TOML string.
    String,
    /// A bounded list of named durable-export destination scopes.
    ExportDestinations,
}

impl SettingKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Integer => "integer",
            Self::String => "string",
            Self::ExportDestinations => "export_destinations",
        }
    }
}

/// The closed value domain owned by one setting definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueDomain {
    /// One exact unsigned integer.
    ExactUnsignedInteger(u16),
    /// One of the listed stable string values.
    StringEnumeration(&'static [&'static str]),
    /// An inclusive unsigned-integer range.
    UnsignedIntegerRange(u16, u16),
    /// A socket address with a byte ceiling whose IP must be loopback.
    LoopbackSocketAddress(usize),
    /// A socket address whose transport policy decides whether public binding is safe.
    SocketAddress(usize),
    /// An absolute normalized path with a byte ceiling.
    AbsolutePath(usize),
    /// A secret-bearing absolute normalized path with a byte ceiling.
    ProtectedAbsolutePath(usize),
    /// Bounded named durable-export destination definitions.
    ExportDestinations(usize, usize, usize),
}

/// The exact source policy declared for one setting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvenancePolicy {
    /// Compiled defaults and the canonical configuration file only.
    ConfigurationFileOnly,
    /// Compiled defaults, file, environment, and command-line sources.
    NonSecretOverrides,
    /// Compiled defaults and file references; literal secret overrides are forbidden.
    ProtectedConfigurationFileOnly,
}

impl ProvenancePolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfigurationFileOnly => "configuration_file_only",
            Self::NonSecretOverrides => "non_secret_overrides",
            Self::ProtectedConfigurationFileOnly => "protected_configuration_file_only",
        }
    }

    pub(crate) const fn allows(self, source: SettingSource) -> bool {
        match self {
            Self::ConfigurationFileOnly | Self::ProtectedConfigurationFileOnly => {
                matches!(
                    source,
                    SettingSource::CompiledDefault | SettingSource::ConfigurationFile
                )
            },
            Self::NonSecretOverrides => true,
        }
    }
}

/// Read-only metadata for one canonical Configuration Contract setting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingDefinition {
    pub(crate) setting: Setting,
    pub(crate) path: &'static str,
    pub(crate) kind: SettingKind,
    pub(crate) default_value: &'static str,
    pub(crate) domain: ValueDomain,
    pub(crate) secrecy: SecrecyClass,
    pub(crate) provenance: ProvenancePolicy,
    pub(crate) mutability: MutabilityClass,
}

impl SettingDefinition {
    #[must_use]
    pub const fn setting(self) -> Setting {
        self.setting
    }

    #[must_use]
    pub const fn path(self) -> &'static str {
        self.path
    }

    #[must_use]
    pub const fn kind(self) -> SettingKind {
        self.kind
    }

    #[must_use]
    pub const fn default_value(self) -> &'static str {
        self.default_value
    }

    #[must_use]
    pub const fn domain(self) -> ValueDomain {
        self.domain
    }

    #[must_use]
    pub const fn secrecy(self) -> SecrecyClass {
        self.secrecy
    }

    #[must_use]
    pub const fn provenance(self) -> ProvenancePolicy {
        self.provenance
    }

    #[must_use]
    pub const fn mutability(self) -> MutabilityClass {
        self.mutability
    }
}

/// Canonical settings owned by the Configuration Contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Setting {
    SchemaVersion,
    DiagnosticsLogLevel,
    RuntimeShutdownGraceSeconds,
    RuntimeMaxRegisteredTenants,
    ListenerControlPath,
    ListenerOperationsBindAddress,
    ListenerApiBindAddress,
    ListenerApiTransport,
    ListenerApiTlsCertificateFile,
    ListenerApiTlsPrivateKeyFile,
    ListenerOtlpGrpcBindAddress,
    ListenerOtlpHttpBindAddress,
    ListenerLokiPushBindAddress,
    StorageDataDirectory,
    StorageSecretsDirectory,
    SecurityLocalKeyFile,
    ExportDestinations,
}

impl Setting {
    #[must_use]
    pub const fn path(self) -> &'static str {
        setting_definition(self).path()
    }

    #[must_use]
    pub const fn secrecy(self) -> SecrecyClass {
        setting_definition(self).secrecy()
    }

    #[must_use]
    pub const fn mutability(self) -> MutabilityClass {
        setting_definition(self).mutability()
    }

    /// Drift in these settings can change instance identity, encryption,
    /// storage ownership, or the owner-only control plane and must fence the
    /// instance rather than be reconciled automatically.
    #[must_use]
    pub const fn requires_drift_fence(self) -> bool {
        matches!(
            self,
            Self::SchemaVersion
                | Self::ListenerControlPath
                | Self::ListenerApiTransport
                | Self::ListenerApiTlsCertificateFile
                | Self::ListenerApiTlsPrivateKeyFile
                | Self::StorageDataDirectory
                | Self::StorageSecretsDirectory
                | Self::SecurityLocalKeyFile
                | Self::ExportDestinations
        )
    }
}

/// Returns the Rust-owned canonical definition for one setting.
#[must_use]
pub const fn setting_definition(setting: Setting) -> SettingDefinition {
    let [
        schema_version,
        diagnostics_log_level,
        runtime_shutdown_grace_seconds,
        runtime_max_registered_tenants,
        listener_control_path,
        listener_operations_bind_address,
        listener_api_bind_address,
        listener_api_transport,
        listener_api_tls_certificate_file,
        listener_api_tls_private_key_file,
        listener_otlp_grpc_bind_address,
        listener_otlp_http_bind_address,
        listener_loki_push_bind_address,
        storage_data_directory,
        storage_secrets_directory,
        security_local_key_file,
        export_destinations,
    ] = contract::SETTING_DEFINITIONS;
    match setting {
        Setting::SchemaVersion => schema_version,
        Setting::DiagnosticsLogLevel => diagnostics_log_level,
        Setting::RuntimeShutdownGraceSeconds => runtime_shutdown_grace_seconds,
        Setting::RuntimeMaxRegisteredTenants => runtime_max_registered_tenants,
        Setting::ListenerControlPath => listener_control_path,
        Setting::ListenerOperationsBindAddress => listener_operations_bind_address,
        Setting::ListenerApiBindAddress => listener_api_bind_address,
        Setting::ListenerApiTransport => listener_api_transport,
        Setting::ListenerApiTlsCertificateFile => listener_api_tls_certificate_file,
        Setting::ListenerApiTlsPrivateKeyFile => listener_api_tls_private_key_file,
        Setting::ListenerOtlpGrpcBindAddress => listener_otlp_grpc_bind_address,
        Setting::ListenerOtlpHttpBindAddress => listener_otlp_http_bind_address,
        Setting::ListenerLokiPushBindAddress => listener_loki_push_bind_address,
        Setting::StorageDataDirectory => storage_data_directory,
        Setting::StorageSecretsDirectory => storage_secrets_directory,
        Setting::SecurityLocalKeyFile => security_local_key_file,
        Setting::ExportDestinations => export_destinations,
    }
}
