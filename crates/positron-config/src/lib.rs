//! Canonical, bounded Configuration Contract resolution for Positron.
//!
//! This M0 boundary resolves compiled defaults, one canonical TOML document,
//! environment overrides, and command-line overrides into checked native
//! values. It owns source provenance, secrecy, validation, mutability, and
//! deterministic schema/reference generation. Runtime publication and live
//! reload remain M4-owned work.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::net::SocketAddr;

const MAX_CONFIGURATION_BYTES: usize = 16 * 1024;
const MAX_OVERRIDE_PAIRS: usize = 16;
const MAX_TOML_ENTRIES: usize = 16;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 256;

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

/// Whether a setting is visible in diagnostics and generated references.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecrecyClass {
    /// The setting can be rendered as an ordinary configuration value.
    Public,
    /// The setting can only be rendered as a redaction marker.
    SecretBearing,
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

/// The TOML scalar shape owned by one setting definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingKind {
    /// A canonical unsigned integer.
    Integer,
    /// A TOML string.
    String,
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
    /// An absolute normalized path with a byte ceiling.
    AbsolutePath(usize),
    /// A secret-bearing absolute normalized path with a byte ceiling.
    ProtectedAbsolutePath(usize),
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
    const fn allows(self, source: SettingSource) -> bool {
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
    setting: Setting,
    path: &'static str,
    kind: SettingKind,
    default_value: &'static str,
    domain: ValueDomain,
    secrecy: SecrecyClass,
    provenance: ProvenancePolicy,
    mutability: MutabilityClass,
}

impl SettingDefinition {
    /// Returns the setting represented by this definition.
    #[must_use]
    pub const fn setting(self) -> Setting {
        self.setting
    }

    /// Returns the stable dotted path.
    #[must_use]
    pub const fn path(self) -> &'static str {
        self.path
    }

    /// Returns the canonical TOML scalar kind.
    #[must_use]
    pub const fn kind(self) -> SettingKind {
        self.kind
    }

    /// Returns the compiled default before secrecy-aware rendering.
    #[must_use]
    pub const fn default_value(self) -> &'static str {
        self.default_value
    }

    /// Returns the complete closed validation domain.
    #[must_use]
    pub const fn domain(self) -> ValueDomain {
        self.domain
    }

    /// Returns the diagnostic secrecy class.
    #[must_use]
    pub const fn secrecy(self) -> SecrecyClass {
        self.secrecy
    }

    /// Returns the exact allowed source policy.
    #[must_use]
    pub const fn provenance(self) -> ProvenancePolicy {
        self.provenance
    }

    /// Returns the lifecycle mutability class.
    #[must_use]
    pub const fn mutability(self) -> MutabilityClass {
        self.mutability
    }
}

/// Canonical settings owned by the M0 Configuration Contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Setting {
    /// The version of the canonical configuration document.
    SchemaVersion,
    /// The safe structured diagnostic verbosity.
    DiagnosticsLogLevel,
    /// The bounded lifecycle Drain deadline.
    RuntimeShutdownGraceSeconds,
    /// The control-listener address, which needs Drain before replacement.
    ListenerControlBindAddress,
    /// The initialized durable data root.
    StorageDataDirectory,
    /// The initialized protected-secrets root.
    StorageSecretsDirectory,
    /// The protected local-root-key reference.
    SecurityLocalKeyFile,
}

impl Setting {
    /// Returns the stable dotted path used by canonical TOML and overrides.
    #[must_use]
    pub const fn path(self) -> &'static str {
        setting_definition(self).path()
    }

    /// Returns the setting's one declared secrecy class.
    #[must_use]
    pub const fn secrecy(self) -> SecrecyClass {
        setting_definition(self).secrecy()
    }

    /// Returns the setting's one declared mutability class.
    #[must_use]
    pub const fn mutability(self) -> MutabilityClass {
        setting_definition(self).mutability()
    }
}

mod contract;

/// Returns the Rust-owned canonical definition for one setting.
#[must_use]
pub const fn setting_definition(setting: Setting) -> SettingDefinition {
    let [
        schema_version,
        diagnostics_log_level,
        runtime_shutdown_grace_seconds,
        listener_control_bind_address,
        storage_data_directory,
        storage_secrets_directory,
        security_local_key_file,
    ] = contract::SETTING_DEFINITIONS;
    match setting {
        Setting::SchemaVersion => schema_version,
        Setting::DiagnosticsLogLevel => diagnostics_log_level,
        Setting::RuntimeShutdownGraceSeconds => runtime_shutdown_grace_seconds,
        Setting::ListenerControlBindAddress => listener_control_bind_address,
        Setting::StorageDataDirectory => storage_data_directory,
        Setting::StorageSecretsDirectory => storage_secrets_directory,
        Setting::SecurityLocalKeyFile => security_local_key_file,
    }
}

/// The bounded diagnostic verbosity accepted by the contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    /// Error diagnostics only.
    Error,
    /// Warning and error diagnostics.
    Warn,
    /// Informational diagnostics.
    Info,
    /// Debug diagnostics, still secret-safe.
    Debug,
}

impl LogLevel {
    fn parse(value: &str) -> Result<Self, ConfigurationFailure> {
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

    const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

/// A protected-file reference that never reveals itself through formatting.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedFileReference {
    path: String,
}

impl ProtectedFileReference {
    fn parse(value: &str) -> Result<Self, ConfigurationFailure> {
        validate_path(value, Setting::SecurityLocalKeyFile)?;
        Ok(Self {
            path: value.to_owned(),
        })
    }
}

/// A closed stable class for a rejected configuration operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationFailureCode {
    /// The bounded source cannot be parsed as the canonical subset of TOML.
    Malformed,
    /// A supplied configuration document omits its required schema version.
    MissingSchemaVersion,
    /// A supplied key is not part of the canonical Configuration Contract.
    UnknownSetting,
    /// A setting has a valid shape but an unsupported value.
    UnsupportedValue,
    /// A value violates an invariant between otherwise known settings.
    UnsafeCombination,
    /// One source declares a setting more than once.
    ConflictingSetting,
    /// A secret-bearing setting attempted an environment or CLI override.
    SecretOverrideNotAllowed,
    /// An input exceeds a declared byte, pair, or path bound.
    ResourceLimit,
    /// A plan tries to modify initialized immutable configuration.
    ImmutableSettingChanged,
}

/// The retry classification for a configuration outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClass {
    /// The same input cannot succeed through retry.
    Never,
    /// The caller must submit corrected configuration.
    AfterInputCorrection,
}

/// Completion truth for a rejected configuration operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionState {
    /// Rejection happened before a candidate became effective.
    Rejected,
}

/// A safe semantic source for a configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureSource {
    /// The complete bounded input document.
    ConfigurationDocument,
    /// A non-secret environment override.
    EnvironmentOverride,
    /// A non-secret command-line override.
    CommandLineOverride,
    /// The configuration schema version.
    SchemaVersion,
    /// The diagnostic-level setting.
    DiagnosticsLogLevel,
    /// The bounded Drain deadline.
    RuntimeShutdownGraceSeconds,
    /// The control-listener address.
    ListenerControlBindAddress,
    /// The durable data root.
    StorageDataDirectory,
    /// The protected-secrets root.
    StorageSecretsDirectory,
    /// The secret-bearing local key reference.
    SecurityLocalKeyFile,
}

/// A secret-safe closed failure from the Configuration Contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationFailure {
    code: ConfigurationFailureCode,
    retry_class: RetryClass,
    completion_state: CompletionState,
    source: FailureSource,
}

impl ConfigurationFailure {
    const fn new(code: ConfigurationFailureCode, source: FailureSource) -> Self {
        Self {
            code,
            retry_class: RetryClass::AfterInputCorrection,
            completion_state: CompletionState::Rejected,
            source,
        }
    }

    const fn unsupported_value(source: FailureSource) -> Self {
        Self::new(ConfigurationFailureCode::UnsupportedValue, source)
    }

    /// Returns the stable caller-control-flow failure code.
    #[must_use]
    pub const fn code(self) -> ConfigurationFailureCode {
        self.code
    }

    /// Returns retry behavior without exposing the rejected value.
    #[must_use]
    pub const fn retry_class(self) -> RetryClass {
        self.retry_class
    }

    /// Returns the truthful completion state.
    #[must_use]
    pub const fn completion_state(self) -> CompletionState {
        self.completion_state
    }

    /// Returns the bounded semantic failure source.
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

/// Bounded non-secret environment overrides.
#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentOverrides {
    pairs: Vec<(String, String)>,
}

impl EnvironmentOverrides {
    /// Collects bounded override pairs without reading ambient process state.
    pub fn try_from_pairs<K, V>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Self, ConfigurationFailure>
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        collect_pairs(pairs, FailureSource::EnvironmentOverride).map(|pairs| Self { pairs })
    }
}

impl Debug for EnvironmentOverrides {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvironmentOverrides")
            .field("pairs", &"<redacted>")
            .field("pair_count", &self.pairs.len())
            .finish()
    }
}

/// Bounded non-secret explicit command-line overrides.
#[derive(Clone, Eq, PartialEq)]
pub struct CommandLineOverrides {
    pairs: Vec<(String, String)>,
}

impl CommandLineOverrides {
    /// Collects bounded override pairs without reading ambient process state.
    pub fn try_from_pairs<K, V>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Self, ConfigurationFailure>
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        collect_pairs(pairs, FailureSource::CommandLineOverride).map(|pairs| Self { pairs })
    }
}

impl Debug for CommandLineOverrides {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandLineOverrides")
            .field("pairs", &"<redacted>")
            .field("pair_count", &self.pairs.len())
            .finish()
    }
}

/// All bounded source inputs required to resolve one candidate.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfigurationInputs {
    file: Option<String>,
    environment: EnvironmentOverrides,
    command_line: CommandLineOverrides,
}

impl Debug for ConfigurationInputs {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigurationInputs")
            .field("file", &self.file.as_ref().map(|_| "<redacted>"))
            .field("environment", &self.environment)
            .field("command_line", &self.command_line)
            .finish()
    }
}

impl ConfigurationInputs {
    /// Captures a selected canonical TOML document and explicit override maps.
    pub fn try_new(
        file: Option<&str>,
        environment: EnvironmentOverrides,
        command_line: CommandLineOverrides,
    ) -> Result<Self, ConfigurationFailure> {
        let file = match file {
            Some(value) => {
                if value.len() > MAX_CONFIGURATION_BYTES {
                    return Err(ConfigurationFailure::new(
                        ConfigurationFailureCode::ResourceLimit,
                        FailureSource::ConfigurationDocument,
                    ));
                }
                Some(value.to_owned())
            },
            None => None,
        };
        Ok(Self {
            file,
            environment,
            command_line,
        })
    }
}

/// One fully checked native Effective Configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct EffectiveConfiguration {
    schema_version: u16,
    log_level: LogLevel,
    shutdown_grace_seconds: u16,
    control_bind_address: SocketAddr,
    data_directory: String,
    secrets_directory: String,
    local_key_file: ProtectedFileReference,
    sources: [SettingSource; 7],
}

impl EffectiveConfiguration {
    /// Returns the checked schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the checked secret-safe diagnostic level.
    #[must_use]
    pub const fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// Returns the bounded configured graceful-shutdown deadline.
    #[must_use]
    pub const fn shutdown_grace_seconds(&self) -> u16 {
        self.shutdown_grace_seconds
    }

    /// Returns the checked listener address that remains loopback-only in M0.
    #[must_use]
    pub const fn control_bind_address(&self) -> SocketAddr {
        self.control_bind_address
    }

    /// Returns the typed protected local-key reference without diagnostic formatting.
    #[must_use]
    pub fn local_key_file(&self) -> &ProtectedFileReference {
        &self.local_key_file
    }

    /// Returns source provenance for one stable dotted setting path.
    #[must_use]
    pub fn source_for(&self, path: &str) -> Option<SettingSource> {
        setting_for_path(path).and_then(|setting| self.sources.get(setting_index(setting)).copied())
    }

    /// Renders a bounded complete reference with secret-bearing values redacted.
    #[must_use]
    pub fn redacted_reference(&self) -> String {
        let mut rendered = String::with_capacity(512);
        rendered.push_str("schema_version = ");
        rendered.push_str(&self.schema_version.to_string());
        rendered.push_str("\n\n[diagnostics]\nlog_level = \"");
        rendered.push_str(self.log_level.as_str());
        rendered.push_str("\"\n\n[runtime]\nshutdown_grace_seconds = ");
        rendered.push_str(&self.shutdown_grace_seconds.to_string());
        rendered.push_str("\n\n[listener]\ncontrol_bind_address = \"");
        rendered.push_str(&self.control_bind_address.to_string());
        rendered.push_str("\"\n\n[storage]\ndata_directory = \"");
        rendered.push_str(&self.data_directory);
        rendered.push_str("\"\nsecrets_directory = \"");
        rendered.push_str(&self.secrets_directory);
        rendered.push_str("\"\n\n[security]\nlocal_key_file = \"<redacted>\"\n");
        rendered
    }

    /// Compares two checked candidates without publishing either one.
    pub fn plan_update(&self, candidate: &Self) -> Result<ConfigurationPlan, ConfigurationFailure> {
        let mut changes = Vec::with_capacity(7);
        for definition in contract::SETTING_DEFINITIONS {
            let setting = definition.setting();
            if self.setting_differs(candidate, setting) {
                if setting.mutability() == MutabilityClass::ImmutableAfterInitialization {
                    return Err(ConfigurationFailure::new(
                        ConfigurationFailureCode::ImmutableSettingChanged,
                        failure_source(setting),
                    ));
                }
                changes.push(setting);
            }
        }
        Ok(ConfigurationPlan::from_changes(changes))
    }

    fn setting_differs(&self, other: &Self, setting: Setting) -> bool {
        match setting {
            Setting::SchemaVersion => self.schema_version != other.schema_version,
            Setting::DiagnosticsLogLevel => self.log_level != other.log_level,
            Setting::RuntimeShutdownGraceSeconds => {
                self.shutdown_grace_seconds != other.shutdown_grace_seconds
            },
            Setting::ListenerControlBindAddress => {
                self.control_bind_address != other.control_bind_address
            },
            Setting::StorageDataDirectory => self.data_directory != other.data_directory,
            Setting::StorageSecretsDirectory => self.secrets_directory != other.secrets_directory,
            Setting::SecurityLocalKeyFile => self.local_key_file != other.local_key_file,
        }
    }
}

impl Debug for EffectiveConfiguration {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectiveConfiguration")
            .field("schema_version", &self.schema_version)
            .field("log_level", &self.log_level)
            .field("shutdown_grace_seconds", &self.shutdown_grace_seconds)
            .field("control_bind_address", &self.control_bind_address)
            .field("data_directory", &self.data_directory)
            .field("secrets_directory", &self.secrets_directory)
            .field("local_key_file", &"<redacted>")
            .field("sources", &self.sources)
            .finish()
    }
}

/// The non-publishing action that a future M4 owner may execute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigurationPlan {
    /// The candidate is exactly the current Effective Configuration.
    NoChange,
    /// Only live-reloadable settings changed.
    PublishLive {
        /// The exact canonical settings whose candidate values differ.
        changed: Vec<Setting>,
    },
    /// At least one setting requires bounded Drain before publication.
    DrainThenPublish {
        /// The exact canonical settings whose candidate values differ.
        changed: Vec<Setting>,
    },
    /// At least one setting remains pending until restart.
    RestartRequired {
        /// The exact canonical settings whose candidate values differ.
        changed: Vec<Setting>,
    },
}

impl ConfigurationPlan {
    fn from_changes(changed: Vec<Setting>) -> Self {
        if changed.is_empty() {
            return Self::NoChange;
        }
        if changed
            .iter()
            .any(|setting| setting.mutability() == MutabilityClass::RestartRequired)
        {
            return Self::RestartRequired { changed };
        }
        if changed
            .iter()
            .any(|setting| setting.mutability() == MutabilityClass::DrainAndReload)
        {
            return Self::DrainThenPublish { changed };
        }
        Self::PublishLive { changed }
    }
}

/// Resolves every source into one checked, redacted typed candidate.
pub fn resolve(
    inputs: ConfigurationInputs,
) -> Result<EffectiveConfiguration, ConfigurationFailure> {
    let mut candidate = Candidate::defaults()?;
    if let Some(file) = inputs.file.as_deref() {
        apply_toml(&mut candidate, file)?;
    }
    apply_environment(&mut candidate, &inputs.environment)?;
    apply_command_line(&mut candidate, &inputs.command_line)?;
    candidate.validate()
}

/// Returns the generated canonical JSON Schema.
#[must_use]
pub fn generated_json_schema() -> String {
    include_str!("../../../configuration/schema.json").to_owned()
}

/// Returns the generated operator/reference documentation without secrets.
#[must_use]
pub fn generated_reference() -> String {
    include_str!("../../../configuration/reference.md").to_owned()
}

#[derive(Clone)]
struct Candidate {
    schema_version: u16,
    log_level: LogLevel,
    shutdown_grace_seconds: u16,
    control_bind_address: SocketAddr,
    data_directory: String,
    secrets_directory: String,
    local_key_file: ProtectedFileReference,
    sources: [SettingSource; 7],
}

impl Candidate {
    fn defaults() -> Result<Self, ConfigurationFailure> {
        let schema_version = setting_definition(Setting::SchemaVersion).default_value();
        let log_level = setting_definition(Setting::DiagnosticsLogLevel).default_value();
        let shutdown = setting_definition(Setting::RuntimeShutdownGraceSeconds).default_value();
        let listener = setting_definition(Setting::ListenerControlBindAddress).default_value();
        let data = setting_definition(Setting::StorageDataDirectory).default_value();
        let secrets = setting_definition(Setting::StorageSecretsDirectory).default_value();
        let local_key = setting_definition(Setting::SecurityLocalKeyFile).default_value();
        Ok(Self {
            schema_version: parse_schema_version(schema_version)?,
            log_level: LogLevel::parse(log_level)?,
            shutdown_grace_seconds: parse_shutdown_grace_seconds(shutdown)?,
            control_bind_address: parse_loopback_address(listener)?,
            data_directory: checked_path(data, Setting::StorageDataDirectory)?,
            secrets_directory: checked_path(secrets, Setting::StorageSecretsDirectory)?,
            local_key_file: ProtectedFileReference::parse(local_key)?,
            sources: [SettingSource::CompiledDefault; 7],
        })
    }

    fn apply(
        &mut self,
        setting: Setting,
        value: &str,
        source: SettingSource,
    ) -> Result<(), ConfigurationFailure> {
        let definition = setting_definition(setting);
        if !definition.provenance().allows(source) {
            let code = if definition.secrecy() == SecrecyClass::SecretBearing {
                ConfigurationFailureCode::SecretOverrideNotAllowed
            } else {
                ConfigurationFailureCode::UnknownSetting
            };
            return Err(ConfigurationFailure::new(code, failure_source(setting)));
        }
        match setting {
            Setting::SchemaVersion => {
                self.schema_version = parse_schema_version(value)?;
            },
            Setting::DiagnosticsLogLevel => self.log_level = LogLevel::parse(value)?,
            Setting::RuntimeShutdownGraceSeconds => {
                self.shutdown_grace_seconds = parse_shutdown_grace_seconds(value)?;
            },
            Setting::ListenerControlBindAddress => {
                self.control_bind_address = parse_loopback_address(value)?;
            },
            Setting::StorageDataDirectory => {
                self.data_directory = checked_path(value, setting)?;
            },
            Setting::StorageSecretsDirectory => {
                self.secrets_directory = checked_path(value, setting)?;
            },
            Setting::SecurityLocalKeyFile => {
                self.local_key_file = ProtectedFileReference::parse(value)?
            },
        }
        let Some(entry) = self.sources.get_mut(setting_index(setting)) else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::Malformed,
                FailureSource::ConfigurationDocument,
            ));
        };
        *entry = source;
        Ok(())
    }

    fn validate(self) -> Result<EffectiveConfiguration, ConfigurationFailure> {
        if self.data_directory == self.secrets_directory {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::UnsafeCombination,
                FailureSource::StorageDataDirectory,
            ));
        }
        Ok(EffectiveConfiguration {
            schema_version: self.schema_version,
            log_level: self.log_level,
            shutdown_grace_seconds: self.shutdown_grace_seconds,
            control_bind_address: self.control_bind_address,
            data_directory: self.data_directory,
            secrets_directory: self.secrets_directory,
            local_key_file: self.local_key_file,
            sources: self.sources,
        })
    }
}

fn collect_pairs<K, V>(
    pairs: impl IntoIterator<Item = (K, V)>,
    source: FailureSource,
) -> Result<Vec<(String, String)>, ConfigurationFailure>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut collected = Vec::with_capacity(MAX_OVERRIDE_PAIRS);
    for (key, value) in pairs {
        let key = key.as_ref();
        let value = value.as_ref();
        if collected.len() == MAX_OVERRIDE_PAIRS
            || key.len() > MAX_KEY_BYTES
            || value.len() > MAX_VALUE_BYTES
        {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::ResourceLimit,
                source,
            ));
        }
        if collected.iter().any(|(existing, _)| existing == key) {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::ConflictingSetting,
                source,
            ));
        }
        collected.push((key.to_owned(), value.to_owned()));
    }
    Ok(collected)
}

fn preflight_toml(file: &str) -> Result<(), ConfigurationFailure> {
    let mut entry_count = 0_usize;
    for raw_line in file.lines() {
        let line = content_before_comment(raw_line)?.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            preflight_table_header(line)?;
            entry_count = entry_count
                .checked_add(1)
                .ok_or_else(|| document_failure(ConfigurationFailureCode::ResourceLimit))?;
            if entry_count > MAX_TOML_ENTRIES {
                return Err(document_failure(ConfigurationFailureCode::ResourceLimit));
            }
            continue;
        }
        let Some(separator) = unquoted_equals(line)? else {
            return Err(document_failure(ConfigurationFailureCode::Malformed));
        };
        let key = line
            .get(..separator)
            .ok_or_else(|| document_failure(ConfigurationFailureCode::Malformed))?
            .trim();
        let value = line
            .get(separator.saturating_add(1)..)
            .ok_or_else(|| document_failure(ConfigurationFailureCode::Malformed))?
            .trim();
        preflight_key(key)?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| document_failure(ConfigurationFailureCode::ResourceLimit))?;
        if entry_count > MAX_TOML_ENTRIES {
            return Err(document_failure(ConfigurationFailureCode::ResourceLimit));
        }
        preflight_scalar(value)?;
    }
    Ok(())
}

fn content_before_comment(line: &str) -> Result<&str, ConfigurationFailure> {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if character == '\\' => escaped = true,
            Some('"') if character == '"' => quote = None,
            Some('\'') if character == '\'' => quote = None,
            Some(_) => {},
            None if character == '"' || character == '\'' => quote = Some(character),
            None if character == '#' => {
                return line
                    .get(..index)
                    .ok_or_else(|| document_failure(ConfigurationFailureCode::Malformed));
            },
            None => {},
        }
    }
    if quote.is_some() || escaped {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    Ok(line)
}

fn preflight_table_header(line: &str) -> Result<(), ConfigurationFailure> {
    if line.starts_with("[[") || !line.ends_with(']') {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    let name = line
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| document_failure(ConfigurationFailureCode::Malformed))?
        .trim();
    if name.len() > MAX_KEY_BYTES {
        return Err(document_failure(ConfigurationFailureCode::ResourceLimit));
    }
    if name.is_empty()
        || name.contains('.')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    Ok(())
}

fn unquoted_equals(line: &str) -> Result<Option<usize>, ConfigurationFailure> {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if character == '\\' => escaped = true,
            Some('"') if character == '"' => quote = None,
            Some('\'') if character == '\'' => quote = None,
            Some(_) => {},
            None if character == '"' || character == '\'' => quote = Some(character),
            None if character == '=' => return Ok(Some(index)),
            None => {},
        }
    }
    if quote.is_some() || escaped {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    Ok(None)
}

fn preflight_key(key: &str) -> Result<(), ConfigurationFailure> {
    if key.len() > MAX_KEY_BYTES {
        return Err(document_failure(ConfigurationFailureCode::ResourceLimit));
    }
    if key.is_empty()
        || key.contains('.')
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    Ok(())
}

fn preflight_scalar(value: &str) -> Result<(), ConfigurationFailure> {
    if value.is_empty() {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    if value.starts_with('[') || value.starts_with('{') {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    let scalar_bytes = if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
    {
        if value.starts_with("\"\"\"") {
            return Err(document_failure(ConfigurationFailureCode::Malformed));
        }
        inner.len()
    } else if let Some(inner) = value
        .strip_prefix('\'')
        .and_then(|inner| inner.strip_suffix('\''))
    {
        if value.starts_with("'''") {
            return Err(document_failure(ConfigurationFailureCode::Malformed));
        }
        inner.len()
    } else {
        value.len()
    };
    if scalar_bytes > MAX_VALUE_BYTES {
        return Err(document_failure(ConfigurationFailureCode::ResourceLimit));
    }
    Ok(())
}

const fn document_failure(code: ConfigurationFailureCode) -> ConfigurationFailure {
    ConfigurationFailure::new(code, FailureSource::ConfigurationDocument)
}

fn environment_path(key: &str) -> Option<String> {
    let suffix = key.strip_prefix("POSITRON__")?;
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return None;
    }
    let segments = suffix.split("__").collect::<Vec<_>>();
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    Some(
        segments
            .into_iter()
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join("."),
    )
}

fn apply_toml(candidate: &mut Candidate, file: &str) -> Result<(), ConfigurationFailure> {
    preflight_toml(file)?;
    let table = file.parse::<toml::Table>().map_err(|_| {
        ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
        )
    })?;

    let Some(schema_version) = table.get("schema_version") else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::MissingSchemaVersion,
            FailureSource::SchemaVersion,
        ));
    };
    apply_toml_value(candidate, Setting::SchemaVersion, schema_version)?;

    for (section, value) in &table {
        if section == "schema_version" {
            continue;
        }
        let toml::Value::Table(settings) = value else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::UnknownSetting,
                FailureSource::ConfigurationDocument,
            ));
        };
        for (key, setting_value) in settings {
            let mut path = String::with_capacity(section.len() + key.len() + 1);
            path.push_str(section);
            path.push('.');
            path.push_str(key);
            let Some(setting) = setting_for_path(&path) else {
                return Err(ConfigurationFailure::new(
                    ConfigurationFailureCode::UnknownSetting,
                    FailureSource::ConfigurationDocument,
                ));
            };
            apply_toml_value(candidate, setting, setting_value)?;
        }
    }
    Ok(())
}

fn apply_toml_value(
    candidate: &mut Candidate,
    setting: Setting,
    value: &toml::Value,
) -> Result<(), ConfigurationFailure> {
    match (setting_definition(setting).kind(), value) {
        (SettingKind::Integer, toml::Value::Integer(value)) => candidate.apply(
            setting,
            &value.to_string(),
            SettingSource::ConfigurationFile,
        ),
        (SettingKind::String, toml::Value::String(value)) => {
            candidate.apply(setting, value, SettingSource::ConfigurationFile)
        },
        _ => Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
        )),
    }
}

fn apply_environment(
    candidate: &mut Candidate,
    overrides: &EnvironmentOverrides,
) -> Result<(), ConfigurationFailure> {
    for (key, value) in &overrides.pairs {
        let Some(path) = environment_path(key) else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::UnknownSetting,
                FailureSource::EnvironmentOverride,
            ));
        };
        let Some(setting) = setting_for_path(&path) else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::UnknownSetting,
                FailureSource::EnvironmentOverride,
            ));
        };
        candidate.apply(setting, value, SettingSource::Environment)?;
    }
    Ok(())
}

fn apply_command_line(
    candidate: &mut Candidate,
    overrides: &CommandLineOverrides,
) -> Result<(), ConfigurationFailure> {
    for (key, value) in &overrides.pairs {
        let Some(setting) = setting_for_path(key) else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::UnknownSetting,
                FailureSource::CommandLineOverride,
            ));
        };
        candidate.apply(setting, value, SettingSource::CommandLine)?;
    }
    Ok(())
}

fn parse_schema_version(value: &str) -> Result<u16, ConfigurationFailure> {
    let version = parse_canonical_u16(value, FailureSource::SchemaVersion)?;
    let ValueDomain::ExactUnsignedInteger(expected) =
        setting_definition(Setting::SchemaVersion).domain()
    else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::SchemaVersion,
        ));
    };
    if version != expected {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::SchemaVersion,
        ));
    }
    Ok(version)
}

fn parse_shutdown_grace_seconds(value: &str) -> Result<u16, ConfigurationFailure> {
    let seconds = parse_canonical_u16(value, FailureSource::RuntimeShutdownGraceSeconds)?;
    let ValueDomain::UnsignedIntegerRange(minimum, maximum) =
        setting_definition(Setting::RuntimeShutdownGraceSeconds).domain()
    else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::RuntimeShutdownGraceSeconds,
        ));
    };
    if !(minimum..=maximum).contains(&seconds) {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::RuntimeShutdownGraceSeconds,
        ));
    }
    Ok(seconds)
}

fn parse_canonical_u16(value: &str, source: FailureSource) -> Result<u16, ConfigurationFailure> {
    if value.is_empty()
        || value.len() > 5
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            source,
        ));
    }
    value
        .parse::<u16>()
        .map_err(|_| ConfigurationFailure::new(ConfigurationFailureCode::UnsupportedValue, source))
}

fn parse_loopback_address(value: &str) -> Result<SocketAddr, ConfigurationFailure> {
    let ValueDomain::LoopbackSocketAddress(maximum_bytes) =
        setting_definition(Setting::ListenerControlBindAddress).domain()
    else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::ListenerControlBindAddress,
        ));
    };
    if value.len() > maximum_bytes {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::ResourceLimit,
            FailureSource::ListenerControlBindAddress,
        ));
    }
    let address = value.parse::<SocketAddr>().map_err(|_| {
        ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::ListenerControlBindAddress,
        )
    })?;
    if !address.ip().is_loopback() {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::UnsafeCombination,
            FailureSource::ListenerControlBindAddress,
        ));
    }
    Ok(address)
}

fn checked_path(value: &str, setting: Setting) -> Result<String, ConfigurationFailure> {
    validate_path(value, setting)?;
    Ok(value.to_owned())
}

fn validate_path(value: &str, setting: Setting) -> Result<(), ConfigurationFailure> {
    let maximum_bytes = match setting_definition(setting).domain() {
        ValueDomain::AbsolutePath(maximum) | ValueDomain::ProtectedAbsolutePath(maximum) => maximum,
        _ => {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::Malformed,
                failure_source(setting),
            ));
        },
    };
    let source = failure_source(setting);
    if value.is_empty() || value.len() > maximum_bytes {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::ResourceLimit,
            source,
        ));
    }
    if !value.starts_with('/') || value.split('/').any(|component| component == "..") {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::UnsafeCombination,
            source,
        ));
    }
    Ok(())
}

const fn setting_index(setting: Setting) -> usize {
    match setting {
        Setting::SchemaVersion => 0,
        Setting::DiagnosticsLogLevel => 1,
        Setting::RuntimeShutdownGraceSeconds => 2,
        Setting::ListenerControlBindAddress => 3,
        Setting::StorageDataDirectory => 4,
        Setting::StorageSecretsDirectory => 5,
        Setting::SecurityLocalKeyFile => 6,
    }
}

fn setting_for_path(path: &str) -> Option<Setting> {
    contract::SETTING_DEFINITIONS
        .into_iter()
        .find(|definition| definition.path() == path)
        .map(SettingDefinition::setting)
}

const fn failure_source(setting: Setting) -> FailureSource {
    match setting {
        Setting::SchemaVersion => FailureSource::SchemaVersion,
        Setting::DiagnosticsLogLevel => FailureSource::DiagnosticsLogLevel,
        Setting::RuntimeShutdownGraceSeconds => FailureSource::RuntimeShutdownGraceSeconds,
        Setting::ListenerControlBindAddress => FailureSource::ListenerControlBindAddress,
        Setting::StorageDataDirectory => FailureSource::StorageDataDirectory,
        Setting::StorageSecretsDirectory => FailureSource::StorageSecretsDirectory,
        Setting::SecurityLocalKeyFile => FailureSource::SecurityLocalKeyFile,
    }
}
