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
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

const MAX_CONFIGURATION_BYTES: usize = 16 * 1024;
const MAX_OVERRIDE_PAIRS: usize = 16;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 256;
const CURRENT_SCHEMA_VERSION: u16 = 1;
const DEFAULT_DATA_DIRECTORY: &str = "/var/lib/positron";
const DEFAULT_SECRETS_DIRECTORY: &str = "/var/lib/positron-secrets";
const DEFAULT_LOCAL_KEY_FILE: &str = "/var/lib/positron-secrets/local-root-key";
const DEFAULT_BIND_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 4317));
const DEFAULT_SHUTDOWN_GRACE_SECONDS: u16 = 30;

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
        match self {
            Self::SchemaVersion => "schema_version",
            Self::DiagnosticsLogLevel => "diagnostics.log_level",
            Self::RuntimeShutdownGraceSeconds => "runtime.shutdown_grace_seconds",
            Self::ListenerControlBindAddress => "listener.control_bind_address",
            Self::StorageDataDirectory => "storage.data_directory",
            Self::StorageSecretsDirectory => "storage.secrets_directory",
            Self::SecurityLocalKeyFile => "security.local_key_file",
        }
    }

    /// Returns the setting's one declared secrecy class.
    #[must_use]
    pub const fn secrecy(self) -> SecrecyClass {
        match self {
            Self::SecurityLocalKeyFile => SecrecyClass::SecretBearing,
            Self::SchemaVersion
            | Self::DiagnosticsLogLevel
            | Self::RuntimeShutdownGraceSeconds
            | Self::ListenerControlBindAddress
            | Self::StorageDataDirectory
            | Self::StorageSecretsDirectory => SecrecyClass::Public,
        }
    }

    /// Returns the setting's one declared mutability class.
    #[must_use]
    pub const fn mutability(self) -> MutabilityClass {
        match self {
            Self::DiagnosticsLogLevel => MutabilityClass::LiveReloadable,
            Self::ListenerControlBindAddress => MutabilityClass::DrainAndReload,
            Self::RuntimeShutdownGraceSeconds => MutabilityClass::RestartRequired,
            Self::SchemaVersion
            | Self::StorageDataDirectory
            | Self::StorageSecretsDirectory
            | Self::SecurityLocalKeyFile => MutabilityClass::ImmutableAfterInitialization,
        }
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
        validate_path(value, FailureSource::SecurityLocalKeyFile)?;
        Ok(Self {
            path: value.to_owned(),
        })
    }

    /// Borrows the protected path only for a module-specific adapter.
    #[must_use]
    pub fn protected_path(&self) -> &str {
        &self.path
    }
}

/// A closed stable class for a rejected configuration operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationFailureCode {
    /// The bounded source cannot be parsed as the canonical subset of TOML.
    InvalidSyntax,
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
    InputLimitExceeded,
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
            ConfigurationFailureCode::InvalidSyntax => "invalid canonical configuration syntax",
            ConfigurationFailureCode::UnknownSetting => "unknown configuration setting",
            ConfigurationFailureCode::UnsupportedValue => "unsupported configuration value",
            ConfigurationFailureCode::UnsafeCombination => "unsafe configuration combination",
            ConfigurationFailureCode::ConflictingSetting => "conflicting configuration setting",
            ConfigurationFailureCode::SecretOverrideNotAllowed => {
                "secret configuration override is not allowed"
            },
            ConfigurationFailureCode::InputLimitExceeded => "configuration input limit exceeded",
            ConfigurationFailureCode::ImmutableSettingChanged => {
                "immutable initialized configuration changed"
            },
        })
    }
}

impl Error for ConfigurationFailure {}

/// Bounded non-secret environment overrides.
#[derive(Clone, Debug, Eq, PartialEq)]
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

/// Bounded non-secret explicit command-line overrides.
#[derive(Clone, Debug, Eq, PartialEq)]
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

/// All bounded source inputs required to resolve one candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationInputs {
    file: Option<String>,
    environment: EnvironmentOverrides,
    command_line: CommandLineOverrides,
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
                        ConfigurationFailureCode::InputLimitExceeded,
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
        for setting in SETTINGS {
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

/// Generates the canonical JSON Schema from the Rust-owned setting inventory.
#[must_use]
pub fn generated_json_schema() -> String {
    let mut schema = String::with_capacity(2048);
    schema.push_str("{\n  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n");
    schema.push_str("  \"title\": \"Positron Configuration Contract v1\",\n");
    schema.push_str("  \"type\": \"object\",\n  \"additionalProperties\": false,\n");
    schema.push_str("  \"properties\": {\n    \"schema_version\": {\"const\": 1},\n");
    schema.push_str("    \"diagnostics\": {\"type\": \"object\", \"additionalProperties\": false, \"properties\": {\"log_level\": {\"enum\": [\"error\", \"warn\", \"info\", \"debug\"]}}},\n");
    schema.push_str("    \"runtime\": {\"type\": \"object\", \"additionalProperties\": false, \"properties\": {\"shutdown_grace_seconds\": {\"type\": \"integer\", \"minimum\": 1, \"maximum\": 3600}}},\n");
    schema.push_str("    \"listener\": {\"type\": \"object\", \"additionalProperties\": false, \"properties\": {\"control_bind_address\": {\"type\": \"string\", \"maxLength\": 256}}},\n");
    schema.push_str("    \"storage\": {\"type\": \"object\", \"additionalProperties\": false, \"properties\": {\"data_directory\": {\"type\": \"string\", \"maxLength\": 256}, \"secrets_directory\": {\"type\": \"string\", \"maxLength\": 256}}},\n");
    schema.push_str("    \"security\": {\"type\": \"object\", \"additionalProperties\": false, \"properties\": {\"local_key_file\": {\"type\": \"string\", \"maxLength\": 256, \"writeOnly\": true}}}\n  },\n  \"required\": [\"schema_version\"]\n}\n");
    schema
}

/// Generates the canonical operator/reference documentation without secrets.
#[must_use]
pub fn generated_reference() -> String {
    let mut reference = String::with_capacity(2048);
    reference.push_str("# Positron Configuration Contract v1\n\n");
    reference.push_str("Precedence: compiled defaults, TOML file, non-secret POSITRON__ overrides, then non-secret CLI overrides.\n\n");
    reference.push_str("| Setting | Default | Secrecy | Mutability |\n| --- | --- | --- | --- |\n");
    for setting in SETTINGS {
        reference.push_str("| `");
        reference.push_str(setting.path());
        reference.push_str("` | ");
        reference.push_str(default_description(setting));
        reference.push_str(" | ");
        reference.push_str(match setting.secrecy() {
            SecrecyClass::Public => "public",
            SecrecyClass::SecretBearing => "secret-bearing (redacted)",
        });
        reference.push_str(" | ");
        reference.push_str(match setting.mutability() {
            MutabilityClass::LiveReloadable => "live-reloadable",
            MutabilityClass::DrainAndReload => "drain-and-reload",
            MutabilityClass::RestartRequired => "restart-required",
            MutabilityClass::ImmutableAfterInitialization => "immutable after initialization",
        });
        reference.push_str(" |\n");
    }
    reference
}

const SETTINGS: [Setting; 7] = [
    Setting::SchemaVersion,
    Setting::DiagnosticsLogLevel,
    Setting::RuntimeShutdownGraceSeconds,
    Setting::ListenerControlBindAddress,
    Setting::StorageDataDirectory,
    Setting::StorageSecretsDirectory,
    Setting::SecurityLocalKeyFile,
];

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
        Ok(Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            log_level: LogLevel::Info,
            shutdown_grace_seconds: DEFAULT_SHUTDOWN_GRACE_SECONDS,
            control_bind_address: DEFAULT_BIND_ADDRESS,
            data_directory: DEFAULT_DATA_DIRECTORY.to_owned(),
            secrets_directory: DEFAULT_SECRETS_DIRECTORY.to_owned(),
            local_key_file: ProtectedFileReference::parse(DEFAULT_LOCAL_KEY_FILE)?,
            sources: [SettingSource::CompiledDefault; 7],
        })
    }

    fn apply(
        &mut self,
        setting: Setting,
        value: &str,
        source: SettingSource,
    ) -> Result<(), ConfigurationFailure> {
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
                validate_path(value, FailureSource::StorageDataDirectory)?;
                self.data_directory = value.to_owned();
            },
            Setting::StorageSecretsDirectory => {
                validate_path(value, FailureSource::StorageSecretsDirectory)?;
                self.secrets_directory = value.to_owned();
            },
            Setting::SecurityLocalKeyFile => {
                self.local_key_file = ProtectedFileReference::parse(value)?
            },
        }
        let Some(entry) = self.sources.get_mut(setting_index(setting)) else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::InvalidSyntax,
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
                ConfigurationFailureCode::InputLimitExceeded,
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

fn apply_toml(candidate: &mut Candidate, file: &str) -> Result<(), ConfigurationFailure> {
    let mut section = "";
    let mut seen = [false; 7];
    for line in file.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            section = match name {
                "diagnostics" | "runtime" | "listener" | "storage" | "security" => name,
                _ => {
                    return Err(ConfigurationFailure::new(
                        ConfigurationFailureCode::UnknownSetting,
                        FailureSource::ConfigurationDocument,
                    ));
                },
            };
            continue;
        }
        let Some((key, raw_value)) = trimmed.split_once('=') else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::InvalidSyntax,
                FailureSource::ConfigurationDocument,
            ));
        };
        let key = key.trim();
        let value = parse_toml_scalar(raw_value.trim())?;
        let path = if section.is_empty() {
            key.to_owned()
        } else {
            let mut path = String::with_capacity(section.len() + key.len() + 1);
            path.push_str(section);
            path.push('.');
            path.push_str(key);
            path
        };
        let Some(setting) = setting_for_path(&path) else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::UnknownSetting,
                FailureSource::ConfigurationDocument,
            ));
        };
        let index = setting_index(setting);
        let Some(already_seen) = seen.get(index).copied() else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::InvalidSyntax,
                FailureSource::ConfigurationDocument,
            ));
        };
        if already_seen {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::ConflictingSetting,
                FailureSource::ConfigurationDocument,
            ));
        }
        let Some(entry) = seen.get_mut(index) else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::InvalidSyntax,
                FailureSource::ConfigurationDocument,
            ));
        };
        *entry = true;
        candidate.apply(setting, value, SettingSource::ConfigurationFile)?;
    }
    Ok(())
}

fn parse_toml_scalar(value: &str) -> Result<&str, ConfigurationFailure> {
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        if inner.contains('"') || inner.contains('\\') || inner.len() > MAX_VALUE_BYTES {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::InvalidSyntax,
                FailureSource::ConfigurationDocument,
            ));
        }
        return Ok(inner);
    }
    if value.is_empty()
        || value.len() > MAX_VALUE_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::InvalidSyntax,
            FailureSource::ConfigurationDocument,
        ));
    }
    Ok(value)
}

fn apply_environment(
    candidate: &mut Candidate,
    overrides: &EnvironmentOverrides,
) -> Result<(), ConfigurationFailure> {
    for (key, value) in &overrides.pairs {
        let setting = match key.as_str() {
            "POSITRON__DIAGNOSTICS__LOG_LEVEL" => Setting::DiagnosticsLogLevel,
            "POSITRON__RUNTIME__SHUTDOWN_GRACE_SECONDS" => Setting::RuntimeShutdownGraceSeconds,
            "POSITRON__LISTENER__CONTROL_BIND_ADDRESS" => Setting::ListenerControlBindAddress,
            "POSITRON__SECURITY__LOCAL_KEY_FILE" => {
                return Err(ConfigurationFailure::new(
                    ConfigurationFailureCode::SecretOverrideNotAllowed,
                    FailureSource::SecurityLocalKeyFile,
                ));
            },
            _ => {
                return Err(ConfigurationFailure::new(
                    ConfigurationFailureCode::UnknownSetting,
                    FailureSource::EnvironmentOverride,
                ));
            },
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
        let setting = match key.as_str() {
            "diagnostics.log_level" => Setting::DiagnosticsLogLevel,
            "runtime.shutdown_grace_seconds" => Setting::RuntimeShutdownGraceSeconds,
            "listener.control_bind_address" => Setting::ListenerControlBindAddress,
            "security.local_key_file" => {
                return Err(ConfigurationFailure::new(
                    ConfigurationFailureCode::SecretOverrideNotAllowed,
                    FailureSource::SecurityLocalKeyFile,
                ));
            },
            _ => {
                return Err(ConfigurationFailure::new(
                    ConfigurationFailureCode::UnknownSetting,
                    FailureSource::CommandLineOverride,
                ));
            },
        };
        candidate.apply(setting, value, SettingSource::CommandLine)?;
    }
    Ok(())
}

fn parse_schema_version(value: &str) -> Result<u16, ConfigurationFailure> {
    let version = parse_canonical_u16(value, FailureSource::SchemaVersion)?;
    if version != CURRENT_SCHEMA_VERSION {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::SchemaVersion,
        ));
    }
    Ok(version)
}

fn parse_shutdown_grace_seconds(value: &str) -> Result<u16, ConfigurationFailure> {
    let seconds = parse_canonical_u16(value, FailureSource::RuntimeShutdownGraceSeconds)?;
    if !(1..=3600).contains(&seconds) {
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
            ConfigurationFailureCode::InvalidSyntax,
            source,
        ));
    }
    value
        .parse::<u16>()
        .map_err(|_| ConfigurationFailure::new(ConfigurationFailureCode::UnsupportedValue, source))
}

fn parse_loopback_address(value: &str) -> Result<SocketAddr, ConfigurationFailure> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::InputLimitExceeded,
            FailureSource::ListenerControlBindAddress,
        ));
    }
    let address = value.parse::<SocketAddr>().map_err(|_| {
        ConfigurationFailure::new(
            ConfigurationFailureCode::InvalidSyntax,
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

fn validate_path(value: &str, source: FailureSource) -> Result<(), ConfigurationFailure> {
    if value.is_empty() || value.len() > MAX_PATH_BYTES {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::InputLimitExceeded,
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
    SETTINGS.into_iter().find(|setting| setting.path() == path)
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

const fn default_description(setting: Setting) -> &'static str {
    match setting {
        Setting::SchemaVersion => "`1`",
        Setting::DiagnosticsLogLevel => "`info`",
        Setting::RuntimeShutdownGraceSeconds => "`30` seconds",
        Setting::ListenerControlBindAddress => "`127.0.0.1:4317`",
        Setting::StorageDataDirectory => "`/var/lib/positron`",
        Setting::StorageSecretsDirectory => "`/var/lib/positron-secrets`",
        Setting::SecurityLocalKeyFile => "redacted protected-file reference",
    }
}
