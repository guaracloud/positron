use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::Path;

use super::{Setting, ValueDomain, setting_definition, validate_path};

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
    pub(crate) fn parse(value: &str) -> Result<Self, ConfigurationFailure> {
        validate_path(value, Setting::SecurityLocalKeyFile)?;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClass {
    Never,
    AfterInputCorrection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionState {
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureSource {
    ConfigurationDocument,
    EnvironmentOverride,
    CommandLineOverride,
    SchemaVersion,
    DiagnosticsLogLevel,
    RuntimeShutdownGraceSeconds,
    ListenerControlPath,
    ListenerOperationsBindAddress,
    ListenerApiBindAddress,
    ListenerOtlpGrpcBindAddress,
    ListenerOtlpHttpBindAddress,
    StorageDataDirectory,
    StorageSecretsDirectory,
    SecurityLocalKeyFile,
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
