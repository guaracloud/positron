//! Canonical, bounded Configuration Contract resolution for Positron.
//!
//! This boundary resolves compiled defaults, one canonical TOML document,
//! environment overrides, and command-line overrides into checked native
//! values. It owns source provenance, secrecy, validation, mutability, and
//! deterministic schema/reference generation. Runtime publication and live
//! reload remain M4-owned work.

#![forbid(unsafe_code)]

use std::net::SocketAddr;

const MAX_CONFIGURATION_BYTES: usize = 16 * 1024;
const MAX_OVERRIDE_PAIRS: usize = 16;
const MAX_TOML_ENTRIES: usize = 16;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 256;

mod contract;
mod settings;
pub use settings::*;
mod values;
pub use values::*;
mod inputs;
pub use inputs::*;
mod effective;
pub use effective::*;

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

mod source;
use source::{apply_command_line, apply_environment, apply_toml};

#[derive(Clone)]
struct Candidate {
    schema_version: u16,
    log_level: LogLevel,
    shutdown_grace_seconds: u16,
    control_path: String,
    operations_bind_address: SocketAddr,
    api_bind_address: SocketAddr,
    otlp_grpc_bind_address: SocketAddr,
    otlp_http_bind_address: SocketAddr,
    loki_push_bind_address: SocketAddr,
    data_directory: String,
    secrets_directory: String,
    local_key_file: ProtectedFileReference,
    sources: [SettingSource; 12],
}

impl Candidate {
    fn defaults() -> Result<Self, ConfigurationFailure> {
        let schema_version = setting_definition(Setting::SchemaVersion).default_value();
        let log_level = setting_definition(Setting::DiagnosticsLogLevel).default_value();
        let shutdown = setting_definition(Setting::RuntimeShutdownGraceSeconds).default_value();
        let control = setting_definition(Setting::ListenerControlPath).default_value();
        let operations = setting_definition(Setting::ListenerOperationsBindAddress).default_value();
        let api = setting_definition(Setting::ListenerApiBindAddress).default_value();
        let otlp_grpc = setting_definition(Setting::ListenerOtlpGrpcBindAddress).default_value();
        let otlp_http = setting_definition(Setting::ListenerOtlpHttpBindAddress).default_value();
        let loki_push = setting_definition(Setting::ListenerLokiPushBindAddress).default_value();
        let data = setting_definition(Setting::StorageDataDirectory).default_value();
        let secrets = setting_definition(Setting::StorageSecretsDirectory).default_value();
        let local_key = setting_definition(Setting::SecurityLocalKeyFile).default_value();
        Ok(Self {
            schema_version: parse_schema_version(schema_version)?,
            log_level: LogLevel::parse(log_level)?,
            shutdown_grace_seconds: parse_shutdown_grace_seconds(shutdown)?,
            control_path: checked_path(control, Setting::ListenerControlPath)?,
            operations_bind_address: parse_loopback_address(
                operations,
                Setting::ListenerOperationsBindAddress,
            )?,
            api_bind_address: parse_loopback_address(api, Setting::ListenerApiBindAddress)?,
            otlp_grpc_bind_address: parse_loopback_address(
                otlp_grpc,
                Setting::ListenerOtlpGrpcBindAddress,
            )?,
            otlp_http_bind_address: parse_loopback_address(
                otlp_http,
                Setting::ListenerOtlpHttpBindAddress,
            )?,
            loki_push_bind_address: parse_loopback_address(
                loki_push,
                Setting::ListenerLokiPushBindAddress,
            )?,
            data_directory: checked_path(data, Setting::StorageDataDirectory)?,
            secrets_directory: checked_path(secrets, Setting::StorageSecretsDirectory)?,
            local_key_file: ProtectedFileReference::parse(local_key)?,
            sources: [SettingSource::CompiledDefault; 12],
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
            Setting::ListenerControlPath => {
                self.control_path = checked_path(value, setting)?;
            },
            Setting::ListenerOperationsBindAddress => {
                self.operations_bind_address = parse_loopback_address(value, setting)?;
            },
            Setting::ListenerApiBindAddress => {
                self.api_bind_address = parse_loopback_address(value, setting)?;
            },
            Setting::ListenerOtlpGrpcBindAddress => {
                self.otlp_grpc_bind_address = parse_loopback_address(value, setting)?;
            },
            Setting::ListenerOtlpHttpBindAddress => {
                self.otlp_http_bind_address = parse_loopback_address(value, setting)?;
            },
            Setting::ListenerLokiPushBindAddress => {
                self.loki_push_bind_address = parse_loopback_address(value, setting)?;
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
            control_path: self.control_path,
            operations_bind_address: self.operations_bind_address,
            api_bind_address: self.api_bind_address,
            otlp_grpc_bind_address: self.otlp_grpc_bind_address,
            otlp_http_bind_address: self.otlp_http_bind_address,
            loki_push_bind_address: self.loki_push_bind_address,
            data_directory: self.data_directory,
            secrets_directory: self.secrets_directory,
            local_key_file: self.local_key_file,
            sources: self.sources,
        })
    }
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

fn parse_loopback_address(
    value: &str,
    setting: Setting,
) -> Result<SocketAddr, ConfigurationFailure> {
    let source = failure_source(setting);
    let ValueDomain::LoopbackSocketAddress(_) = setting_definition(setting).domain() else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            source,
        ));
    };
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| ConfigurationFailure::new(ConfigurationFailureCode::Malformed, source))?;
    if !address.ip().is_loopback() {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::UnsafeCombination,
            source,
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
        Setting::ListenerControlPath => 3,
        Setting::ListenerOperationsBindAddress => 4,
        Setting::ListenerApiBindAddress => 5,
        Setting::ListenerOtlpGrpcBindAddress => 6,
        Setting::ListenerOtlpHttpBindAddress => 7,
        Setting::ListenerLokiPushBindAddress => 8,
        Setting::StorageDataDirectory => 9,
        Setting::StorageSecretsDirectory => 10,
        Setting::SecurityLocalKeyFile => 11,
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
        Setting::ListenerControlPath => FailureSource::ListenerControlPath,
        Setting::ListenerOperationsBindAddress => FailureSource::ListenerOperationsBindAddress,
        Setting::ListenerApiBindAddress => FailureSource::ListenerApiBindAddress,
        Setting::ListenerOtlpGrpcBindAddress => FailureSource::ListenerOtlpGrpcBindAddress,
        Setting::ListenerOtlpHttpBindAddress => FailureSource::ListenerOtlpHttpBindAddress,
        Setting::ListenerLokiPushBindAddress => FailureSource::ListenerLokiPushBindAddress,
        Setting::StorageDataDirectory => FailureSource::StorageDataDirectory,
        Setting::StorageSecretsDirectory => FailureSource::StorageSecretsDirectory,
        Setting::SecurityLocalKeyFile => FailureSource::SecurityLocalKeyFile,
    }
}
