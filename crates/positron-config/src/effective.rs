use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;

use super::{
    ConfigurationFailure, ConfigurationFailureCode, LogLevel, MutabilityClass,
    ProtectedFileReference, Setting, SettingSource, contract, failure_source, setting_for_path,
    setting_index,
};

#[derive(Clone, Eq, PartialEq)]
pub struct EffectiveConfiguration {
    pub(crate) schema_version: u16,
    pub(crate) log_level: LogLevel,
    pub(crate) shutdown_grace_seconds: u16,
    pub(crate) control_path: String,
    pub(crate) operations_bind_address: SocketAddr,
    pub(crate) api_bind_address: SocketAddr,
    pub(crate) otlp_grpc_bind_address: SocketAddr,
    pub(crate) otlp_http_bind_address: SocketAddr,
    pub(crate) data_directory: String,
    pub(crate) secrets_directory: String,
    pub(crate) local_key_file: ProtectedFileReference,
    pub(crate) sources: [SettingSource; 11],
}

impl EffectiveConfiguration {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn log_level(&self) -> LogLevel {
        self.log_level
    }

    #[must_use]
    pub const fn shutdown_grace_seconds(&self) -> u16 {
        self.shutdown_grace_seconds
    }

    #[must_use]
    pub fn control_path(&self) -> &str {
        &self.control_path
    }

    #[must_use]
    pub const fn operations_bind_address(&self) -> SocketAddr {
        self.operations_bind_address
    }

    #[must_use]
    pub const fn api_bind_address(&self) -> SocketAddr {
        self.api_bind_address
    }

    #[must_use]
    pub const fn otlp_grpc_bind_address(&self) -> SocketAddr {
        self.otlp_grpc_bind_address
    }

    #[must_use]
    pub const fn otlp_http_bind_address(&self) -> SocketAddr {
        self.otlp_http_bind_address
    }

    #[must_use]
    pub fn data_directory(&self) -> &str {
        &self.data_directory
    }

    #[must_use]
    pub fn secrets_directory(&self) -> &str {
        &self.secrets_directory
    }

    #[must_use]
    pub fn local_key_file(&self) -> &ProtectedFileReference {
        &self.local_key_file
    }

    #[must_use]
    pub fn source_for(&self, path: &str) -> Option<SettingSource> {
        setting_for_path(path).and_then(|setting| self.sources.get(setting_index(setting)).copied())
    }

    #[must_use]
    pub fn redacted_reference(&self) -> String {
        let mut rendered = String::with_capacity(512);
        rendered.push_str("schema_version = ");
        rendered.push_str(&self.schema_version.to_string());
        rendered.push_str("\n\n[diagnostics]\nlog_level = \"");
        rendered.push_str(self.log_level.as_str());
        rendered.push_str("\"\n\n[runtime]\nshutdown_grace_seconds = ");
        rendered.push_str(&self.shutdown_grace_seconds.to_string());
        rendered.push_str("\n\n[listener]\ncontrol_path = \"");
        rendered.push_str(&self.control_path);
        rendered.push_str("\"\noperations_bind_address = \"");
        rendered.push_str(&self.operations_bind_address.to_string());
        rendered.push_str("\"\napi_bind_address = \"");
        rendered.push_str(&self.api_bind_address.to_string());
        rendered.push_str("\"\notlp_grpc_bind_address = \"");
        rendered.push_str(&self.otlp_grpc_bind_address.to_string());
        rendered.push_str("\"\notlp_http_bind_address = \"");
        rendered.push_str(&self.otlp_http_bind_address.to_string());
        rendered.push_str("\"\n\n[storage]\ndata_directory = \"");
        rendered.push_str(&self.data_directory);
        rendered.push_str("\"\nsecrets_directory = \"");
        rendered.push_str(&self.secrets_directory);
        rendered.push_str("\"\n\n[security]\nlocal_key_file = \"<redacted>\"\n");
        rendered
    }

    pub fn plan_update(&self, candidate: &Self) -> Result<ConfigurationPlan, ConfigurationFailure> {
        let mut changes = Vec::with_capacity(11);
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
            Setting::ListenerControlPath => self.control_path != other.control_path,
            Setting::ListenerOperationsBindAddress => {
                self.operations_bind_address != other.operations_bind_address
            },
            Setting::ListenerApiBindAddress => self.api_bind_address != other.api_bind_address,
            Setting::ListenerOtlpGrpcBindAddress => {
                self.otlp_grpc_bind_address != other.otlp_grpc_bind_address
            },
            Setting::ListenerOtlpHttpBindAddress => {
                self.otlp_http_bind_address != other.otlp_http_bind_address
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
            .field("control_path", &self.control_path)
            .field("operations_bind_address", &self.operations_bind_address)
            .field("api_bind_address", &self.api_bind_address)
            .field("otlp_grpc_bind_address", &self.otlp_grpc_bind_address)
            .field("otlp_http_bind_address", &self.otlp_http_bind_address)
            .field("data_directory", &self.data_directory)
            .field("secrets_directory", &self.secrets_directory)
            .field("local_key_file", &"<redacted>")
            .field("sources", &self.sources)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigurationPlan {
    NoChange,
    PublishLive { changed: Vec<Setting> },
    DrainThenPublish { changed: Vec<Setting> },
    RestartRequired { changed: Vec<Setting> },
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
