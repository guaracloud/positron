use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;

use positron_domain::identity::TenantId;

use super::{
    ApiTransport, ConfigurationFailure, ConfigurationFailureCode, LogLevel, MutabilityClass,
    ProtectedFileReference, Setting, SettingSource, contract, failure_source, setting_for_path,
    setting_index,
};

/// A bounded, non-secret warning derived from the active effective profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationWarning {
    /// The API listener accepts unencrypted traffic by explicit operator choice.
    PublicPlaintextApi,
}

impl ConfigurationWarning {
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::PublicPlaintextApi => "public API transport is plaintext",
        }
    }
}

const NO_CONFIGURATION_WARNINGS: &[ConfigurationWarning] = &[];
const PUBLIC_PLAINTEXT_API_WARNING: &[ConfigurationWarning] =
    &[ConfigurationWarning::PublicPlaintextApi];

/// One resolved export destination authorized for a caller's tenant.
///
/// The identity has no public constructor: it is minted only after the
/// Configuration Contract has validated an operator-owned definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredExportDestination {
    name: String,
    identity: [u8; 16],
    tenant_id: TenantId,
}

impl ConfiguredExportDestination {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn identity(&self) -> [u8; 16] {
        self.identity
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExportDestinationDefinition {
    pub(crate) name: String,
    pub(crate) identity: [u8; 16],
    pub(crate) allowed_tenants: Vec<TenantId>,
}

impl ExportDestinationDefinition {
    pub(crate) fn resolve(&self, tenant_id: TenantId) -> Option<ConfiguredExportDestination> {
        self.allowed_tenants
            .contains(&tenant_id)
            .then(|| ConfiguredExportDestination {
                name: self.name.clone(),
                identity: self.identity,
                tenant_id,
            })
    }
}

/// The resolved, configuration-file-only plaintext listener selection that
/// startup must durably acknowledge before serving.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicPlaintextApiConfiguration {
    api_bind_address: SocketAddr,
}

impl PublicPlaintextApiConfiguration {
    #[must_use]
    pub const fn api_bind_address(self) -> SocketAddr {
        self.api_bind_address
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EffectiveConfiguration {
    pub(crate) schema_version: u16,
    pub(crate) log_level: LogLevel,
    pub(crate) shutdown_grace_seconds: u16,
    pub(crate) max_registered_tenants: u16,
    pub(crate) control_path: String,
    pub(crate) operations_bind_address: SocketAddr,
    pub(crate) api_bind_address: SocketAddr,
    pub(crate) api_transport: ApiTransport,
    pub(crate) api_tls_certificate_file: ProtectedFileReference,
    pub(crate) api_tls_private_key_file: ProtectedFileReference,
    pub(crate) otlp_grpc_bind_address: SocketAddr,
    pub(crate) otlp_http_bind_address: SocketAddr,
    pub(crate) loki_push_bind_address: SocketAddr,
    pub(crate) data_directory: String,
    pub(crate) secrets_directory: String,
    pub(crate) local_key_file: ProtectedFileReference,
    pub(crate) export_destinations: Vec<ExportDestinationDefinition>,
    pub(crate) sources: [SettingSource; 17],
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

    /// Maximum tenant quotas simultaneously registered in the live Resource Governor.
    #[must_use]
    pub const fn max_registered_tenants(&self) -> u16 {
        self.max_registered_tenants
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
    pub const fn api_transport(&self) -> ApiTransport {
        self.api_transport
    }

    /// Returns the typed startup intent only for the exact configuration-file
    /// opt-out accepted by the Configuration Contract.
    #[must_use]
    pub fn public_plaintext_api_configuration(&self) -> Option<PublicPlaintextApiConfiguration> {
        (self.api_transport == ApiTransport::PlaintextOptOut
            && self.source_for(Setting::ListenerApiTransport.path())
                == Some(SettingSource::ConfigurationFile))
        .then_some(PublicPlaintextApiConfiguration {
            api_bind_address: self.api_bind_address,
        })
    }

    /// Returns the visible security consequences of the selected profile.
    #[must_use]
    pub const fn security_warnings(&self) -> &'static [ConfigurationWarning] {
        match self.api_transport {
            ApiTransport::Tls => NO_CONFIGURATION_WARNINGS,
            ApiTransport::PlaintextOptOut => PUBLIC_PLAINTEXT_API_WARNING,
        }
    }

    #[must_use]
    pub fn api_tls_certificate_file(&self) -> &ProtectedFileReference {
        &self.api_tls_certificate_file
    }

    #[must_use]
    pub fn api_tls_private_key_file(&self) -> &ProtectedFileReference {
        &self.api_tls_private_key_file
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
    pub const fn loki_push_bind_address(&self) -> SocketAddr {
        self.loki_push_bind_address
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

    /// Returns an operator-configured destination only when its scope includes
    /// the authenticated tenant. No configured entries means durable export is
    /// disabled.
    #[must_use]
    pub fn export_destination(
        &self,
        tenant_id: TenantId,
        name: &str,
    ) -> Option<ConfiguredExportDestination> {
        self.export_destinations
            .iter()
            .find(|destination| destination.name == name)
            .and_then(|destination| destination.resolve(tenant_id))
    }

    #[must_use]
    pub const fn durable_exports_enabled(&self) -> bool {
        !self.export_destinations.is_empty()
    }

    #[must_use]
    pub fn source_for(&self, path: &str) -> Option<SettingSource> {
        setting_for_path(path).and_then(|setting| self.sources.get(setting_index(setting)).copied())
    }

    /// Renders the complete effective state with every secret-bearing setting
    /// replaced by a redaction marker and each setting's source recorded.
    #[must_use]
    pub fn redacted_effective(&self) -> String {
        let mut rendered = self.redacted_reference();
        rendered.push_str("\n[provenance]\n");
        for definition in contract::SETTING_DEFINITIONS {
            let setting = definition.setting();
            rendered.push('"');
            rendered.push_str(definition.path());
            rendered.push_str("\" = \"");
            if let Some(source) = self.sources.get(setting_index(setting)) {
                rendered.push_str(source.as_str());
            } else {
                rendered.push_str("unavailable");
            }
            rendered.push_str("\"\n");
        }
        rendered
    }

    /// Computes the deterministic semantic difference without mutating a
    /// runtime or publishing a configuration generation.
    #[must_use]
    pub fn semantic_diff(&self, candidate: &Self) -> ConfigurationDiff {
        let mut changes = Vec::with_capacity(12);
        for definition in contract::SETTING_DEFINITIONS {
            let setting = definition.setting();
            if self.setting_differs(candidate, setting) {
                changes.push(ConfigurationChange {
                    setting,
                    before: self.redacted_value(setting),
                    after: candidate.redacted_value(setting),
                    before_source: self.source_for(setting.path()),
                    after_source: candidate.source_for(setting.path()),
                });
            }
        }
        let plan = ConfigurationDiffPlan::from_changes(&changes);
        ConfigurationDiff { changes, plan }
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
        rendered.push_str("\nmax_registered_tenants = ");
        rendered.push_str(&self.max_registered_tenants.to_string());
        rendered.push_str("\n\n[listener]\ncontrol_path = \"");
        rendered.push_str(&self.control_path);
        rendered.push_str("\"\noperations_bind_address = \"");
        rendered.push_str(&self.operations_bind_address.to_string());
        rendered.push_str("\"\napi_bind_address = \"");
        rendered.push_str(&self.api_bind_address.to_string());
        rendered.push_str("\"\napi_transport = \"");
        rendered.push_str(self.api_transport.as_str());
        rendered.push_str("\"\napi_tls_certificate_file = \"<redacted>\"\napi_tls_private_key_file = \"<redacted>");
        rendered.push_str("\"\notlp_grpc_bind_address = \"");
        rendered.push_str(&self.otlp_grpc_bind_address.to_string());
        rendered.push_str("\"\notlp_http_bind_address = \"");
        rendered.push_str(&self.otlp_http_bind_address.to_string());
        rendered.push_str("\"\nloki_push_bind_address = \"");
        rendered.push_str(&self.loki_push_bind_address.to_string());
        rendered.push('"');
        for destination in &self.export_destinations {
            rendered.push_str("\n\n[[export.destination]]\nname = \"");
            rendered.push_str(&destination.name);
            rendered.push_str("\"\nidentity = \"");
            rendered.push_str(&hexadecimal_identity(destination.identity));
            rendered.push_str("\"\nallowed_tenants = [");
            for (index, tenant) in destination.allowed_tenants.iter().enumerate() {
                if index != 0 {
                    rendered.push_str(", ");
                }
                rendered.push('"');
                rendered.push_str(&tenant.to_canonical_text());
                rendered.push('"');
            }
            rendered.push(']');
        }
        if let Some(warning) = self.security_warnings().first() {
            rendered.push_str("\n\n[warnings]\nwarning = \"");
            rendered.push_str(warning.message());
            rendered.push('"');
        }
        rendered.push_str("\n\n[storage]\ndata_directory = \"");
        rendered.push_str(&self.data_directory);
        rendered.push_str("\"\nsecrets_directory = \"");
        rendered.push_str(&self.secrets_directory);
        rendered.push_str("\"\n\n[security]\nlocal_key_file = \"<redacted>\"\n");
        rendered
    }

    pub fn plan_update(&self, candidate: &Self) -> Result<ConfigurationPlan, ConfigurationFailure> {
        let mut changes = Vec::with_capacity(12);
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
            Setting::RuntimeMaxRegisteredTenants => {
                self.max_registered_tenants != other.max_registered_tenants
            },
            Setting::ListenerControlPath => self.control_path != other.control_path,
            Setting::ListenerOperationsBindAddress => {
                self.operations_bind_address != other.operations_bind_address
            },
            Setting::ListenerApiBindAddress => self.api_bind_address != other.api_bind_address,
            Setting::ListenerApiTransport => self.api_transport != other.api_transport,
            Setting::ListenerApiTlsCertificateFile => {
                self.api_tls_certificate_file != other.api_tls_certificate_file
            },
            Setting::ListenerApiTlsPrivateKeyFile => {
                self.api_tls_private_key_file != other.api_tls_private_key_file
            },
            Setting::ListenerOtlpGrpcBindAddress => {
                self.otlp_grpc_bind_address != other.otlp_grpc_bind_address
            },
            Setting::ListenerOtlpHttpBindAddress => {
                self.otlp_http_bind_address != other.otlp_http_bind_address
            },
            Setting::ListenerLokiPushBindAddress => {
                self.loki_push_bind_address != other.loki_push_bind_address
            },
            Setting::StorageDataDirectory => self.data_directory != other.data_directory,
            Setting::StorageSecretsDirectory => self.secrets_directory != other.secrets_directory,
            Setting::SecurityLocalKeyFile => self.local_key_file != other.local_key_file,
            Setting::ExportDestinations => self.export_destinations != other.export_destinations,
        }
    }

    fn redacted_value(&self, setting: Setting) -> String {
        if setting.secrecy() == super::SecrecyClass::SecretBearing {
            return "<redacted>".to_owned();
        }
        match setting {
            Setting::SchemaVersion => self.schema_version.to_string(),
            Setting::DiagnosticsLogLevel => self.log_level.as_str().to_owned(),
            Setting::RuntimeShutdownGraceSeconds => self.shutdown_grace_seconds.to_string(),
            Setting::RuntimeMaxRegisteredTenants => self.max_registered_tenants.to_string(),
            Setting::ListenerControlPath => self.control_path.clone(),
            Setting::ListenerOperationsBindAddress => self.operations_bind_address.to_string(),
            Setting::ListenerApiBindAddress => self.api_bind_address.to_string(),
            Setting::ListenerApiTransport => self.api_transport.as_str().to_owned(),
            Setting::ListenerApiTlsCertificateFile
            | Setting::ListenerApiTlsPrivateKeyFile
            | Setting::SecurityLocalKeyFile => "<redacted>".to_owned(),
            Setting::ListenerOtlpGrpcBindAddress => self.otlp_grpc_bind_address.to_string(),
            Setting::ListenerOtlpHttpBindAddress => self.otlp_http_bind_address.to_string(),
            Setting::ListenerLokiPushBindAddress => self.loki_push_bind_address.to_string(),
            Setting::StorageDataDirectory => self.data_directory.clone(),
            Setting::StorageSecretsDirectory => self.secrets_directory.clone(),
            Setting::ExportDestinations => self.redacted_export_destinations(),
        }
    }

    fn redacted_export_destinations(&self) -> String {
        let mut rendered = String::new();
        for (index, destination) in self.export_destinations.iter().enumerate() {
            if index != 0 {
                rendered.push(',');
            }
            rendered.push_str(&destination.name);
            rendered.push(':');
            rendered.push_str(&hexadecimal_identity(destination.identity));
        }
        rendered
    }
}

fn hexadecimal_identity(identity: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(32);
    for byte in identity {
        rendered.push(char::from(HEX[usize::from(byte >> 4)]));
        rendered.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    rendered
}

impl Debug for EffectiveConfiguration {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectiveConfiguration")
            .field("schema_version", &self.schema_version)
            .field("log_level", &self.log_level)
            .field("shutdown_grace_seconds", &self.shutdown_grace_seconds)
            .field("max_registered_tenants", &self.max_registered_tenants)
            .field("control_path", &self.control_path)
            .field("operations_bind_address", &self.operations_bind_address)
            .field("api_bind_address", &self.api_bind_address)
            .field("api_transport", &self.api_transport)
            .field("security_warnings", &self.security_warnings())
            .field("otlp_grpc_bind_address", &self.otlp_grpc_bind_address)
            .field("otlp_http_bind_address", &self.otlp_http_bind_address)
            .field("loki_push_bind_address", &self.loki_push_bind_address)
            .field("data_directory", &self.data_directory)
            .field("secrets_directory", &self.secrets_directory)
            .field("local_key_file", &"<redacted>")
            .field("export_destination_count", &self.export_destinations.len())
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

/// One redacted, provenance-bearing semantic setting difference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationChange {
    setting: Setting,
    before: String,
    after: String,
    before_source: Option<SettingSource>,
    after_source: Option<SettingSource>,
}

impl ConfigurationChange {
    #[must_use]
    pub const fn setting(&self) -> Setting {
        self.setting
    }

    #[must_use]
    pub fn before(&self) -> &str {
        &self.before
    }

    #[must_use]
    pub fn after(&self) -> &str {
        &self.after
    }

    #[must_use]
    pub const fn before_source(&self) -> Option<SettingSource> {
        self.before_source
    }

    #[must_use]
    pub const fn after_source(&self) -> Option<SettingSource> {
        self.after_source
    }
}

/// The lifecycle treatment derived from a complete semantic difference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationDiffPlan {
    NoChange,
    PublishLive,
    DrainThenPublish,
    RestartRequired,
    RequiresMigration,
}

impl ConfigurationDiffPlan {
    fn from_changes(changes: &[ConfigurationChange]) -> Self {
        if changes.is_empty() {
            return Self::NoChange;
        }
        if changes.iter().any(|change| {
            change.setting().mutability() == MutabilityClass::ImmutableAfterInitialization
        }) {
            return Self::RequiresMigration;
        }
        if changes
            .iter()
            .any(|change| change.setting().mutability() == MutabilityClass::RestartRequired)
        {
            return Self::RestartRequired;
        }
        if changes
            .iter()
            .any(|change| change.setting().mutability() == MutabilityClass::DrainAndReload)
        {
            return Self::DrainThenPublish;
        }
        Self::PublishLive
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoChange => "no_change",
            Self::PublishLive => "publish_live",
            Self::DrainThenPublish => "drain_then_publish",
            Self::RestartRequired => "restart_required",
            Self::RequiresMigration => "requires_migration",
        }
    }
}

/// The complete deterministic semantic difference and its lifecycle plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationDiff {
    changes: Vec<ConfigurationChange>,
    plan: ConfigurationDiffPlan,
}

impl ConfigurationDiff {
    #[must_use]
    pub fn changes(&self) -> &[ConfigurationChange] {
        &self.changes
    }

    #[must_use]
    pub const fn plan(&self) -> ConfigurationDiffPlan {
        self.plan
    }
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
