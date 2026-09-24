//! Canonical, bounded Configuration Contract resolution for Positron.
//!
//! This boundary resolves compiled defaults, one canonical TOML document,
//! environment overrides, and command-line overrides into checked native
//! values. It owns source provenance, secrecy, validation, mutability, and
//! deterministic schema/reference generation. Runtime publication and live
//! reload remain M4-owned work.

#![forbid(unsafe_code)]

use std::{
    fs::{File, OpenOptions},
    io::Write,
    net::{IpAddr, SocketAddr},
    num::NonZeroU8,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rustix::fs::{CWD, RenameFlags, renameat_with};

pub use positron_domain::identity::TenantId;

const MAX_CONFIGURATION_BYTES: usize = 16 * 1024;
const MAX_OVERRIDE_PAIRS: usize = 16;
const MAX_TOML_ENTRIES: usize = 64;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 256;
const MAX_CANDIDATE_TEMPORARY_ATTEMPTS: u64 = 32;
static NEXT_CANDIDATE_TEMPORARY: AtomicU64 = AtomicU64::new(0);

mod contract;
mod settings;
pub use settings::*;
mod values;
pub use values::*;
mod inputs;
pub use inputs::*;
mod effective;
pub use effective::*;
mod rendering;
pub use rendering::*;

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

/// Failure while writing a separately named, current-schema configuration candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationCandidateFailure {
    Input(ConfigurationInputFailure),
    Configuration(ConfigurationFailure),
    DestinationExists,
    DestinationUnavailable,
    CleanupFailed,
}

/// Validates one source document and writes its current-schema candidate without
/// allowing source precedence inputs to alter the persisted document.
///
/// The current Release 1 schema is version 1. Preserving its validated bytes
/// avoids inventing a transform, materializing defaults, or replacing protected
/// references with redaction markers. The destination is published only after
/// the candidate has been fully written and synced, and it is never replaced.
pub fn write_current_schema_candidate(
    source: &Path,
    destination: &Path,
) -> Result<EffectiveConfiguration, ConfigurationCandidateFailure> {
    let inputs = ConfigurationInputs::try_from_sources(
        Some(source),
        [] as [(&str, &str); 0],
        [] as [(&str, &str); 0],
    )
    .map_err(ConfigurationCandidateFailure::Input)?;
    let effective =
        resolve(inputs.clone()).map_err(ConfigurationCandidateFailure::Configuration)?;
    let document = inputs
        .file
        .as_deref()
        .ok_or(ConfigurationCandidateFailure::DestinationUnavailable)?;
    write_candidate_document(destination, document)?;
    Ok(effective)
}

fn write_candidate_document(
    destination: &Path,
    document: &str,
) -> Result<(), ConfigurationCandidateFailure> {
    let (temporary, mut file) = create_temporary_candidate(destination)?;
    let write_result = file
        .write_all(document.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if write_result.is_err() {
        return remove_temporary_candidate(&temporary)
            .and(Err(ConfigurationCandidateFailure::DestinationUnavailable));
    }
    match renameat_with(CWD, &temporary, CWD, destination, RenameFlags::NOREPLACE) {
        Ok(()) => sync_candidate_parent(destination),
        Err(error) => {
            let failure = if error.kind() == std::io::ErrorKind::AlreadyExists {
                ConfigurationCandidateFailure::DestinationExists
            } else {
                ConfigurationCandidateFailure::DestinationUnavailable
            };
            remove_temporary_candidate(&temporary).and(Err(failure))
        },
    }
}

fn sync_candidate_parent(destination: &Path) -> Result<(), ConfigurationCandidateFailure> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ConfigurationCandidateFailure::DestinationUnavailable)
}

fn create_temporary_candidate(
    destination: &Path,
) -> Result<(PathBuf, std::fs::File), ConfigurationCandidateFailure> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    for _ in 0..MAX_CANDIDATE_TEMPORARY_ATTEMPTS {
        let sequence = NEXT_CANDIDATE_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".positron-config-candidate-{}-{sequence}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(_) => return Err(ConfigurationCandidateFailure::DestinationUnavailable),
        }
    }
    Err(ConfigurationCandidateFailure::DestinationUnavailable)
}

fn remove_temporary_candidate(path: &Path) -> Result<(), ConfigurationCandidateFailure> {
    std::fs::remove_file(path).map_err(|_| ConfigurationCandidateFailure::CleanupFailed)
}

/// Returns the generated canonical JSON Schema.
#[must_use]
pub fn generated_json_schema() -> String {
    render_json_schema()
}

/// Returns the generated operator/reference documentation without secrets.
#[must_use]
pub fn generated_reference() -> String {
    render_reference()
}

/// Returns the generated public-only example configuration.
#[must_use]
pub fn generated_example() -> String {
    render_example()
}

/// Returns the contract definition for a canonical setting path.
#[must_use]
pub fn setting_for_path(path: &str) -> Option<Setting> {
    contract::SETTING_DEFINITIONS
        .into_iter()
        .find(|definition| definition.path() == path)
        .map(SettingDefinition::setting)
}

/// Returns the complete canonical contract in deterministic declaration order.
#[must_use]
pub const fn setting_definitions() -> [SettingDefinition; 32] {
    contract::SETTING_DEFINITIONS
}

mod source;
use source::{apply_command_line, apply_environment, apply_toml};

#[derive(Clone)]
struct Candidate {
    schema_version: u16,
    log_level: LogLevel,
    shutdown_grace_seconds: u16,
    max_registered_tenants: u16,
    control_path: String,
    operations_bind_address: SocketAddr,
    operations_transport: NetworkTransport,
    operations_trusted_proxy_cidrs: Vec<String>,
    operations_forwarded_hops: Option<NonZeroU8>,
    api_bind_address: SocketAddr,
    api_transport: ApiTransport,
    api_trusted_proxy_cidrs: Vec<String>,
    api_forwarded_hops: Option<NonZeroU8>,
    api_tls_certificate_file: ProtectedFileReference,
    api_tls_private_key_file: ProtectedFileReference,
    tls_client_ca_file: ProtectedFileReference,
    otlp_grpc_bind_address: SocketAddr,
    otlp_grpc_transport: NetworkTransport,
    otlp_grpc_trusted_proxy_cidrs: Vec<String>,
    otlp_grpc_forwarded_hops: Option<NonZeroU8>,
    otlp_http_bind_address: SocketAddr,
    otlp_http_transport: NetworkTransport,
    otlp_http_trusted_proxy_cidrs: Vec<String>,
    otlp_http_forwarded_hops: Option<NonZeroU8>,
    loki_push_bind_address: SocketAddr,
    loki_push_transport: NetworkTransport,
    loki_push_trusted_proxy_cidrs: Vec<String>,
    loki_push_forwarded_hops: Option<NonZeroU8>,
    data_directory: String,
    secrets_directory: String,
    local_key_file: ProtectedFileReference,
    export_destinations: Vec<ExportDestinationDefinition>,
    sources: [SettingSource; 32],
}

impl Candidate {
    fn defaults() -> Result<Self, ConfigurationFailure> {
        let schema_version = setting_definition(Setting::SchemaVersion).default_value();
        let log_level = setting_definition(Setting::DiagnosticsLogLevel).default_value();
        let shutdown = setting_definition(Setting::RuntimeShutdownGraceSeconds).default_value();
        let max_registered_tenants =
            setting_definition(Setting::RuntimeMaxRegisteredTenants).default_value();
        let control = setting_definition(Setting::ListenerControlPath).default_value();
        let operations = setting_definition(Setting::ListenerOperationsBindAddress).default_value();
        let operations_transport =
            setting_definition(Setting::ListenerOperationsTransport).default_value();
        let api = setting_definition(Setting::ListenerApiBindAddress).default_value();
        let api_transport = setting_definition(Setting::ListenerApiTransport).default_value();
        let api_certificate =
            setting_definition(Setting::ListenerApiTlsCertificateFile).default_value();
        let api_private_key =
            setting_definition(Setting::ListenerApiTlsPrivateKeyFile).default_value();
        let tls_client_ca = setting_definition(Setting::ListenerTlsClientCaFile).default_value();
        let otlp_grpc = setting_definition(Setting::ListenerOtlpGrpcBindAddress).default_value();
        let otlp_grpc_transport =
            setting_definition(Setting::ListenerOtlpGrpcTransport).default_value();
        let otlp_http = setting_definition(Setting::ListenerOtlpHttpBindAddress).default_value();
        let otlp_http_transport =
            setting_definition(Setting::ListenerOtlpHttpTransport).default_value();
        let loki_push = setting_definition(Setting::ListenerLokiPushBindAddress).default_value();
        let loki_push_transport =
            setting_definition(Setting::ListenerLokiPushTransport).default_value();
        let data = setting_definition(Setting::StorageDataDirectory).default_value();
        let secrets = setting_definition(Setting::StorageSecretsDirectory).default_value();
        let local_key = setting_definition(Setting::SecurityLocalKeyFile).default_value();
        Ok(Self {
            schema_version: parse_schema_version(schema_version)?,
            log_level: LogLevel::parse(log_level)?,
            shutdown_grace_seconds: parse_shutdown_grace_seconds(shutdown)?,
            max_registered_tenants: parse_max_registered_tenants(max_registered_tenants)?,
            control_path: checked_path(control, Setting::ListenerControlPath)?,
            operations_bind_address: parse_socket_address(
                operations,
                Setting::ListenerOperationsBindAddress,
            )?,
            operations_transport: NetworkTransport::parse(
                operations_transport,
                FailureSource::ListenerOperationsTransport,
            )?,
            operations_trusted_proxy_cidrs: Vec::new(),
            operations_forwarded_hops: None,
            api_bind_address: parse_socket_address(api, Setting::ListenerApiBindAddress)?,
            api_transport: ApiTransport::parse(api_transport)?,
            api_trusted_proxy_cidrs: Vec::new(),
            api_forwarded_hops: None,
            api_tls_certificate_file: ProtectedFileReference::parse(
                api_certificate,
                Setting::ListenerApiTlsCertificateFile,
            )?,
            api_tls_private_key_file: ProtectedFileReference::parse(
                api_private_key,
                Setting::ListenerApiTlsPrivateKeyFile,
            )?,
            tls_client_ca_file: ProtectedFileReference::parse(
                tls_client_ca,
                Setting::ListenerTlsClientCaFile,
            )?,
            otlp_grpc_bind_address: parse_socket_address(
                otlp_grpc,
                Setting::ListenerOtlpGrpcBindAddress,
            )?,
            otlp_grpc_transport: NetworkTransport::parse(
                otlp_grpc_transport,
                FailureSource::ListenerOtlpGrpcTransport,
            )?,
            otlp_grpc_trusted_proxy_cidrs: Vec::new(),
            otlp_grpc_forwarded_hops: None,
            otlp_http_bind_address: parse_socket_address(
                otlp_http,
                Setting::ListenerOtlpHttpBindAddress,
            )?,
            otlp_http_transport: NetworkTransport::parse(
                otlp_http_transport,
                FailureSource::ListenerOtlpHttpTransport,
            )?,
            otlp_http_trusted_proxy_cidrs: Vec::new(),
            otlp_http_forwarded_hops: None,
            loki_push_bind_address: parse_socket_address(
                loki_push,
                Setting::ListenerLokiPushBindAddress,
            )?,
            loki_push_transport: NetworkTransport::parse(
                loki_push_transport,
                FailureSource::ListenerLokiPushTransport,
            )?,
            loki_push_trusted_proxy_cidrs: Vec::new(),
            loki_push_forwarded_hops: None,
            data_directory: checked_path(data, Setting::StorageDataDirectory)?,
            secrets_directory: checked_path(secrets, Setting::StorageSecretsDirectory)?,
            local_key_file: ProtectedFileReference::parse(
                local_key,
                Setting::SecurityLocalKeyFile,
            )?,
            export_destinations: Vec::new(),
            sources: [SettingSource::CompiledDefault; 32],
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
            Setting::RuntimeMaxRegisteredTenants => {
                self.max_registered_tenants = parse_max_registered_tenants(value)?;
            },
            Setting::ListenerControlPath => {
                self.control_path = checked_path(value, setting)?;
            },
            Setting::ListenerOperationsBindAddress => {
                self.operations_bind_address = parse_socket_address(value, setting)?;
            },
            Setting::ListenerOperationsTransport => {
                self.operations_transport =
                    NetworkTransport::parse(value, FailureSource::ListenerOperationsTransport)?;
            },
            Setting::ListenerOperationsForwardedHops => {
                self.operations_forwarded_hops = parse_forwarded_hops(value, setting)?;
            },
            Setting::ListenerApiBindAddress => {
                self.api_bind_address = parse_socket_address(value, setting)?;
            },
            Setting::ListenerApiTransport => {
                self.api_transport = ApiTransport::parse(value)?;
            },
            Setting::ListenerApiForwardedHops => {
                self.api_forwarded_hops = parse_forwarded_hops(value, setting)?;
            },
            Setting::ListenerApiTlsCertificateFile => {
                self.api_tls_certificate_file = ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerApiTlsPrivateKeyFile => {
                self.api_tls_private_key_file = ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerTlsClientCaFile => {
                self.tls_client_ca_file = ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerOtlpGrpcBindAddress => {
                self.otlp_grpc_bind_address = parse_socket_address(value, setting)?;
            },
            Setting::ListenerOtlpGrpcTransport => {
                self.otlp_grpc_transport =
                    NetworkTransport::parse(value, FailureSource::ListenerOtlpGrpcTransport)?;
            },
            Setting::ListenerOtlpGrpcForwardedHops => {
                self.otlp_grpc_forwarded_hops = parse_forwarded_hops(value, setting)?;
            },
            Setting::ListenerOtlpHttpBindAddress => {
                self.otlp_http_bind_address = parse_socket_address(value, setting)?;
            },
            Setting::ListenerOtlpHttpTransport => {
                self.otlp_http_transport =
                    NetworkTransport::parse(value, FailureSource::ListenerOtlpHttpTransport)?;
            },
            Setting::ListenerOtlpHttpForwardedHops => {
                self.otlp_http_forwarded_hops = parse_forwarded_hops(value, setting)?;
            },
            Setting::ListenerLokiPushBindAddress => {
                self.loki_push_bind_address = parse_socket_address(value, setting)?;
            },
            Setting::ListenerLokiPushTransport => {
                self.loki_push_transport =
                    NetworkTransport::parse(value, FailureSource::ListenerLokiPushTransport)?;
            },
            Setting::ListenerLokiPushForwardedHops => {
                self.loki_push_forwarded_hops = parse_forwarded_hops(value, setting)?;
            },
            Setting::StorageDataDirectory => {
                self.data_directory = checked_path(value, setting)?;
            },
            Setting::StorageSecretsDirectory => {
                self.secrets_directory = checked_path(value, setting)?;
            },
            Setting::SecurityLocalKeyFile => {
                self.local_key_file = ProtectedFileReference::parse(value, setting)?
            },
            Setting::ListenerOperationsTrustedProxyCidrs
            | Setting::ListenerApiTrustedProxyCidrs
            | Setting::ListenerOtlpGrpcTrustedProxyCidrs
            | Setting::ListenerOtlpHttpTrustedProxyCidrs
            | Setting::ListenerLokiPushTrustedProxyCidrs
            | Setting::ExportDestinations => {
                return Err(ConfigurationFailure::new(
                    ConfigurationFailureCode::Malformed,
                    FailureSource::ExportDestinations,
                ));
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

    fn apply_trusted_proxy_cidrs(
        &mut self,
        setting: Setting,
        cidrs: Vec<String>,
    ) -> Result<(), ConfigurationFailure> {
        let destination = match setting {
            Setting::ListenerOperationsTrustedProxyCidrs => {
                &mut self.operations_trusted_proxy_cidrs
            },
            Setting::ListenerApiTrustedProxyCidrs => &mut self.api_trusted_proxy_cidrs,
            Setting::ListenerOtlpGrpcTrustedProxyCidrs => &mut self.otlp_grpc_trusted_proxy_cidrs,
            Setting::ListenerOtlpHttpTrustedProxyCidrs => &mut self.otlp_http_trusted_proxy_cidrs,
            Setting::ListenerLokiPushTrustedProxyCidrs => &mut self.loki_push_trusted_proxy_cidrs,
            _ => {
                return Err(ConfigurationFailure::new(
                    ConfigurationFailureCode::Malformed,
                    failure_source(setting),
                ));
            },
        };
        *destination = cidrs;
        let Some(entry) = self.sources.get_mut(setting_index(setting)) else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::Malformed,
                FailureSource::ConfigurationDocument,
            ));
        };
        *entry = SettingSource::ConfigurationFile;
        Ok(())
    }

    fn apply_export_destinations(
        &mut self,
        destinations: Vec<ExportDestinationDefinition>,
    ) -> Result<(), ConfigurationFailure> {
        self.export_destinations = destinations;
        let Some(entry) = self
            .sources
            .get_mut(setting_index(Setting::ExportDestinations))
        else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::Malformed,
                FailureSource::ConfigurationDocument,
            ));
        };
        *entry = SettingSource::ConfigurationFile;
        Ok(())
    }

    fn validate(self) -> Result<EffectiveConfiguration, ConfigurationFailure> {
        if self.data_directory == self.secrets_directory {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::UnsafeCombination,
                FailureSource::StorageDataDirectory,
            ));
        }
        validate_proxy_trust_pair(
            &self.operations_trusted_proxy_cidrs,
            self.operations_forwarded_hops,
            Setting::ListenerOperationsTrustedProxyCidrs,
            Setting::ListenerOperationsForwardedHops,
        )?;
        validate_proxy_trust_pair(
            &self.api_trusted_proxy_cidrs,
            self.api_forwarded_hops,
            Setting::ListenerApiTrustedProxyCidrs,
            Setting::ListenerApiForwardedHops,
        )?;
        validate_proxy_trust_pair(
            &self.otlp_grpc_trusted_proxy_cidrs,
            self.otlp_grpc_forwarded_hops,
            Setting::ListenerOtlpGrpcTrustedProxyCidrs,
            Setting::ListenerOtlpGrpcForwardedHops,
        )?;
        validate_proxy_trust_pair(
            &self.otlp_http_trusted_proxy_cidrs,
            self.otlp_http_forwarded_hops,
            Setting::ListenerOtlpHttpTrustedProxyCidrs,
            Setting::ListenerOtlpHttpForwardedHops,
        )?;
        validate_proxy_trust_pair(
            &self.loki_push_trusted_proxy_cidrs,
            self.loki_push_forwarded_hops,
            Setting::ListenerLokiPushTrustedProxyCidrs,
            Setting::ListenerLokiPushForwardedHops,
        )?;
        Ok(EffectiveConfiguration {
            schema_version: self.schema_version,
            log_level: self.log_level,
            shutdown_grace_seconds: self.shutdown_grace_seconds,
            max_registered_tenants: self.max_registered_tenants,
            control_path: self.control_path,
            operations_bind_address: self.operations_bind_address,
            operations_transport: self.operations_transport,
            operations_trusted_proxy_cidrs: self.operations_trusted_proxy_cidrs,
            operations_forwarded_hops: self.operations_forwarded_hops,
            api_bind_address: self.api_bind_address,
            api_transport: self.api_transport,
            api_trusted_proxy_cidrs: self.api_trusted_proxy_cidrs,
            api_forwarded_hops: self.api_forwarded_hops,
            api_tls_certificate_file: self.api_tls_certificate_file,
            api_tls_private_key_file: self.api_tls_private_key_file,
            tls_client_ca_file: self.tls_client_ca_file,
            otlp_grpc_bind_address: self.otlp_grpc_bind_address,
            otlp_grpc_transport: self.otlp_grpc_transport,
            otlp_grpc_trusted_proxy_cidrs: self.otlp_grpc_trusted_proxy_cidrs,
            otlp_grpc_forwarded_hops: self.otlp_grpc_forwarded_hops,
            otlp_http_bind_address: self.otlp_http_bind_address,
            otlp_http_transport: self.otlp_http_transport,
            otlp_http_trusted_proxy_cidrs: self.otlp_http_trusted_proxy_cidrs,
            otlp_http_forwarded_hops: self.otlp_http_forwarded_hops,
            loki_push_bind_address: self.loki_push_bind_address,
            loki_push_transport: self.loki_push_transport,
            loki_push_trusted_proxy_cidrs: self.loki_push_trusted_proxy_cidrs,
            loki_push_forwarded_hops: self.loki_push_forwarded_hops,
            data_directory: self.data_directory,
            secrets_directory: self.secrets_directory,
            local_key_file: self.local_key_file,
            export_destinations: self.export_destinations,
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

fn parse_max_registered_tenants(value: &str) -> Result<u16, ConfigurationFailure> {
    let tenants = parse_canonical_u16(value, FailureSource::RuntimeMaxRegisteredTenants)?;
    let ValueDomain::UnsignedIntegerRange(minimum, maximum) =
        setting_definition(Setting::RuntimeMaxRegisteredTenants).domain()
    else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::RuntimeMaxRegisteredTenants,
        ));
    };
    if !(minimum..=maximum).contains(&tenants) {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::RuntimeMaxRegisteredTenants,
        ));
    }
    Ok(tenants)
}

fn parse_forwarded_hops(
    value: &str,
    setting: Setting,
) -> Result<Option<NonZeroU8>, ConfigurationFailure> {
    let hops = parse_canonical_u16(value, failure_source(setting))?;
    let ValueDomain::UnsignedIntegerRange(minimum, maximum) = setting_definition(setting).domain()
    else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            failure_source(setting),
        ));
    };
    if !(minimum..=maximum).contains(&hops) {
        return Err(ConfigurationFailure::unsupported_value(failure_source(
            setting,
        )));
    }
    let hops = u8::try_from(hops)
        .map_err(|_| ConfigurationFailure::unsupported_value(failure_source(setting)))?;
    Ok(NonZeroU8::new(hops))
}

fn parse_trusted_proxy_cidrs(
    values: &[toml::Value],
    setting: Setting,
) -> Result<Vec<String>, ConfigurationFailure> {
    let ValueDomain::TrustedProxyCidrs(maximum_entries, maximum_entry_bytes) =
        setting_definition(setting).domain()
    else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            failure_source(setting),
        ));
    };
    if values.len() > maximum_entries {
        return Err(ConfigurationFailure::unsupported_value(failure_source(
            setting,
        )));
    }
    let mut cidrs = Vec::with_capacity(values.len());
    for value in values {
        let toml::Value::String(value) = value else {
            return Err(ConfigurationFailure::unsupported_value(failure_source(
                setting,
            )));
        };
        validate_trusted_proxy_cidr(value, maximum_entry_bytes, setting)?;
        cidrs.push(value.clone());
    }
    Ok(cidrs)
}

fn validate_trusted_proxy_cidr(
    value: &str,
    maximum_bytes: usize,
    setting: Setting,
) -> Result<(), ConfigurationFailure> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ConfigurationFailure::unsupported_value(failure_source(
            setting,
        )));
    }
    let Some((address, prefix_text)) = value.split_once('/') else {
        return Err(ConfigurationFailure::unsupported_value(failure_source(
            setting,
        )));
    };
    if prefix_text.is_empty()
        || prefix_text.len() > 3
        || !prefix_text.bytes().all(|byte| byte.is_ascii_digit())
        || (prefix_text.len() > 1 && prefix_text.starts_with('0'))
    {
        return Err(ConfigurationFailure::unsupported_value(failure_source(
            setting,
        )));
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| ConfigurationFailure::unsupported_value(failure_source(setting)))?;
    let prefix = prefix_text
        .parse::<u16>()
        .map_err(|_| ConfigurationFailure::unsupported_value(failure_source(setting)))?;
    let maximum_prefix = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > maximum_prefix {
        return Err(ConfigurationFailure::unsupported_value(failure_source(
            setting,
        )));
    }
    Ok(())
}

fn validate_proxy_trust_pair(
    cidrs: &[String],
    forwarded_hops: Option<NonZeroU8>,
    cidr_setting: Setting,
    hop_setting: Setting,
) -> Result<(), ConfigurationFailure> {
    if cidrs.is_empty() == forwarded_hops.is_none() {
        return Ok(());
    }
    let setting = if cidrs.is_empty() {
        hop_setting
    } else {
        cidr_setting
    };
    Err(ConfigurationFailure::new(
        ConfigurationFailureCode::UnsafeCombination,
        failure_source(setting),
    ))
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

fn parse_socket_address(value: &str, setting: Setting) -> Result<SocketAddr, ConfigurationFailure> {
    let ValueDomain::SocketAddress(_) = setting_definition(setting).domain() else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            failure_source(setting),
        ));
    };
    value.parse::<SocketAddr>().map_err(|_| {
        ConfigurationFailure::new(ConfigurationFailureCode::Malformed, failure_source(setting))
    })
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
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::UnsafeCombination,
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
        Setting::RuntimeMaxRegisteredTenants => 3,
        Setting::ListenerControlPath => 4,
        Setting::ListenerOperationsBindAddress => 5,
        Setting::ListenerOperationsTransport => 6,
        Setting::ListenerOperationsTrustedProxyCidrs => 7,
        Setting::ListenerOperationsForwardedHops => 8,
        Setting::ListenerApiBindAddress => 9,
        Setting::ListenerApiTransport => 10,
        Setting::ListenerApiTrustedProxyCidrs => 11,
        Setting::ListenerApiForwardedHops => 12,
        Setting::ListenerApiTlsCertificateFile => 13,
        Setting::ListenerApiTlsPrivateKeyFile => 14,
        Setting::ListenerTlsClientCaFile => 15,
        Setting::ListenerOtlpGrpcBindAddress => 16,
        Setting::ListenerOtlpGrpcTransport => 17,
        Setting::ListenerOtlpGrpcTrustedProxyCidrs => 18,
        Setting::ListenerOtlpGrpcForwardedHops => 19,
        Setting::ListenerOtlpHttpBindAddress => 20,
        Setting::ListenerOtlpHttpTransport => 21,
        Setting::ListenerOtlpHttpTrustedProxyCidrs => 22,
        Setting::ListenerOtlpHttpForwardedHops => 23,
        Setting::ListenerLokiPushBindAddress => 24,
        Setting::ListenerLokiPushTransport => 25,
        Setting::ListenerLokiPushTrustedProxyCidrs => 26,
        Setting::ListenerLokiPushForwardedHops => 27,
        Setting::StorageDataDirectory => 28,
        Setting::StorageSecretsDirectory => 29,
        Setting::SecurityLocalKeyFile => 30,
        Setting::ExportDestinations => 31,
    }
}

const fn failure_source(setting: Setting) -> FailureSource {
    match setting {
        Setting::SchemaVersion => FailureSource::SchemaVersion,
        Setting::DiagnosticsLogLevel => FailureSource::DiagnosticsLogLevel,
        Setting::RuntimeShutdownGraceSeconds => FailureSource::RuntimeShutdownGraceSeconds,
        Setting::RuntimeMaxRegisteredTenants => FailureSource::RuntimeMaxRegisteredTenants,
        Setting::ListenerControlPath => FailureSource::ListenerControlPath,
        Setting::ListenerOperationsBindAddress => FailureSource::ListenerOperationsBindAddress,
        Setting::ListenerOperationsTransport => FailureSource::ListenerOperationsTransport,
        Setting::ListenerOperationsTrustedProxyCidrs => {
            FailureSource::ListenerOperationsTrustedProxyCidrs
        },
        Setting::ListenerOperationsForwardedHops => FailureSource::ListenerOperationsForwardedHops,
        Setting::ListenerApiBindAddress => FailureSource::ListenerApiBindAddress,
        Setting::ListenerApiTransport => FailureSource::ListenerApiTransport,
        Setting::ListenerApiTrustedProxyCidrs => FailureSource::ListenerApiTrustedProxyCidrs,
        Setting::ListenerApiForwardedHops => FailureSource::ListenerApiForwardedHops,
        Setting::ListenerApiTlsCertificateFile => FailureSource::ListenerApiTlsCertificateFile,
        Setting::ListenerApiTlsPrivateKeyFile => FailureSource::ListenerApiTlsPrivateKeyFile,
        Setting::ListenerTlsClientCaFile => FailureSource::ListenerTlsClientCaFile,
        Setting::ListenerOtlpGrpcBindAddress => FailureSource::ListenerOtlpGrpcBindAddress,
        Setting::ListenerOtlpGrpcTransport => FailureSource::ListenerOtlpGrpcTransport,
        Setting::ListenerOtlpGrpcTrustedProxyCidrs => {
            FailureSource::ListenerOtlpGrpcTrustedProxyCidrs
        },
        Setting::ListenerOtlpGrpcForwardedHops => FailureSource::ListenerOtlpGrpcForwardedHops,
        Setting::ListenerOtlpHttpBindAddress => FailureSource::ListenerOtlpHttpBindAddress,
        Setting::ListenerOtlpHttpTransport => FailureSource::ListenerOtlpHttpTransport,
        Setting::ListenerOtlpHttpTrustedProxyCidrs => {
            FailureSource::ListenerOtlpHttpTrustedProxyCidrs
        },
        Setting::ListenerOtlpHttpForwardedHops => FailureSource::ListenerOtlpHttpForwardedHops,
        Setting::ListenerLokiPushBindAddress => FailureSource::ListenerLokiPushBindAddress,
        Setting::ListenerLokiPushTransport => FailureSource::ListenerLokiPushTransport,
        Setting::ListenerLokiPushTrustedProxyCidrs => {
            FailureSource::ListenerLokiPushTrustedProxyCidrs
        },
        Setting::ListenerLokiPushForwardedHops => FailureSource::ListenerLokiPushForwardedHops,
        Setting::StorageDataDirectory => FailureSource::StorageDataDirectory,
        Setting::StorageSecretsDirectory => FailureSource::StorageSecretsDirectory,
        Setting::SecurityLocalKeyFile => FailureSource::SecurityLocalKeyFile,
        Setting::ExportDestinations => FailureSource::ExportDestinations,
    }
}
