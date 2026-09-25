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
    num::{NonZeroU8, NonZeroU16, NonZeroU32},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rustix::fs::{CWD, RenameFlags, renameat_with};

pub use positron_domain::identity::TenantId;

const MAX_CONFIGURATION_BYTES: usize = 16 * 1024;
const MAX_OVERRIDE_PAIRS: usize = 16;
// The generated public example includes every public setting and nested
// listener-policy table. Keep enough bounded headroom for the canonical
// configuration contract without admitting an unbounded document shape.
const MAX_TOML_ENTRIES: usize = 128;
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
pub const fn setting_definitions() -> [SettingDefinition; 97] {
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
    operations_accepted_socket_limit: NonZeroU16,
    operations_per_address_accepted_socket_limit: NonZeroU16,
    operations_connection_protection: ConnectionProtectionProfile,
    operations_tls_certificate_file: ProtectedFileReference,
    operations_tls_private_key_file: ProtectedFileReference,
    operations_tls_client_ca_file: ProtectedFileReference,
    operations_trusted_proxy_cidrs: Vec<String>,
    operations_forwarded_hops: Option<NonZeroU8>,
    api_bind_address: SocketAddr,
    api_transport: ApiTransport,
    api_accepted_socket_limit: NonZeroU16,
    api_per_address_accepted_socket_limit: NonZeroU16,
    api_connection_protection: ConnectionProtectionProfile,
    api_http2_profile: Http2Profile,
    api_trusted_proxy_cidrs: Vec<String>,
    api_forwarded_hops: Option<NonZeroU8>,
    api_tls_certificate_file: ProtectedFileReference,
    api_tls_private_key_file: ProtectedFileReference,
    api_tls_client_ca_file: ProtectedFileReference,
    otlp_grpc_bind_address: SocketAddr,
    otlp_grpc_transport: NetworkTransport,
    otlp_grpc_accepted_socket_limit: NonZeroU16,
    otlp_grpc_per_address_accepted_socket_limit: NonZeroU16,
    otlp_grpc_connection_protection: ConnectionProtectionProfile,
    otlp_grpc_http2_profile: Http2Profile,
    otlp_grpc_tls_certificate_file: ProtectedFileReference,
    otlp_grpc_tls_private_key_file: ProtectedFileReference,
    otlp_grpc_tls_client_ca_file: ProtectedFileReference,
    otlp_grpc_trusted_proxy_cidrs: Vec<String>,
    otlp_grpc_forwarded_hops: Option<NonZeroU8>,
    otlp_http_bind_address: SocketAddr,
    otlp_http_transport: NetworkTransport,
    otlp_http_accepted_socket_limit: NonZeroU16,
    otlp_http_per_address_accepted_socket_limit: NonZeroU16,
    otlp_http_connection_protection: ConnectionProtectionProfile,
    otlp_http_tls_certificate_file: ProtectedFileReference,
    otlp_http_tls_private_key_file: ProtectedFileReference,
    otlp_http_tls_client_ca_file: ProtectedFileReference,
    otlp_http_trusted_proxy_cidrs: Vec<String>,
    otlp_http_forwarded_hops: Option<NonZeroU8>,
    loki_push_bind_address: SocketAddr,
    loki_push_transport: NetworkTransport,
    loki_push_accepted_socket_limit: NonZeroU16,
    loki_push_per_address_accepted_socket_limit: NonZeroU16,
    loki_push_connection_protection: ConnectionProtectionProfile,
    loki_push_tls_certificate_file: ProtectedFileReference,
    loki_push_tls_private_key_file: ProtectedFileReference,
    loki_push_tls_client_ca_file: ProtectedFileReference,
    loki_push_trusted_proxy_cidrs: Vec<String>,
    loki_push_forwarded_hops: Option<NonZeroU8>,
    data_directory: String,
    secrets_directory: String,
    local_key_file: ProtectedFileReference,
    export_destinations: Vec<ExportDestinationDefinition>,
    sources: [SettingSource; 97],
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
            operations_accepted_socket_limit: parse_accepted_socket_limit(
                setting_definition(Setting::ListenerOperationsAcceptedSocketLimit).default_value(),
                Setting::ListenerOperationsAcceptedSocketLimit,
            )?,
            operations_per_address_accepted_socket_limit: parse_accepted_socket_limit(
                setting_definition(Setting::ListenerOperationsPerAddressAcceptedSocketLimit)
                    .default_value(),
                Setting::ListenerOperationsPerAddressAcceptedSocketLimit,
            )?,
            operations_connection_protection: default_connection_protection([
                Setting::ListenerOperationsTlsHandshakeLimit,
                Setting::ListenerOperationsTlsHandshakeDeadlineSeconds,
                Setting::ListenerOperationsHeaderDeadlineSeconds,
                Setting::ListenerOperationsBodyDeadlineSeconds,
                Setting::ListenerOperationsRequestDeadlineSeconds,
                Setting::ListenerOperationsIdleDeadlineSeconds,
            ])?,
            operations_tls_certificate_file: default_protected_reference(
                Setting::ListenerOperationsTlsCertificateFile,
            )?,
            operations_tls_private_key_file: default_protected_reference(
                Setting::ListenerOperationsTlsPrivateKeyFile,
            )?,
            operations_tls_client_ca_file: default_protected_reference(
                Setting::ListenerOperationsTlsClientCaFile,
            )?,
            operations_trusted_proxy_cidrs: Vec::new(),
            operations_forwarded_hops: None,
            api_bind_address: parse_socket_address(api, Setting::ListenerApiBindAddress)?,
            api_transport: ApiTransport::parse(api_transport)?,
            api_accepted_socket_limit: parse_accepted_socket_limit(
                setting_definition(Setting::ListenerApiAcceptedSocketLimit).default_value(),
                Setting::ListenerApiAcceptedSocketLimit,
            )?,
            api_per_address_accepted_socket_limit: parse_accepted_socket_limit(
                setting_definition(Setting::ListenerApiPerAddressAcceptedSocketLimit)
                    .default_value(),
                Setting::ListenerApiPerAddressAcceptedSocketLimit,
            )?,
            api_trusted_proxy_cidrs: Vec::new(),
            api_forwarded_hops: None,
            api_connection_protection: default_connection_protection([
                Setting::ListenerApiTlsHandshakeLimit,
                Setting::ListenerApiTlsHandshakeDeadlineSeconds,
                Setting::ListenerApiHeaderDeadlineSeconds,
                Setting::ListenerApiBodyDeadlineSeconds,
                Setting::ListenerApiRequestDeadlineSeconds,
                Setting::ListenerApiIdleDeadlineSeconds,
            ])?,
            api_http2_profile: default_http2_profile(
                [
                    Setting::ListenerApiHttp2MaxConcurrentStreams,
                    Setting::ListenerApiHttp2InitialStreamWindowBytes,
                    Setting::ListenerApiHttp2InitialConnectionWindowBytes,
                    Setting::ListenerApiHttp2MaxFrameBytes,
                    Setting::ListenerApiHttp2MaxHeaderListBytes,
                    Setting::ListenerApiHttp2MinimumPingIntervalSeconds,
                ],
                None,
            )?,
            api_tls_certificate_file: ProtectedFileReference::parse(
                api_certificate,
                Setting::ListenerApiTlsCertificateFile,
            )?,
            api_tls_private_key_file: ProtectedFileReference::parse(
                api_private_key,
                Setting::ListenerApiTlsPrivateKeyFile,
            )?,
            api_tls_client_ca_file: default_protected_reference(
                Setting::ListenerApiTlsClientCaFile,
            )?,
            otlp_grpc_bind_address: parse_socket_address(
                otlp_grpc,
                Setting::ListenerOtlpGrpcBindAddress,
            )?,
            otlp_grpc_transport: NetworkTransport::parse(
                otlp_grpc_transport,
                FailureSource::ListenerOtlpGrpcTransport,
            )?,
            otlp_grpc_accepted_socket_limit: parse_accepted_socket_limit(
                setting_definition(Setting::ListenerOtlpGrpcAcceptedSocketLimit).default_value(),
                Setting::ListenerOtlpGrpcAcceptedSocketLimit,
            )?,
            otlp_grpc_per_address_accepted_socket_limit: parse_accepted_socket_limit(
                setting_definition(Setting::ListenerOtlpGrpcPerAddressAcceptedSocketLimit)
                    .default_value(),
                Setting::ListenerOtlpGrpcPerAddressAcceptedSocketLimit,
            )?,
            otlp_grpc_connection_protection: default_connection_protection([
                Setting::ListenerOtlpGrpcTlsHandshakeLimit,
                Setting::ListenerOtlpGrpcTlsHandshakeDeadlineSeconds,
                Setting::ListenerOtlpGrpcHeaderDeadlineSeconds,
                Setting::ListenerOtlpGrpcBodyDeadlineSeconds,
                Setting::ListenerOtlpGrpcRequestDeadlineSeconds,
                Setting::ListenerOtlpGrpcIdleDeadlineSeconds,
            ])?,
            otlp_grpc_http2_profile: default_http2_profile(
                [
                    Setting::ListenerOtlpGrpcHttp2MaxConcurrentStreams,
                    Setting::ListenerOtlpGrpcHttp2InitialStreamWindowBytes,
                    Setting::ListenerOtlpGrpcHttp2InitialConnectionWindowBytes,
                    Setting::ListenerOtlpGrpcHttp2MaxFrameBytes,
                    Setting::ListenerOtlpGrpcHttp2MaxHeaderListBytes,
                    Setting::ListenerOtlpGrpcHttp2MinimumPingIntervalSeconds,
                ],
                Some(Setting::ListenerOtlpGrpcMaxMessageBytes),
            )?,
            otlp_grpc_tls_certificate_file: default_protected_reference(
                Setting::ListenerOtlpGrpcTlsCertificateFile,
            )?,
            otlp_grpc_tls_private_key_file: default_protected_reference(
                Setting::ListenerOtlpGrpcTlsPrivateKeyFile,
            )?,
            otlp_grpc_tls_client_ca_file: default_protected_reference(
                Setting::ListenerOtlpGrpcTlsClientCaFile,
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
            otlp_http_accepted_socket_limit: parse_accepted_socket_limit(
                setting_definition(Setting::ListenerOtlpHttpAcceptedSocketLimit).default_value(),
                Setting::ListenerOtlpHttpAcceptedSocketLimit,
            )?,
            otlp_http_per_address_accepted_socket_limit: parse_accepted_socket_limit(
                setting_definition(Setting::ListenerOtlpHttpPerAddressAcceptedSocketLimit)
                    .default_value(),
                Setting::ListenerOtlpHttpPerAddressAcceptedSocketLimit,
            )?,
            otlp_http_connection_protection: default_connection_protection([
                Setting::ListenerOtlpHttpTlsHandshakeLimit,
                Setting::ListenerOtlpHttpTlsHandshakeDeadlineSeconds,
                Setting::ListenerOtlpHttpHeaderDeadlineSeconds,
                Setting::ListenerOtlpHttpBodyDeadlineSeconds,
                Setting::ListenerOtlpHttpRequestDeadlineSeconds,
                Setting::ListenerOtlpHttpIdleDeadlineSeconds,
            ])?,
            otlp_http_tls_certificate_file: default_protected_reference(
                Setting::ListenerOtlpHttpTlsCertificateFile,
            )?,
            otlp_http_tls_private_key_file: default_protected_reference(
                Setting::ListenerOtlpHttpTlsPrivateKeyFile,
            )?,
            otlp_http_tls_client_ca_file: default_protected_reference(
                Setting::ListenerOtlpHttpTlsClientCaFile,
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
            loki_push_accepted_socket_limit: parse_accepted_socket_limit(
                setting_definition(Setting::ListenerLokiPushAcceptedSocketLimit).default_value(),
                Setting::ListenerLokiPushAcceptedSocketLimit,
            )?,
            loki_push_per_address_accepted_socket_limit: parse_accepted_socket_limit(
                setting_definition(Setting::ListenerLokiPushPerAddressAcceptedSocketLimit)
                    .default_value(),
                Setting::ListenerLokiPushPerAddressAcceptedSocketLimit,
            )?,
            loki_push_connection_protection: default_connection_protection([
                Setting::ListenerLokiPushTlsHandshakeLimit,
                Setting::ListenerLokiPushTlsHandshakeDeadlineSeconds,
                Setting::ListenerLokiPushHeaderDeadlineSeconds,
                Setting::ListenerLokiPushBodyDeadlineSeconds,
                Setting::ListenerLokiPushRequestDeadlineSeconds,
                Setting::ListenerLokiPushIdleDeadlineSeconds,
            ])?,
            loki_push_tls_certificate_file: default_protected_reference(
                Setting::ListenerLokiPushTlsCertificateFile,
            )?,
            loki_push_tls_private_key_file: default_protected_reference(
                Setting::ListenerLokiPushTlsPrivateKeyFile,
            )?,
            loki_push_tls_client_ca_file: default_protected_reference(
                Setting::ListenerLokiPushTlsClientCaFile,
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
            sources: [SettingSource::CompiledDefault; 97],
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
            Setting::ListenerOperationsAcceptedSocketLimit => {
                self.operations_accepted_socket_limit =
                    parse_accepted_socket_limit(value, setting)?;
            },
            Setting::ListenerOperationsPerAddressAcceptedSocketLimit => {
                self.operations_per_address_accepted_socket_limit =
                    parse_accepted_socket_limit(value, setting)?;
            },
            Setting::ListenerOperationsTlsHandshakeLimit => {
                self.operations_connection_protection.tls_handshake_limit =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOperationsTlsHandshakeDeadlineSeconds => {
                self.operations_connection_protection
                    .tls_handshake_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOperationsHeaderDeadlineSeconds => {
                self.operations_connection_protection
                    .header_deadline_seconds = parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOperationsBodyDeadlineSeconds => {
                self.operations_connection_protection.body_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOperationsRequestDeadlineSeconds => {
                self.operations_connection_protection
                    .request_deadline_seconds = parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOperationsIdleDeadlineSeconds => {
                self.operations_connection_protection.idle_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOperationsTlsCertificateFile => {
                self.operations_tls_certificate_file =
                    ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerOperationsTlsPrivateKeyFile => {
                self.operations_tls_private_key_file =
                    ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerOperationsTlsClientCaFile => {
                self.operations_tls_client_ca_file = ProtectedFileReference::parse(value, setting)?;
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
            Setting::ListenerApiAcceptedSocketLimit => {
                self.api_accepted_socket_limit = parse_accepted_socket_limit(value, setting)?;
            },
            Setting::ListenerApiPerAddressAcceptedSocketLimit => {
                self.api_per_address_accepted_socket_limit =
                    parse_accepted_socket_limit(value, setting)?;
            },
            Setting::ListenerApiForwardedHops => {
                self.api_forwarded_hops = parse_forwarded_hops(value, setting)?;
            },
            Setting::ListenerApiTlsHandshakeLimit => {
                self.api_connection_protection.tls_handshake_limit =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerApiTlsHandshakeDeadlineSeconds => {
                self.api_connection_protection
                    .tls_handshake_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerApiHeaderDeadlineSeconds => {
                self.api_connection_protection.header_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerApiBodyDeadlineSeconds => {
                self.api_connection_protection.body_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerApiRequestDeadlineSeconds => {
                self.api_connection_protection.request_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerApiIdleDeadlineSeconds => {
                self.api_connection_protection.idle_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerApiHttp2MaxConcurrentStreams => {
                self.api_http2_profile.max_concurrent_streams =
                    parse_http2_stream_limit(value, setting)?;
            },
            Setting::ListenerApiHttp2InitialStreamWindowBytes => {
                self.api_http2_profile.initial_stream_window_bytes =
                    parse_http2_value(value, setting)?;
            },
            Setting::ListenerApiHttp2InitialConnectionWindowBytes => {
                self.api_http2_profile.initial_connection_window_bytes =
                    parse_http2_value(value, setting)?;
            },
            Setting::ListenerApiHttp2MaxFrameBytes => {
                self.api_http2_profile.max_frame_bytes = parse_http2_value(value, setting)?;
            },
            Setting::ListenerApiHttp2MaxHeaderListBytes => {
                self.api_http2_profile.max_header_list_bytes = parse_http2_value(value, setting)?;
            },
            Setting::ListenerApiHttp2MinimumPingIntervalSeconds => {
                self.api_http2_profile.minimum_ping_interval_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerApiTlsCertificateFile => {
                self.api_tls_certificate_file = ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerApiTlsPrivateKeyFile => {
                self.api_tls_private_key_file = ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerApiTlsClientCaFile => {
                self.api_tls_client_ca_file = ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerOtlpGrpcBindAddress => {
                self.otlp_grpc_bind_address = parse_socket_address(value, setting)?;
            },
            Setting::ListenerOtlpGrpcTransport => {
                self.otlp_grpc_transport =
                    NetworkTransport::parse(value, FailureSource::ListenerOtlpGrpcTransport)?;
            },
            Setting::ListenerOtlpGrpcAcceptedSocketLimit => {
                self.otlp_grpc_accepted_socket_limit = parse_accepted_socket_limit(value, setting)?;
            },
            Setting::ListenerOtlpGrpcPerAddressAcceptedSocketLimit => {
                self.otlp_grpc_per_address_accepted_socket_limit =
                    parse_accepted_socket_limit(value, setting)?;
            },
            Setting::ListenerOtlpGrpcTlsHandshakeLimit => {
                self.otlp_grpc_connection_protection.tls_handshake_limit =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpGrpcTlsHandshakeDeadlineSeconds => {
                self.otlp_grpc_connection_protection
                    .tls_handshake_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpGrpcHeaderDeadlineSeconds => {
                self.otlp_grpc_connection_protection.header_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpGrpcBodyDeadlineSeconds => {
                self.otlp_grpc_connection_protection.body_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpGrpcRequestDeadlineSeconds => {
                self.otlp_grpc_connection_protection
                    .request_deadline_seconds = parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpGrpcIdleDeadlineSeconds => {
                self.otlp_grpc_connection_protection.idle_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpGrpcHttp2MaxConcurrentStreams => {
                self.otlp_grpc_http2_profile.max_concurrent_streams =
                    parse_http2_stream_limit(value, setting)?;
            },
            Setting::ListenerOtlpGrpcHttp2InitialStreamWindowBytes => {
                self.otlp_grpc_http2_profile.initial_stream_window_bytes =
                    parse_http2_value(value, setting)?;
            },
            Setting::ListenerOtlpGrpcHttp2InitialConnectionWindowBytes => {
                self.otlp_grpc_http2_profile.initial_connection_window_bytes =
                    parse_http2_value(value, setting)?;
            },
            Setting::ListenerOtlpGrpcHttp2MaxFrameBytes => {
                self.otlp_grpc_http2_profile.max_frame_bytes = parse_http2_value(value, setting)?;
            },
            Setting::ListenerOtlpGrpcHttp2MaxHeaderListBytes => {
                self.otlp_grpc_http2_profile.max_header_list_bytes =
                    parse_http2_value(value, setting)?;
            },
            Setting::ListenerOtlpGrpcHttp2MinimumPingIntervalSeconds => {
                self.otlp_grpc_http2_profile.minimum_ping_interval_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpGrpcMaxMessageBytes => {
                self.otlp_grpc_http2_profile.max_grpc_message_bytes =
                    Some(parse_http2_value(value, setting)?);
            },
            Setting::ListenerOtlpGrpcTlsCertificateFile => {
                self.otlp_grpc_tls_certificate_file =
                    ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerOtlpGrpcTlsPrivateKeyFile => {
                self.otlp_grpc_tls_private_key_file =
                    ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerOtlpGrpcTlsClientCaFile => {
                self.otlp_grpc_tls_client_ca_file = ProtectedFileReference::parse(value, setting)?;
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
            Setting::ListenerOtlpHttpAcceptedSocketLimit => {
                self.otlp_http_accepted_socket_limit = parse_accepted_socket_limit(value, setting)?;
            },
            Setting::ListenerOtlpHttpPerAddressAcceptedSocketLimit => {
                self.otlp_http_per_address_accepted_socket_limit =
                    parse_accepted_socket_limit(value, setting)?;
            },
            Setting::ListenerOtlpHttpTlsHandshakeLimit => {
                self.otlp_http_connection_protection.tls_handshake_limit =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpHttpTlsHandshakeDeadlineSeconds => {
                self.otlp_http_connection_protection
                    .tls_handshake_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpHttpHeaderDeadlineSeconds => {
                self.otlp_http_connection_protection.header_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpHttpBodyDeadlineSeconds => {
                self.otlp_http_connection_protection.body_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpHttpRequestDeadlineSeconds => {
                self.otlp_http_connection_protection
                    .request_deadline_seconds = parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpHttpIdleDeadlineSeconds => {
                self.otlp_http_connection_protection.idle_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerOtlpHttpTlsCertificateFile => {
                self.otlp_http_tls_certificate_file =
                    ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerOtlpHttpTlsPrivateKeyFile => {
                self.otlp_http_tls_private_key_file =
                    ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerOtlpHttpTlsClientCaFile => {
                self.otlp_http_tls_client_ca_file = ProtectedFileReference::parse(value, setting)?;
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
            Setting::ListenerLokiPushAcceptedSocketLimit => {
                self.loki_push_accepted_socket_limit = parse_accepted_socket_limit(value, setting)?;
            },
            Setting::ListenerLokiPushPerAddressAcceptedSocketLimit => {
                self.loki_push_per_address_accepted_socket_limit =
                    parse_accepted_socket_limit(value, setting)?;
            },
            Setting::ListenerLokiPushTlsHandshakeLimit => {
                self.loki_push_connection_protection.tls_handshake_limit =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerLokiPushTlsHandshakeDeadlineSeconds => {
                self.loki_push_connection_protection
                    .tls_handshake_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerLokiPushHeaderDeadlineSeconds => {
                self.loki_push_connection_protection.header_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerLokiPushBodyDeadlineSeconds => {
                self.loki_push_connection_protection.body_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerLokiPushRequestDeadlineSeconds => {
                self.loki_push_connection_protection
                    .request_deadline_seconds = parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerLokiPushIdleDeadlineSeconds => {
                self.loki_push_connection_protection.idle_deadline_seconds =
                    parse_connection_protection_value(value, setting)?;
            },
            Setting::ListenerLokiPushTlsCertificateFile => {
                self.loki_push_tls_certificate_file =
                    ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerLokiPushTlsPrivateKeyFile => {
                self.loki_push_tls_private_key_file =
                    ProtectedFileReference::parse(value, setting)?;
            },
            Setting::ListenerLokiPushTlsClientCaFile => {
                self.loki_push_tls_client_ca_file = ProtectedFileReference::parse(value, setting)?;
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
        validate_accepted_socket_limits(
            self.operations_accepted_socket_limit,
            self.operations_per_address_accepted_socket_limit,
            Setting::ListenerOperationsPerAddressAcceptedSocketLimit,
        )?;
        validate_accepted_socket_limits(
            self.api_accepted_socket_limit,
            self.api_per_address_accepted_socket_limit,
            Setting::ListenerApiPerAddressAcceptedSocketLimit,
        )?;
        validate_accepted_socket_limits(
            self.otlp_grpc_accepted_socket_limit,
            self.otlp_grpc_per_address_accepted_socket_limit,
            Setting::ListenerOtlpGrpcPerAddressAcceptedSocketLimit,
        )?;
        validate_accepted_socket_limits(
            self.otlp_http_accepted_socket_limit,
            self.otlp_http_per_address_accepted_socket_limit,
            Setting::ListenerOtlpHttpPerAddressAcceptedSocketLimit,
        )?;
        validate_accepted_socket_limits(
            self.loki_push_accepted_socket_limit,
            self.loki_push_per_address_accepted_socket_limit,
            Setting::ListenerLokiPushPerAddressAcceptedSocketLimit,
        )?;
        Ok(EffectiveConfiguration {
            schema_version: self.schema_version,
            log_level: self.log_level,
            shutdown_grace_seconds: self.shutdown_grace_seconds,
            max_registered_tenants: self.max_registered_tenants,
            control_path: self.control_path,
            operations_bind_address: self.operations_bind_address,
            operations_transport: self.operations_transport,
            operations_accepted_socket_limit: self.operations_accepted_socket_limit,
            operations_per_address_accepted_socket_limit: self
                .operations_per_address_accepted_socket_limit,
            operations_connection_protection: self.operations_connection_protection,
            operations_tls_certificate_file: self.operations_tls_certificate_file,
            operations_tls_private_key_file: self.operations_tls_private_key_file,
            operations_tls_client_ca_file: self.operations_tls_client_ca_file,
            operations_trusted_proxy_cidrs: self.operations_trusted_proxy_cidrs,
            operations_forwarded_hops: self.operations_forwarded_hops,
            api_bind_address: self.api_bind_address,
            api_transport: self.api_transport,
            api_accepted_socket_limit: self.api_accepted_socket_limit,
            api_per_address_accepted_socket_limit: self.api_per_address_accepted_socket_limit,
            api_trusted_proxy_cidrs: self.api_trusted_proxy_cidrs,
            api_forwarded_hops: self.api_forwarded_hops,
            api_connection_protection: self.api_connection_protection,
            api_http2_profile: self.api_http2_profile,
            api_tls_certificate_file: self.api_tls_certificate_file,
            api_tls_private_key_file: self.api_tls_private_key_file,
            api_tls_client_ca_file: self.api_tls_client_ca_file,
            otlp_grpc_bind_address: self.otlp_grpc_bind_address,
            otlp_grpc_transport: self.otlp_grpc_transport,
            otlp_grpc_accepted_socket_limit: self.otlp_grpc_accepted_socket_limit,
            otlp_grpc_per_address_accepted_socket_limit: self
                .otlp_grpc_per_address_accepted_socket_limit,
            otlp_grpc_connection_protection: self.otlp_grpc_connection_protection,
            otlp_grpc_http2_profile: self.otlp_grpc_http2_profile,
            otlp_grpc_tls_certificate_file: self.otlp_grpc_tls_certificate_file,
            otlp_grpc_tls_private_key_file: self.otlp_grpc_tls_private_key_file,
            otlp_grpc_tls_client_ca_file: self.otlp_grpc_tls_client_ca_file,
            otlp_grpc_trusted_proxy_cidrs: self.otlp_grpc_trusted_proxy_cidrs,
            otlp_grpc_forwarded_hops: self.otlp_grpc_forwarded_hops,
            otlp_http_bind_address: self.otlp_http_bind_address,
            otlp_http_transport: self.otlp_http_transport,
            otlp_http_accepted_socket_limit: self.otlp_http_accepted_socket_limit,
            otlp_http_per_address_accepted_socket_limit: self
                .otlp_http_per_address_accepted_socket_limit,
            otlp_http_connection_protection: self.otlp_http_connection_protection,
            otlp_http_tls_certificate_file: self.otlp_http_tls_certificate_file,
            otlp_http_tls_private_key_file: self.otlp_http_tls_private_key_file,
            otlp_http_tls_client_ca_file: self.otlp_http_tls_client_ca_file,
            otlp_http_trusted_proxy_cidrs: self.otlp_http_trusted_proxy_cidrs,
            otlp_http_forwarded_hops: self.otlp_http_forwarded_hops,
            loki_push_bind_address: self.loki_push_bind_address,
            loki_push_transport: self.loki_push_transport,
            loki_push_accepted_socket_limit: self.loki_push_accepted_socket_limit,
            loki_push_per_address_accepted_socket_limit: self
                .loki_push_per_address_accepted_socket_limit,
            loki_push_connection_protection: self.loki_push_connection_protection,
            loki_push_tls_certificate_file: self.loki_push_tls_certificate_file,
            loki_push_tls_private_key_file: self.loki_push_tls_private_key_file,
            loki_push_tls_client_ca_file: self.loki_push_tls_client_ca_file,
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

fn default_protected_reference(
    setting: Setting,
) -> Result<ProtectedFileReference, ConfigurationFailure> {
    ProtectedFileReference::parse(setting_definition(setting).default_value(), setting)
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
    if !(minimum..=maximum).contains(&u32::from(seconds)) {
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
    if !(minimum..=maximum).contains(&u32::from(tenants)) {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::RuntimeMaxRegisteredTenants,
        ));
    }
    Ok(tenants)
}

fn default_connection_protection(
    settings: [Setting; 6],
) -> Result<ConnectionProtectionProfile, ConfigurationFailure> {
    let [
        tls_handshake_limit,
        tls_handshake_deadline_seconds,
        header_deadline_seconds,
        body_deadline_seconds,
        request_deadline_seconds,
        idle_deadline_seconds,
    ] = settings;
    Ok(ConnectionProtectionProfile {
        tls_handshake_limit: parse_connection_protection_value(
            setting_definition(tls_handshake_limit).default_value(),
            tls_handshake_limit,
        )?,
        tls_handshake_deadline_seconds: parse_connection_protection_value(
            setting_definition(tls_handshake_deadline_seconds).default_value(),
            tls_handshake_deadline_seconds,
        )?,
        header_deadline_seconds: parse_connection_protection_value(
            setting_definition(header_deadline_seconds).default_value(),
            header_deadline_seconds,
        )?,
        body_deadline_seconds: parse_connection_protection_value(
            setting_definition(body_deadline_seconds).default_value(),
            body_deadline_seconds,
        )?,
        request_deadline_seconds: parse_connection_protection_value(
            setting_definition(request_deadline_seconds).default_value(),
            request_deadline_seconds,
        )?,
        idle_deadline_seconds: parse_connection_protection_value(
            setting_definition(idle_deadline_seconds).default_value(),
            idle_deadline_seconds,
        )?,
    })
}

fn default_http2_profile(
    settings: [Setting; 6],
    grpc_message_setting: Option<Setting>,
) -> Result<Http2Profile, ConfigurationFailure> {
    let [
        max_concurrent_streams,
        initial_stream_window_bytes,
        initial_connection_window_bytes,
        max_frame_bytes,
        max_header_list_bytes,
        minimum_ping_interval_seconds,
    ] = settings;
    Ok(Http2Profile {
        max_concurrent_streams: parse_http2_stream_limit(
            setting_definition(max_concurrent_streams).default_value(),
            max_concurrent_streams,
        )?,
        initial_stream_window_bytes: parse_http2_value(
            setting_definition(initial_stream_window_bytes).default_value(),
            initial_stream_window_bytes,
        )?,
        initial_connection_window_bytes: parse_http2_value(
            setting_definition(initial_connection_window_bytes).default_value(),
            initial_connection_window_bytes,
        )?,
        max_frame_bytes: parse_http2_value(
            setting_definition(max_frame_bytes).default_value(),
            max_frame_bytes,
        )?,
        max_header_list_bytes: parse_http2_value(
            setting_definition(max_header_list_bytes).default_value(),
            max_header_list_bytes,
        )?,
        minimum_ping_interval_seconds: parse_connection_protection_value(
            setting_definition(minimum_ping_interval_seconds).default_value(),
            minimum_ping_interval_seconds,
        )?,
        max_grpc_message_bytes: grpc_message_setting
            .map(|setting| parse_http2_value(setting_definition(setting).default_value(), setting))
            .transpose()?,
    })
}

fn parse_connection_protection_value(
    value: &str,
    setting: Setting,
) -> Result<NonZeroU16, ConfigurationFailure> {
    let value = parse_canonical_u16(value, failure_source(setting))?;
    let ValueDomain::UnsignedIntegerRange(minimum, maximum) = setting_definition(setting).domain()
    else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            failure_source(setting),
        ));
    };
    if !(minimum..=maximum).contains(&u32::from(value)) {
        return Err(ConfigurationFailure::unsupported_value(failure_source(
            setting,
        )));
    }
    NonZeroU16::new(value)
        .ok_or_else(|| ConfigurationFailure::unsupported_value(failure_source(setting)))
}

fn parse_accepted_socket_limit(
    value: &str,
    setting: Setting,
) -> Result<NonZeroU16, ConfigurationFailure> {
    let limit = parse_canonical_u16(value, failure_source(setting))?;
    let ValueDomain::UnsignedIntegerRange(minimum, maximum) = setting_definition(setting).domain()
    else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            failure_source(setting),
        ));
    };
    if !(minimum..=maximum).contains(&u32::from(limit)) {
        return Err(ConfigurationFailure::unsupported_value(failure_source(
            setting,
        )));
    }
    NonZeroU16::new(limit)
        .ok_or_else(|| ConfigurationFailure::unsupported_value(failure_source(setting)))
}

fn validate_accepted_socket_limits(
    global: NonZeroU16,
    per_address: NonZeroU16,
    per_address_setting: Setting,
) -> Result<(), ConfigurationFailure> {
    if per_address > global {
        return Err(ConfigurationFailure::unsupported_value(failure_source(
            per_address_setting,
        )));
    }
    Ok(())
}

fn parse_http2_stream_limit(
    value: &str,
    setting: Setting,
) -> Result<NonZeroU16, ConfigurationFailure> {
    let value = parse_http2_value(value, setting)?;
    u16::try_from(value.get())
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or_else(|| ConfigurationFailure::unsupported_value(failure_source(setting)))
}

fn parse_http2_value(value: &str, setting: Setting) -> Result<NonZeroU32, ConfigurationFailure> {
    let source = failure_source(setting);
    if value.is_empty()
        || value.len() > 10
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            source,
        ));
    }
    let value = value.parse::<u32>().map_err(|_| {
        ConfigurationFailure::new(ConfigurationFailureCode::UnsupportedValue, source)
    })?;
    let ValueDomain::UnsignedIntegerRange(minimum, maximum) = setting_definition(setting).domain()
    else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            source,
        ));
    };
    if !(minimum..=maximum).contains(&value) {
        return Err(ConfigurationFailure::unsupported_value(source));
    }
    NonZeroU32::new(value).ok_or_else(|| ConfigurationFailure::unsupported_value(source))
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
    if !(minimum..=maximum).contains(&u32::from(hops)) {
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
    setting as usize
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
        Setting::ListenerOperationsAcceptedSocketLimit => {
            FailureSource::ListenerOperationsAcceptedSocketLimit
        },
        Setting::ListenerOperationsPerAddressAcceptedSocketLimit => {
            FailureSource::ListenerOperationsPerAddressAcceptedSocketLimit
        },
        Setting::ListenerOperationsTlsHandshakeLimit => {
            FailureSource::ListenerOperationsTlsHandshakeLimit
        },
        Setting::ListenerOperationsTlsHandshakeDeadlineSeconds => {
            FailureSource::ListenerOperationsTlsHandshakeDeadlineSeconds
        },
        Setting::ListenerOperationsHeaderDeadlineSeconds => {
            FailureSource::ListenerOperationsHeaderDeadlineSeconds
        },
        Setting::ListenerOperationsBodyDeadlineSeconds => {
            FailureSource::ListenerOperationsBodyDeadlineSeconds
        },
        Setting::ListenerOperationsRequestDeadlineSeconds => {
            FailureSource::ListenerOperationsRequestDeadlineSeconds
        },
        Setting::ListenerOperationsIdleDeadlineSeconds => {
            FailureSource::ListenerOperationsIdleDeadlineSeconds
        },
        Setting::ListenerOperationsTlsCertificateFile => {
            FailureSource::ListenerOperationsTlsCertificateFile
        },
        Setting::ListenerOperationsTlsPrivateKeyFile => {
            FailureSource::ListenerOperationsTlsPrivateKeyFile
        },
        Setting::ListenerOperationsTlsClientCaFile => {
            FailureSource::ListenerOperationsTlsClientCaFile
        },
        Setting::ListenerOperationsTrustedProxyCidrs => {
            FailureSource::ListenerOperationsTrustedProxyCidrs
        },
        Setting::ListenerOperationsForwardedHops => FailureSource::ListenerOperationsForwardedHops,
        Setting::ListenerApiBindAddress => FailureSource::ListenerApiBindAddress,
        Setting::ListenerApiTransport => FailureSource::ListenerApiTransport,
        Setting::ListenerApiAcceptedSocketLimit => FailureSource::ListenerApiAcceptedSocketLimit,
        Setting::ListenerApiPerAddressAcceptedSocketLimit => {
            FailureSource::ListenerApiPerAddressAcceptedSocketLimit
        },
        Setting::ListenerApiTlsHandshakeLimit => FailureSource::ListenerApiTlsHandshakeLimit,
        Setting::ListenerApiTlsHandshakeDeadlineSeconds => {
            FailureSource::ListenerApiTlsHandshakeDeadlineSeconds
        },
        Setting::ListenerApiHeaderDeadlineSeconds => {
            FailureSource::ListenerApiHeaderDeadlineSeconds
        },
        Setting::ListenerApiBodyDeadlineSeconds => FailureSource::ListenerApiBodyDeadlineSeconds,
        Setting::ListenerApiRequestDeadlineSeconds => {
            FailureSource::ListenerApiRequestDeadlineSeconds
        },
        Setting::ListenerApiIdleDeadlineSeconds => FailureSource::ListenerApiIdleDeadlineSeconds,
        Setting::ListenerApiHttp2MaxConcurrentStreams => {
            FailureSource::ListenerApiHttp2MaxConcurrentStreams
        },
        Setting::ListenerApiHttp2InitialStreamWindowBytes => {
            FailureSource::ListenerApiHttp2InitialStreamWindowBytes
        },
        Setting::ListenerApiHttp2InitialConnectionWindowBytes => {
            FailureSource::ListenerApiHttp2InitialConnectionWindowBytes
        },
        Setting::ListenerApiHttp2MaxFrameBytes => FailureSource::ListenerApiHttp2MaxFrameBytes,
        Setting::ListenerApiHttp2MaxHeaderListBytes => {
            FailureSource::ListenerApiHttp2MaxHeaderListBytes
        },
        Setting::ListenerApiHttp2MinimumPingIntervalSeconds => {
            FailureSource::ListenerApiHttp2MinimumPingIntervalSeconds
        },
        Setting::ListenerApiTrustedProxyCidrs => FailureSource::ListenerApiTrustedProxyCidrs,
        Setting::ListenerApiForwardedHops => FailureSource::ListenerApiForwardedHops,
        Setting::ListenerApiTlsCertificateFile => FailureSource::ListenerApiTlsCertificateFile,
        Setting::ListenerApiTlsPrivateKeyFile => FailureSource::ListenerApiTlsPrivateKeyFile,
        Setting::ListenerApiTlsClientCaFile => FailureSource::ListenerApiTlsClientCaFile,
        Setting::ListenerOtlpGrpcBindAddress => FailureSource::ListenerOtlpGrpcBindAddress,
        Setting::ListenerOtlpGrpcTransport => FailureSource::ListenerOtlpGrpcTransport,
        Setting::ListenerOtlpGrpcAcceptedSocketLimit => {
            FailureSource::ListenerOtlpGrpcAcceptedSocketLimit
        },
        Setting::ListenerOtlpGrpcPerAddressAcceptedSocketLimit => {
            FailureSource::ListenerOtlpGrpcPerAddressAcceptedSocketLimit
        },
        Setting::ListenerOtlpGrpcTlsHandshakeLimit => {
            FailureSource::ListenerOtlpGrpcTlsHandshakeLimit
        },
        Setting::ListenerOtlpGrpcTlsHandshakeDeadlineSeconds => {
            FailureSource::ListenerOtlpGrpcTlsHandshakeDeadlineSeconds
        },
        Setting::ListenerOtlpGrpcHeaderDeadlineSeconds => {
            FailureSource::ListenerOtlpGrpcHeaderDeadlineSeconds
        },
        Setting::ListenerOtlpGrpcBodyDeadlineSeconds => {
            FailureSource::ListenerOtlpGrpcBodyDeadlineSeconds
        },
        Setting::ListenerOtlpGrpcRequestDeadlineSeconds => {
            FailureSource::ListenerOtlpGrpcRequestDeadlineSeconds
        },
        Setting::ListenerOtlpGrpcIdleDeadlineSeconds => {
            FailureSource::ListenerOtlpGrpcIdleDeadlineSeconds
        },
        Setting::ListenerOtlpGrpcHttp2MaxConcurrentStreams => {
            FailureSource::ListenerOtlpGrpcHttp2MaxConcurrentStreams
        },
        Setting::ListenerOtlpGrpcHttp2InitialStreamWindowBytes => {
            FailureSource::ListenerOtlpGrpcHttp2InitialStreamWindowBytes
        },
        Setting::ListenerOtlpGrpcHttp2InitialConnectionWindowBytes => {
            FailureSource::ListenerOtlpGrpcHttp2InitialConnectionWindowBytes
        },
        Setting::ListenerOtlpGrpcHttp2MaxFrameBytes => {
            FailureSource::ListenerOtlpGrpcHttp2MaxFrameBytes
        },
        Setting::ListenerOtlpGrpcHttp2MaxHeaderListBytes => {
            FailureSource::ListenerOtlpGrpcHttp2MaxHeaderListBytes
        },
        Setting::ListenerOtlpGrpcHttp2MinimumPingIntervalSeconds => {
            FailureSource::ListenerOtlpGrpcHttp2MinimumPingIntervalSeconds
        },
        Setting::ListenerOtlpGrpcMaxMessageBytes => FailureSource::ListenerOtlpGrpcMaxMessageBytes,
        Setting::ListenerOtlpGrpcTlsCertificateFile => {
            FailureSource::ListenerOtlpGrpcTlsCertificateFile
        },
        Setting::ListenerOtlpGrpcTlsPrivateKeyFile => {
            FailureSource::ListenerOtlpGrpcTlsPrivateKeyFile
        },
        Setting::ListenerOtlpGrpcTlsClientCaFile => FailureSource::ListenerOtlpGrpcTlsClientCaFile,
        Setting::ListenerOtlpGrpcTrustedProxyCidrs => {
            FailureSource::ListenerOtlpGrpcTrustedProxyCidrs
        },
        Setting::ListenerOtlpGrpcForwardedHops => FailureSource::ListenerOtlpGrpcForwardedHops,
        Setting::ListenerOtlpHttpBindAddress => FailureSource::ListenerOtlpHttpBindAddress,
        Setting::ListenerOtlpHttpTransport => FailureSource::ListenerOtlpHttpTransport,
        Setting::ListenerOtlpHttpAcceptedSocketLimit => {
            FailureSource::ListenerOtlpHttpAcceptedSocketLimit
        },
        Setting::ListenerOtlpHttpPerAddressAcceptedSocketLimit => {
            FailureSource::ListenerOtlpHttpPerAddressAcceptedSocketLimit
        },
        Setting::ListenerOtlpHttpTlsHandshakeLimit => {
            FailureSource::ListenerOtlpHttpTlsHandshakeLimit
        },
        Setting::ListenerOtlpHttpTlsHandshakeDeadlineSeconds => {
            FailureSource::ListenerOtlpHttpTlsHandshakeDeadlineSeconds
        },
        Setting::ListenerOtlpHttpHeaderDeadlineSeconds => {
            FailureSource::ListenerOtlpHttpHeaderDeadlineSeconds
        },
        Setting::ListenerOtlpHttpBodyDeadlineSeconds => {
            FailureSource::ListenerOtlpHttpBodyDeadlineSeconds
        },
        Setting::ListenerOtlpHttpRequestDeadlineSeconds => {
            FailureSource::ListenerOtlpHttpRequestDeadlineSeconds
        },
        Setting::ListenerOtlpHttpIdleDeadlineSeconds => {
            FailureSource::ListenerOtlpHttpIdleDeadlineSeconds
        },
        Setting::ListenerOtlpHttpTlsCertificateFile => {
            FailureSource::ListenerOtlpHttpTlsCertificateFile
        },
        Setting::ListenerOtlpHttpTlsPrivateKeyFile => {
            FailureSource::ListenerOtlpHttpTlsPrivateKeyFile
        },
        Setting::ListenerOtlpHttpTlsClientCaFile => FailureSource::ListenerOtlpHttpTlsClientCaFile,
        Setting::ListenerOtlpHttpTrustedProxyCidrs => {
            FailureSource::ListenerOtlpHttpTrustedProxyCidrs
        },
        Setting::ListenerOtlpHttpForwardedHops => FailureSource::ListenerOtlpHttpForwardedHops,
        Setting::ListenerLokiPushBindAddress => FailureSource::ListenerLokiPushBindAddress,
        Setting::ListenerLokiPushTransport => FailureSource::ListenerLokiPushTransport,
        Setting::ListenerLokiPushAcceptedSocketLimit => {
            FailureSource::ListenerLokiPushAcceptedSocketLimit
        },
        Setting::ListenerLokiPushPerAddressAcceptedSocketLimit => {
            FailureSource::ListenerLokiPushPerAddressAcceptedSocketLimit
        },
        Setting::ListenerLokiPushTlsHandshakeLimit => {
            FailureSource::ListenerLokiPushTlsHandshakeLimit
        },
        Setting::ListenerLokiPushTlsHandshakeDeadlineSeconds => {
            FailureSource::ListenerLokiPushTlsHandshakeDeadlineSeconds
        },
        Setting::ListenerLokiPushHeaderDeadlineSeconds => {
            FailureSource::ListenerLokiPushHeaderDeadlineSeconds
        },
        Setting::ListenerLokiPushBodyDeadlineSeconds => {
            FailureSource::ListenerLokiPushBodyDeadlineSeconds
        },
        Setting::ListenerLokiPushRequestDeadlineSeconds => {
            FailureSource::ListenerLokiPushRequestDeadlineSeconds
        },
        Setting::ListenerLokiPushIdleDeadlineSeconds => {
            FailureSource::ListenerLokiPushIdleDeadlineSeconds
        },
        Setting::ListenerLokiPushTlsCertificateFile => {
            FailureSource::ListenerLokiPushTlsCertificateFile
        },
        Setting::ListenerLokiPushTlsPrivateKeyFile => {
            FailureSource::ListenerLokiPushTlsPrivateKeyFile
        },
        Setting::ListenerLokiPushTlsClientCaFile => FailureSource::ListenerLokiPushTlsClientCaFile,
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
