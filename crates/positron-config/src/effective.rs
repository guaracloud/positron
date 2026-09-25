use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32};
use std::time::Duration;

use positron_domain::identity::TenantId;
use sha2::{Digest, Sha256};

use super::{
    ApiTransport, ConfigurationFailure, ConfigurationFailureCode, LogLevel, MutabilityClass,
    NetworkListenerRole, NetworkTransport, ProtectedFileReference, Setting, SettingSource,
    contract, failure_source, setting_for_path, setting_index,
};

/// A bounded, non-secret warning derived from the active effective profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationWarning {
    /// The API listener accepts unencrypted traffic by explicit operator choice.
    PublicPlaintextApi,
    /// One named listener role accepts unencrypted traffic by explicit choice.
    PublicPlaintextListener(NetworkListenerRole),
}

impl ConfigurationWarning {
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::PublicPlaintextApi => "public API transport is plaintext",
            Self::PublicPlaintextListener(role) => match role {
                NetworkListenerRole::Operations => "operations transport is plaintext",
                NetworkListenerRole::Api => "public API transport is plaintext",
                NetworkListenerRole::OtlpGrpc => "OTLP gRPC transport is plaintext",
                NetworkListenerRole::OtlpHttp => "OTLP HTTP transport is plaintext",
                NetworkListenerRole::LokiPush => "Loki push transport is plaintext",
            },
        }
    }
}

/// One resolved transport profile. Certificate and trust references stay
/// protected and are loaded by the runtime before listener publication.
#[derive(Clone, Eq, PartialEq)]
pub struct NetworkListenerProfile<'a> {
    role: NetworkListenerRole,
    bind_address: SocketAddr,
    transport: NetworkTransport,
    tls_certificate_file: ProtectedFileReference,
    tls_private_key_file: ProtectedFileReference,
    tls_client_ca_file: Option<ProtectedFileReference>,
    trusted_proxy_cidrs: &'a [String],
    cors_allowed_origins: Option<&'a [String]>,
    forwarded_hops: Option<NonZeroU8>,
    connection_admission: ConnectionAdmissionProfile,
    connection_protection: ConnectionProtectionProfile,
    http2_profile: Option<Http2Profile>,
}

/// The bounded pre-authentication accepted-socket policy for one network listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionAdmissionProfile {
    global_accepted_socket_limit: NonZeroU16,
    per_address_accepted_socket_limit: NonZeroU16,
    global_admission_rate_per_second: NonZeroU16,
    per_address_admission_rate_per_second: NonZeroU16,
}

impl ConnectionAdmissionProfile {
    #[must_use]
    pub const fn global_accepted_socket_limit(self) -> NonZeroU16 {
        self.global_accepted_socket_limit
    }

    #[must_use]
    pub const fn per_address_accepted_socket_limit(self) -> NonZeroU16 {
        self.per_address_accepted_socket_limit
    }

    #[must_use]
    pub const fn global_admission_rate_per_second(self) -> NonZeroU16 {
        self.global_admission_rate_per_second
    }

    #[must_use]
    pub const fn per_address_admission_rate_per_second(self) -> NonZeroU16 {
        self.per_address_admission_rate_per_second
    }
}

/// The bounded pre-authentication handshake and deadline policy for one network listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionProtectionProfile {
    pub(crate) tls_handshake_limit: NonZeroU16,
    pub(crate) tls_handshake_deadline_seconds: NonZeroU16,
    pub(crate) header_deadline_seconds: NonZeroU16,
    pub(crate) body_deadline_seconds: NonZeroU16,
    pub(crate) request_deadline_seconds: NonZeroU16,
    pub(crate) idle_deadline_seconds: NonZeroU16,
}

/// Bounded HTTP/2 transport controls for one role that actually serves HTTP/2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Profile {
    pub(crate) max_concurrent_streams: NonZeroU16,
    pub(crate) initial_stream_window_bytes: NonZeroU32,
    pub(crate) initial_connection_window_bytes: NonZeroU32,
    pub(crate) max_frame_bytes: NonZeroU32,
    pub(crate) max_header_list_bytes: NonZeroU32,
    pub(crate) minimum_ping_interval_seconds: NonZeroU16,
    pub(crate) max_grpc_message_bytes: Option<NonZeroU32>,
}

impl Http2Profile {
    #[must_use]
    pub const fn max_concurrent_streams(self) -> NonZeroU16 {
        self.max_concurrent_streams
    }
    #[must_use]
    pub const fn initial_stream_window_bytes(self) -> NonZeroU32 {
        self.initial_stream_window_bytes
    }
    #[must_use]
    pub const fn initial_connection_window_bytes(self) -> NonZeroU32 {
        self.initial_connection_window_bytes
    }
    #[must_use]
    pub const fn max_frame_bytes(self) -> NonZeroU32 {
        self.max_frame_bytes
    }
    #[must_use]
    pub const fn max_header_list_bytes(self) -> NonZeroU32 {
        self.max_header_list_bytes
    }
    #[must_use]
    pub const fn minimum_ping_interval(self) -> Duration {
        Duration::from_secs(self.minimum_ping_interval_seconds.get() as u64)
    }
    #[must_use]
    pub const fn max_grpc_message_bytes(self) -> Option<NonZeroU32> {
        self.max_grpc_message_bytes
    }
}

impl ConnectionProtectionProfile {
    #[must_use]
    pub const fn tls_handshake_limit(self) -> NonZeroU16 {
        self.tls_handshake_limit
    }
    #[must_use]
    pub const fn tls_handshake_deadline(self) -> Duration {
        Duration::from_secs(self.tls_handshake_deadline_seconds.get() as u64)
    }
    #[must_use]
    pub const fn header_deadline(self) -> Duration {
        Duration::from_secs(self.header_deadline_seconds.get() as u64)
    }
    #[must_use]
    pub const fn body_deadline(self) -> Duration {
        Duration::from_secs(self.body_deadline_seconds.get() as u64)
    }
    #[must_use]
    pub const fn request_deadline(self) -> Duration {
        Duration::from_secs(self.request_deadline_seconds.get() as u64)
    }
    #[must_use]
    pub const fn idle_deadline(self) -> Duration {
        Duration::from_secs(self.idle_deadline_seconds.get() as u64)
    }
}

impl NetworkListenerProfile<'_> {
    #[must_use]
    pub const fn role(&self) -> NetworkListenerRole {
        self.role
    }
    #[must_use]
    pub const fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }
    #[must_use]
    pub const fn transport(&self) -> NetworkTransport {
        self.transport
    }
    #[must_use]
    pub fn tls_certificate_file(&self) -> &ProtectedFileReference {
        &self.tls_certificate_file
    }
    #[must_use]
    pub fn tls_private_key_file(&self) -> &ProtectedFileReference {
        &self.tls_private_key_file
    }
    #[must_use]
    pub fn tls_client_ca_file(&self) -> Option<&ProtectedFileReference> {
        self.tls_client_ca_file.as_ref()
    }
    #[must_use]
    pub fn trusted_proxy_cidrs(&self) -> &[String] {
        self.trusted_proxy_cidrs
    }

    #[must_use]
    pub fn cors_allowed_origins(&self) -> Option<&[String]> {
        self.cors_allowed_origins
    }
    #[must_use]
    pub const fn forwarded_hops(&self) -> Option<NonZeroU8> {
        self.forwarded_hops
    }
    #[must_use]
    pub const fn connection_admission(&self) -> ConnectionAdmissionProfile {
        self.connection_admission
    }
    #[must_use]
    pub const fn connection_protection(&self) -> ConnectionProtectionProfile {
        self.connection_protection
    }
    #[must_use]
    pub const fn http2_profile(&self) -> Option<Http2Profile> {
        self.http2_profile
    }
}

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
    pub(crate) admission_rate_per_second: NonZeroU16,
    pub(crate) per_address_admission_rate_per_second: NonZeroU16,
    pub(crate) operations_bind_address: SocketAddr,
    pub(crate) operations_transport: NetworkTransport,
    pub(crate) operations_accepted_socket_limit: NonZeroU16,
    pub(crate) operations_per_address_accepted_socket_limit: NonZeroU16,
    pub(crate) operations_connection_protection: ConnectionProtectionProfile,
    pub(crate) operations_tls_certificate_file: ProtectedFileReference,
    pub(crate) operations_tls_private_key_file: ProtectedFileReference,
    pub(crate) operations_tls_client_ca_file: ProtectedFileReference,
    pub(crate) operations_trusted_proxy_cidrs: Vec<String>,
    pub(crate) operations_forwarded_hops: Option<NonZeroU8>,
    pub(crate) api_bind_address: SocketAddr,
    pub(crate) api_transport: ApiTransport,
    pub(crate) api_accepted_socket_limit: NonZeroU16,
    pub(crate) api_per_address_accepted_socket_limit: NonZeroU16,
    pub(crate) api_connection_protection: ConnectionProtectionProfile,
    pub(crate) api_http2_profile: Http2Profile,
    pub(crate) api_cors_allowed_origins: Vec<String>,
    pub(crate) api_trusted_proxy_cidrs: Vec<String>,
    pub(crate) api_forwarded_hops: Option<NonZeroU8>,
    pub(crate) api_tls_certificate_file: ProtectedFileReference,
    pub(crate) api_tls_private_key_file: ProtectedFileReference,
    pub(crate) api_tls_client_ca_file: ProtectedFileReference,
    pub(crate) otlp_grpc_bind_address: SocketAddr,
    pub(crate) otlp_grpc_transport: NetworkTransport,
    pub(crate) otlp_grpc_accepted_socket_limit: NonZeroU16,
    pub(crate) otlp_grpc_per_address_accepted_socket_limit: NonZeroU16,
    pub(crate) otlp_grpc_connection_protection: ConnectionProtectionProfile,
    pub(crate) otlp_grpc_http2_profile: Http2Profile,
    pub(crate) otlp_grpc_tls_certificate_file: ProtectedFileReference,
    pub(crate) otlp_grpc_tls_private_key_file: ProtectedFileReference,
    pub(crate) otlp_grpc_tls_client_ca_file: ProtectedFileReference,
    pub(crate) otlp_grpc_trusted_proxy_cidrs: Vec<String>,
    pub(crate) otlp_grpc_forwarded_hops: Option<NonZeroU8>,
    pub(crate) otlp_http_bind_address: SocketAddr,
    pub(crate) otlp_http_transport: NetworkTransport,
    pub(crate) otlp_http_accepted_socket_limit: NonZeroU16,
    pub(crate) otlp_http_per_address_accepted_socket_limit: NonZeroU16,
    pub(crate) otlp_http_connection_protection: ConnectionProtectionProfile,
    pub(crate) otlp_http_tls_certificate_file: ProtectedFileReference,
    pub(crate) otlp_http_tls_private_key_file: ProtectedFileReference,
    pub(crate) otlp_http_tls_client_ca_file: ProtectedFileReference,
    pub(crate) otlp_http_trusted_proxy_cidrs: Vec<String>,
    pub(crate) otlp_http_forwarded_hops: Option<NonZeroU8>,
    pub(crate) loki_push_bind_address: SocketAddr,
    pub(crate) loki_push_transport: NetworkTransport,
    pub(crate) loki_push_accepted_socket_limit: NonZeroU16,
    pub(crate) loki_push_per_address_accepted_socket_limit: NonZeroU16,
    pub(crate) loki_push_connection_protection: ConnectionProtectionProfile,
    pub(crate) loki_push_tls_certificate_file: ProtectedFileReference,
    pub(crate) loki_push_tls_private_key_file: ProtectedFileReference,
    pub(crate) loki_push_tls_client_ca_file: ProtectedFileReference,
    pub(crate) loki_push_trusted_proxy_cidrs: Vec<String>,
    pub(crate) loki_push_forwarded_hops: Option<NonZeroU8>,
    pub(crate) data_directory: String,
    pub(crate) secrets_directory: String,
    pub(crate) local_key_file: ProtectedFileReference,
    pub(crate) export_destinations: Vec<ExportDestinationDefinition>,
    pub(crate) sources: [SettingSource; 100],
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

    /// Returns the complete resolved profile for one network-facing role.
    #[must_use]
    pub fn network_listener_profile(
        &self,
        role: NetworkListenerRole,
    ) -> Option<NetworkListenerProfile<'_>> {
        let (
            bind_address,
            transport,
            certificate,
            private_key,
            client_ca,
            trusted_proxy_cidrs,
            forwarded_hops,
            global_accepted_socket_limit,
            per_address_accepted_socket_limit,
            connection_protection,
            http2_profile,
            cors_allowed_origins,
        ) = match role {
            NetworkListenerRole::Operations => (
                self.operations_bind_address,
                self.operations_transport,
                &self.operations_tls_certificate_file,
                &self.operations_tls_private_key_file,
                &self.operations_tls_client_ca_file,
                &self.operations_trusted_proxy_cidrs,
                self.operations_forwarded_hops,
                self.operations_accepted_socket_limit,
                self.operations_per_address_accepted_socket_limit,
                self.operations_connection_protection,
                None,
                None,
            ),
            NetworkListenerRole::Api => (
                self.api_bind_address,
                match self.api_transport {
                    ApiTransport::Tls => NetworkTransport::Tls,
                    ApiTransport::MutualTls => NetworkTransport::MutualTls,
                    ApiTransport::PlaintextOptOut => NetworkTransport::PlaintextOptOut,
                },
                &self.api_tls_certificate_file,
                &self.api_tls_private_key_file,
                &self.api_tls_client_ca_file,
                &self.api_trusted_proxy_cidrs,
                self.api_forwarded_hops,
                self.api_accepted_socket_limit,
                self.api_per_address_accepted_socket_limit,
                self.api_connection_protection,
                Some(self.api_http2_profile),
                Some(&self.api_cors_allowed_origins),
            ),
            NetworkListenerRole::OtlpGrpc => (
                self.otlp_grpc_bind_address,
                self.otlp_grpc_transport,
                &self.otlp_grpc_tls_certificate_file,
                &self.otlp_grpc_tls_private_key_file,
                &self.otlp_grpc_tls_client_ca_file,
                &self.otlp_grpc_trusted_proxy_cidrs,
                self.otlp_grpc_forwarded_hops,
                self.otlp_grpc_accepted_socket_limit,
                self.otlp_grpc_per_address_accepted_socket_limit,
                self.otlp_grpc_connection_protection,
                Some(self.otlp_grpc_http2_profile),
                None,
            ),
            NetworkListenerRole::OtlpHttp => (
                self.otlp_http_bind_address,
                self.otlp_http_transport,
                &self.otlp_http_tls_certificate_file,
                &self.otlp_http_tls_private_key_file,
                &self.otlp_http_tls_client_ca_file,
                &self.otlp_http_trusted_proxy_cidrs,
                self.otlp_http_forwarded_hops,
                self.otlp_http_accepted_socket_limit,
                self.otlp_http_per_address_accepted_socket_limit,
                self.otlp_http_connection_protection,
                None,
                None,
            ),
            NetworkListenerRole::LokiPush => (
                self.loki_push_bind_address,
                self.loki_push_transport,
                &self.loki_push_tls_certificate_file,
                &self.loki_push_tls_private_key_file,
                &self.loki_push_tls_client_ca_file,
                &self.loki_push_trusted_proxy_cidrs,
                self.loki_push_forwarded_hops,
                self.loki_push_accepted_socket_limit,
                self.loki_push_per_address_accepted_socket_limit,
                self.loki_push_connection_protection,
                None,
                None,
            ),
        };
        Some(NetworkListenerProfile {
            role,
            bind_address,
            transport,
            tls_certificate_file: certificate.clone(),
            tls_private_key_file: private_key.clone(),
            tls_client_ca_file: (transport == NetworkTransport::MutualTls)
                .then(|| client_ca.clone()),
            trusted_proxy_cidrs,
            cors_allowed_origins: cors_allowed_origins.map(Vec::as_slice),
            forwarded_hops,
            connection_admission: ConnectionAdmissionProfile {
                global_accepted_socket_limit,
                per_address_accepted_socket_limit,
                global_admission_rate_per_second: self.admission_rate_per_second,
                per_address_admission_rate_per_second: self.per_address_admission_rate_per_second,
            },
            connection_protection,
            http2_profile,
        })
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
    pub fn security_warnings(&self) -> Vec<ConfigurationWarning> {
        let mut warnings = Vec::with_capacity(5);
        for role in [
            NetworkListenerRole::Operations,
            NetworkListenerRole::Api,
            NetworkListenerRole::OtlpGrpc,
            NetworkListenerRole::OtlpHttp,
            NetworkListenerRole::LokiPush,
        ] {
            let Some(profile) = self.network_listener_profile(role) else {
                continue;
            };
            if profile.transport != NetworkTransport::PlaintextOptOut {
                continue;
            }
            warnings.push(if role == NetworkListenerRole::Api {
                ConfigurationWarning::PublicPlaintextApi
            } else {
                ConfigurationWarning::PublicPlaintextListener(role)
            });
        }
        warnings
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

    /// Returns the durable, non-reversible binding for settings that may only
    /// change through an explicit initialization, migration, or restore
    /// workflow. The Catalog stores this digest instead of protected paths.
    #[must_use]
    pub fn immutable_configuration_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"positron.configuration.immutable.v1\0");
        for definition in contract::SETTING_DEFINITIONS {
            if definition.mutability() != MutabilityClass::ImmutableAfterInitialization {
                continue;
            }
            update_digest_string(&mut hasher, definition.path());
            update_digest_string(
                &mut hasher,
                &self.canonical_identity_value(definition.setting()),
            );
        }
        let digest = hasher.finalize();
        let mut result = [0; 32];
        result.copy_from_slice(&digest);
        result
    }

    /// Returns the complete, non-reversible configuration intent bound to
    /// private Catalog binding and an opaque Governance Audit request
    /// identifier. Unlike the public redacted rendering, this includes
    /// protected file references so two candidates with different protected
    /// inputs cannot share audit intent.
    #[must_use]
    pub fn audit_binding_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"positron.configuration.audit-binding.v1\0");
        for definition in contract::SETTING_DEFINITIONS {
            update_digest_string(&mut hasher, definition.path());
            update_digest_string(
                &mut hasher,
                &self.canonical_identity_value(definition.setting()),
            );
        }
        let digest = hasher.finalize();
        let mut result = [0; 32];
        result.copy_from_slice(&digest);
        result
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
            rendered.push_str(&super::render_toml_basic_string(definition.path()));
            rendered.push_str(" = ");
            if let Some(source) = self.sources.get(setting_index(setting)) {
                rendered.push_str(&super::render_toml_basic_string(source.as_str()));
            } else {
                rendered.push_str(&super::render_toml_basic_string("unavailable"));
            }
            rendered.push('\n');
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

    /// Compares one operator-rendered desired configuration to this observed
    /// active configuration without exposing secret-bearing values.
    #[must_use]
    pub fn drift_against(&self, desired: &Self) -> ConfigurationDrift {
        let diff = self.semantic_diff(desired);
        ConfigurationDrift::from_diff(diff)
    }

    #[must_use]
    pub fn redacted_reference(&self) -> String {
        let mut rendered = String::with_capacity(512);
        rendered.push_str("schema_version = ");
        rendered.push_str(&self.schema_version.to_string());
        rendered.push_str("\n\n[diagnostics]\nlog_level = ");
        rendered.push_str(&super::render_toml_basic_string(self.log_level.as_str()));
        rendered.push_str("\n\n[runtime]\nshutdown_grace_seconds = ");
        rendered.push_str(&self.shutdown_grace_seconds.to_string());
        rendered.push_str("\nmax_registered_tenants = ");
        rendered.push_str(&self.max_registered_tenants.to_string());
        rendered.push_str("\n\n[listener]\ncontrol_path = ");
        rendered.push_str(&super::render_toml_basic_string(&self.control_path));
        rendered.push_str("\noperations_bind_address = ");
        rendered.push_str(&super::render_toml_basic_string(
            &self.operations_bind_address.to_string(),
        ));
        rendered.push_str("\noperations_transport = ");
        rendered.push_str(&super::render_toml_basic_string(
            self.operations_transport.as_str(),
        ));
        append_accepted_socket_limits(
            &mut rendered,
            "operations",
            self.operations_accepted_socket_limit,
            self.operations_per_address_accepted_socket_limit,
        );
        append_connection_protection_reference(
            &mut rendered,
            "operations",
            self.operations_connection_protection,
        );
        append_redacted_listener_tls_references(&mut rendered, "operations");
        rendered.push_str("\napi_bind_address = ");
        rendered.push_str(&super::render_toml_basic_string(
            &self.api_bind_address.to_string(),
        ));
        rendered.push_str("\napi_transport = ");
        rendered.push_str(&super::render_toml_basic_string(
            self.api_transport.as_str(),
        ));
        append_accepted_socket_limits(
            &mut rendered,
            "api",
            self.api_accepted_socket_limit,
            self.api_per_address_accepted_socket_limit,
        );
        append_connection_protection_reference(
            &mut rendered,
            "api",
            self.api_connection_protection,
        );
        append_redacted_listener_tls_references(&mut rendered, "api");
        rendered.push_str("\notlp_grpc_bind_address = ");
        rendered.push_str(&super::render_toml_basic_string(
            &self.otlp_grpc_bind_address.to_string(),
        ));
        rendered.push_str("\notlp_grpc_transport = ");
        rendered.push_str(&super::render_toml_basic_string(
            self.otlp_grpc_transport.as_str(),
        ));
        append_accepted_socket_limits(
            &mut rendered,
            "otlp_grpc",
            self.otlp_grpc_accepted_socket_limit,
            self.otlp_grpc_per_address_accepted_socket_limit,
        );
        append_connection_protection_reference(
            &mut rendered,
            "otlp_grpc",
            self.otlp_grpc_connection_protection,
        );
        append_redacted_listener_tls_references(&mut rendered, "otlp_grpc");
        rendered.push_str("\notlp_http_bind_address = ");
        rendered.push_str(&super::render_toml_basic_string(
            &self.otlp_http_bind_address.to_string(),
        ));
        rendered.push_str("\notlp_http_transport = ");
        rendered.push_str(&super::render_toml_basic_string(
            self.otlp_http_transport.as_str(),
        ));
        append_accepted_socket_limits(
            &mut rendered,
            "otlp_http",
            self.otlp_http_accepted_socket_limit,
            self.otlp_http_per_address_accepted_socket_limit,
        );
        append_connection_protection_reference(
            &mut rendered,
            "otlp_http",
            self.otlp_http_connection_protection,
        );
        append_redacted_listener_tls_references(&mut rendered, "otlp_http");
        rendered.push_str("\nloki_push_bind_address = ");
        rendered.push_str(&super::render_toml_basic_string(
            &self.loki_push_bind_address.to_string(),
        ));
        rendered.push_str("\nloki_push_transport = ");
        rendered.push_str(&super::render_toml_basic_string(
            self.loki_push_transport.as_str(),
        ));
        append_accepted_socket_limits(
            &mut rendered,
            "loki_push",
            self.loki_push_accepted_socket_limit,
            self.loki_push_per_address_accepted_socket_limit,
        );
        append_connection_protection_reference(
            &mut rendered,
            "loki_push",
            self.loki_push_connection_protection,
        );
        append_redacted_listener_tls_references(&mut rendered, "loki_push");
        append_proxy_trust_reference(
            &mut rendered,
            "operations",
            &self.operations_trusted_proxy_cidrs,
            self.operations_forwarded_hops,
        );
        append_proxy_trust_reference(
            &mut rendered,
            "api",
            &self.api_trusted_proxy_cidrs,
            self.api_forwarded_hops,
        );
        append_proxy_trust_reference(
            &mut rendered,
            "otlp_grpc",
            &self.otlp_grpc_trusted_proxy_cidrs,
            self.otlp_grpc_forwarded_hops,
        );
        append_proxy_trust_reference(
            &mut rendered,
            "otlp_http",
            &self.otlp_http_trusted_proxy_cidrs,
            self.otlp_http_forwarded_hops,
        );
        append_proxy_trust_reference(
            &mut rendered,
            "loki_push",
            &self.loki_push_trusted_proxy_cidrs,
            self.loki_push_forwarded_hops,
        );
        for destination in &self.export_destinations {
            rendered.push_str("\n\n[[export.destination]]\nname = ");
            rendered.push_str(&super::render_toml_basic_string(&destination.name));
            rendered.push_str("\nidentity = ");
            rendered.push_str(&super::render_toml_basic_string(&hexadecimal_identity(
                destination.identity,
            )));
            rendered.push_str("\nallowed_tenants = [");
            for (index, tenant) in destination.allowed_tenants.iter().enumerate() {
                if index != 0 {
                    rendered.push_str(", ");
                }
                rendered.push_str(&super::render_toml_basic_string(
                    &tenant.to_canonical_text(),
                ));
            }
            rendered.push(']');
        }
        for (index, warning) in self.security_warnings().iter().enumerate() {
            if index == 0 {
                rendered.push_str("\n\n[warnings]");
            }
            rendered.push_str("\nwarning_");
            rendered.push_str(&index.to_string());
            rendered.push_str(" = ");
            rendered.push_str(&super::render_toml_basic_string(warning.message()));
        }
        rendered.push_str("\n\n[storage]\ndata_directory = ");
        rendered.push_str(&super::render_toml_basic_string(&self.data_directory));
        rendered.push_str("\nsecrets_directory = ");
        rendered.push_str(&super::render_toml_basic_string(&self.secrets_directory));
        rendered.push_str("\n\n[security]\nlocal_key_file = \"<redacted>\"\n");
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

    /// Produces the active successor after applying only settings the
    /// Configuration Contract classifies as live-reloadable. Callers retain
    /// the complete candidate separately when restart-required settings are
    /// pending, so no consumer can observe a partly applied candidate.
    #[must_use]
    pub fn with_live_changes_from(&self, candidate: &Self) -> Self {
        let mut active = self.clone();
        for definition in contract::SETTING_DEFINITIONS {
            let setting = definition.setting();
            if setting.mutability() != MutabilityClass::LiveReloadable
                || !self.setting_differs(candidate, setting)
            {
                continue;
            }
            match setting {
                Setting::DiagnosticsLogLevel => active.log_level = candidate.log_level,
                Setting::SchemaVersion
                | Setting::RuntimeShutdownGraceSeconds
                | Setting::RuntimeMaxRegisteredTenants
                | Setting::ListenerControlPath
                | Setting::ListenerAdmissionRatePerSecond
                | Setting::ListenerPerAddressAdmissionRatePerSecond
                | Setting::ListenerOperationsBindAddress
                | Setting::ListenerOperationsTransport
                | Setting::ListenerOperationsAcceptedSocketLimit
                | Setting::ListenerOperationsPerAddressAcceptedSocketLimit
                | Setting::ListenerOperationsTlsCertificateFile
                | Setting::ListenerOperationsTlsPrivateKeyFile
                | Setting::ListenerOperationsTlsClientCaFile
                | Setting::ListenerOperationsTrustedProxyCidrs
                | Setting::ListenerOperationsForwardedHops
                | Setting::ListenerApiBindAddress
                | Setting::ListenerApiTransport
                | Setting::ListenerApiAcceptedSocketLimit
                | Setting::ListenerApiPerAddressAcceptedSocketLimit
                | Setting::ListenerApiTrustedProxyCidrs
                | Setting::ListenerApiForwardedHops
                | Setting::ListenerApiTlsCertificateFile
                | Setting::ListenerApiTlsPrivateKeyFile
                | Setting::ListenerApiTlsClientCaFile
                | Setting::ListenerOtlpGrpcBindAddress
                | Setting::ListenerOtlpGrpcTransport
                | Setting::ListenerOtlpGrpcAcceptedSocketLimit
                | Setting::ListenerOtlpGrpcPerAddressAcceptedSocketLimit
                | Setting::ListenerOtlpGrpcTlsCertificateFile
                | Setting::ListenerOtlpGrpcTlsPrivateKeyFile
                | Setting::ListenerOtlpGrpcTlsClientCaFile
                | Setting::ListenerOtlpGrpcTrustedProxyCidrs
                | Setting::ListenerOtlpGrpcForwardedHops
                | Setting::ListenerOtlpHttpBindAddress
                | Setting::ListenerOtlpHttpTransport
                | Setting::ListenerOtlpHttpAcceptedSocketLimit
                | Setting::ListenerOtlpHttpPerAddressAcceptedSocketLimit
                | Setting::ListenerOtlpHttpTlsCertificateFile
                | Setting::ListenerOtlpHttpTlsPrivateKeyFile
                | Setting::ListenerOtlpHttpTlsClientCaFile
                | Setting::ListenerOtlpHttpTrustedProxyCidrs
                | Setting::ListenerOtlpHttpForwardedHops
                | Setting::ListenerLokiPushBindAddress
                | Setting::ListenerLokiPushTransport
                | Setting::ListenerLokiPushAcceptedSocketLimit
                | Setting::ListenerLokiPushPerAddressAcceptedSocketLimit
                | Setting::ListenerLokiPushTlsCertificateFile
                | Setting::ListenerLokiPushTlsPrivateKeyFile
                | Setting::ListenerLokiPushTlsClientCaFile
                | Setting::ListenerLokiPushTrustedProxyCidrs
                | Setting::ListenerLokiPushForwardedHops
                | Setting::ListenerOperationsTlsHandshakeLimit
                | Setting::ListenerOperationsTlsHandshakeDeadlineSeconds
                | Setting::ListenerOperationsHeaderDeadlineSeconds
                | Setting::ListenerOperationsBodyDeadlineSeconds
                | Setting::ListenerOperationsRequestDeadlineSeconds
                | Setting::ListenerOperationsIdleDeadlineSeconds
                | Setting::ListenerApiTlsHandshakeLimit
                | Setting::ListenerApiTlsHandshakeDeadlineSeconds
                | Setting::ListenerApiHeaderDeadlineSeconds
                | Setting::ListenerApiBodyDeadlineSeconds
                | Setting::ListenerApiRequestDeadlineSeconds
                | Setting::ListenerApiIdleDeadlineSeconds
                | Setting::ListenerApiHttp2MaxConcurrentStreams
                | Setting::ListenerApiHttp2InitialStreamWindowBytes
                | Setting::ListenerApiHttp2InitialConnectionWindowBytes
                | Setting::ListenerApiHttp2MaxFrameBytes
                | Setting::ListenerApiHttp2MaxHeaderListBytes
                | Setting::ListenerApiHttp2MinimumPingIntervalSeconds
                | Setting::ListenerApiCorsAllowedOrigins
                | Setting::ListenerOtlpGrpcTlsHandshakeLimit
                | Setting::ListenerOtlpGrpcTlsHandshakeDeadlineSeconds
                | Setting::ListenerOtlpGrpcHeaderDeadlineSeconds
                | Setting::ListenerOtlpGrpcBodyDeadlineSeconds
                | Setting::ListenerOtlpGrpcRequestDeadlineSeconds
                | Setting::ListenerOtlpGrpcIdleDeadlineSeconds
                | Setting::ListenerOtlpGrpcHttp2MaxConcurrentStreams
                | Setting::ListenerOtlpGrpcHttp2InitialStreamWindowBytes
                | Setting::ListenerOtlpGrpcHttp2InitialConnectionWindowBytes
                | Setting::ListenerOtlpGrpcHttp2MaxFrameBytes
                | Setting::ListenerOtlpGrpcHttp2MaxHeaderListBytes
                | Setting::ListenerOtlpGrpcHttp2MinimumPingIntervalSeconds
                | Setting::ListenerOtlpGrpcMaxMessageBytes
                | Setting::ListenerOtlpHttpTlsHandshakeLimit
                | Setting::ListenerOtlpHttpTlsHandshakeDeadlineSeconds
                | Setting::ListenerOtlpHttpHeaderDeadlineSeconds
                | Setting::ListenerOtlpHttpBodyDeadlineSeconds
                | Setting::ListenerOtlpHttpRequestDeadlineSeconds
                | Setting::ListenerOtlpHttpIdleDeadlineSeconds
                | Setting::ListenerLokiPushTlsHandshakeLimit
                | Setting::ListenerLokiPushTlsHandshakeDeadlineSeconds
                | Setting::ListenerLokiPushHeaderDeadlineSeconds
                | Setting::ListenerLokiPushBodyDeadlineSeconds
                | Setting::ListenerLokiPushRequestDeadlineSeconds
                | Setting::ListenerLokiPushIdleDeadlineSeconds
                | Setting::StorageDataDirectory
                | Setting::StorageSecretsDirectory
                | Setting::SecurityLocalKeyFile
                | Setting::ExportDestinations => {},
            }
        }
        active
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
            Setting::ListenerAdmissionRatePerSecond => {
                self.admission_rate_per_second != other.admission_rate_per_second
            },
            Setting::ListenerPerAddressAdmissionRatePerSecond => {
                self.per_address_admission_rate_per_second
                    != other.per_address_admission_rate_per_second
            },
            Setting::ListenerOperationsBindAddress => {
                self.operations_bind_address != other.operations_bind_address
            },
            Setting::ListenerOperationsTransport => {
                self.operations_transport != other.operations_transport
            },
            Setting::ListenerOperationsAcceptedSocketLimit => {
                self.operations_accepted_socket_limit != other.operations_accepted_socket_limit
            },
            Setting::ListenerOperationsPerAddressAcceptedSocketLimit => {
                self.operations_per_address_accepted_socket_limit
                    != other.operations_per_address_accepted_socket_limit
            },
            Setting::ListenerOperationsTlsCertificateFile => {
                self.operations_tls_certificate_file != other.operations_tls_certificate_file
            },
            Setting::ListenerOperationsTlsPrivateKeyFile => {
                self.operations_tls_private_key_file != other.operations_tls_private_key_file
            },
            Setting::ListenerOperationsTlsClientCaFile => {
                self.operations_tls_client_ca_file != other.operations_tls_client_ca_file
            },
            Setting::ListenerOperationsTrustedProxyCidrs => {
                self.operations_trusted_proxy_cidrs != other.operations_trusted_proxy_cidrs
            },
            Setting::ListenerOperationsForwardedHops => {
                self.operations_forwarded_hops != other.operations_forwarded_hops
            },
            Setting::ListenerApiBindAddress => self.api_bind_address != other.api_bind_address,
            Setting::ListenerApiTransport => self.api_transport != other.api_transport,
            Setting::ListenerApiAcceptedSocketLimit => {
                self.api_accepted_socket_limit != other.api_accepted_socket_limit
            },
            Setting::ListenerApiPerAddressAcceptedSocketLimit => {
                self.api_per_address_accepted_socket_limit
                    != other.api_per_address_accepted_socket_limit
            },
            Setting::ListenerApiTrustedProxyCidrs => {
                self.api_trusted_proxy_cidrs != other.api_trusted_proxy_cidrs
            },
            Setting::ListenerApiCorsAllowedOrigins => {
                self.api_cors_allowed_origins != other.api_cors_allowed_origins
            },
            Setting::ListenerApiForwardedHops => {
                self.api_forwarded_hops != other.api_forwarded_hops
            },
            Setting::ListenerApiTlsCertificateFile => {
                self.api_tls_certificate_file != other.api_tls_certificate_file
            },
            Setting::ListenerApiTlsPrivateKeyFile => {
                self.api_tls_private_key_file != other.api_tls_private_key_file
            },
            Setting::ListenerApiTlsClientCaFile => {
                self.api_tls_client_ca_file != other.api_tls_client_ca_file
            },
            Setting::ListenerOtlpGrpcBindAddress => {
                self.otlp_grpc_bind_address != other.otlp_grpc_bind_address
            },
            Setting::ListenerOtlpGrpcTransport => {
                self.otlp_grpc_transport != other.otlp_grpc_transport
            },
            Setting::ListenerOtlpGrpcAcceptedSocketLimit => {
                self.otlp_grpc_accepted_socket_limit != other.otlp_grpc_accepted_socket_limit
            },
            Setting::ListenerOtlpGrpcPerAddressAcceptedSocketLimit => {
                self.otlp_grpc_per_address_accepted_socket_limit
                    != other.otlp_grpc_per_address_accepted_socket_limit
            },
            Setting::ListenerOtlpGrpcTlsCertificateFile => {
                self.otlp_grpc_tls_certificate_file != other.otlp_grpc_tls_certificate_file
            },
            Setting::ListenerOtlpGrpcTlsPrivateKeyFile => {
                self.otlp_grpc_tls_private_key_file != other.otlp_grpc_tls_private_key_file
            },
            Setting::ListenerOtlpGrpcTlsClientCaFile => {
                self.otlp_grpc_tls_client_ca_file != other.otlp_grpc_tls_client_ca_file
            },
            Setting::ListenerOtlpGrpcTrustedProxyCidrs => {
                self.otlp_grpc_trusted_proxy_cidrs != other.otlp_grpc_trusted_proxy_cidrs
            },
            Setting::ListenerOtlpGrpcForwardedHops => {
                self.otlp_grpc_forwarded_hops != other.otlp_grpc_forwarded_hops
            },
            Setting::ListenerOtlpHttpBindAddress => {
                self.otlp_http_bind_address != other.otlp_http_bind_address
            },
            Setting::ListenerOtlpHttpTransport => {
                self.otlp_http_transport != other.otlp_http_transport
            },
            Setting::ListenerOtlpHttpAcceptedSocketLimit => {
                self.otlp_http_accepted_socket_limit != other.otlp_http_accepted_socket_limit
            },
            Setting::ListenerOtlpHttpPerAddressAcceptedSocketLimit => {
                self.otlp_http_per_address_accepted_socket_limit
                    != other.otlp_http_per_address_accepted_socket_limit
            },
            Setting::ListenerOtlpHttpTlsCertificateFile => {
                self.otlp_http_tls_certificate_file != other.otlp_http_tls_certificate_file
            },
            Setting::ListenerOtlpHttpTlsPrivateKeyFile => {
                self.otlp_http_tls_private_key_file != other.otlp_http_tls_private_key_file
            },
            Setting::ListenerOtlpHttpTlsClientCaFile => {
                self.otlp_http_tls_client_ca_file != other.otlp_http_tls_client_ca_file
            },
            Setting::ListenerOtlpHttpTrustedProxyCidrs => {
                self.otlp_http_trusted_proxy_cidrs != other.otlp_http_trusted_proxy_cidrs
            },
            Setting::ListenerOtlpHttpForwardedHops => {
                self.otlp_http_forwarded_hops != other.otlp_http_forwarded_hops
            },
            Setting::ListenerLokiPushBindAddress => {
                self.loki_push_bind_address != other.loki_push_bind_address
            },
            Setting::ListenerLokiPushTransport => {
                self.loki_push_transport != other.loki_push_transport
            },
            Setting::ListenerLokiPushAcceptedSocketLimit => {
                self.loki_push_accepted_socket_limit != other.loki_push_accepted_socket_limit
            },
            Setting::ListenerLokiPushPerAddressAcceptedSocketLimit => {
                self.loki_push_per_address_accepted_socket_limit
                    != other.loki_push_per_address_accepted_socket_limit
            },
            Setting::ListenerLokiPushTlsCertificateFile => {
                self.loki_push_tls_certificate_file != other.loki_push_tls_certificate_file
            },
            Setting::ListenerLokiPushTlsPrivateKeyFile => {
                self.loki_push_tls_private_key_file != other.loki_push_tls_private_key_file
            },
            Setting::ListenerLokiPushTlsClientCaFile => {
                self.loki_push_tls_client_ca_file != other.loki_push_tls_client_ca_file
            },
            Setting::ListenerLokiPushTrustedProxyCidrs => {
                self.loki_push_trusted_proxy_cidrs != other.loki_push_trusted_proxy_cidrs
            },
            Setting::ListenerLokiPushForwardedHops => {
                self.loki_push_forwarded_hops != other.loki_push_forwarded_hops
            },
            Setting::ListenerOperationsTlsHandshakeLimit => {
                self.operations_connection_protection.tls_handshake_limit
                    != other.operations_connection_protection.tls_handshake_limit
            },
            Setting::ListenerOperationsTlsHandshakeDeadlineSeconds => {
                self.operations_connection_protection
                    .tls_handshake_deadline_seconds
                    != other
                        .operations_connection_protection
                        .tls_handshake_deadline_seconds
            },
            Setting::ListenerOperationsHeaderDeadlineSeconds => {
                self.operations_connection_protection
                    .header_deadline_seconds
                    != other
                        .operations_connection_protection
                        .header_deadline_seconds
            },
            Setting::ListenerOperationsBodyDeadlineSeconds => {
                self.operations_connection_protection.body_deadline_seconds
                    != other.operations_connection_protection.body_deadline_seconds
            },
            Setting::ListenerOperationsRequestDeadlineSeconds => {
                self.operations_connection_protection
                    .request_deadline_seconds
                    != other
                        .operations_connection_protection
                        .request_deadline_seconds
            },
            Setting::ListenerOperationsIdleDeadlineSeconds => {
                self.operations_connection_protection.idle_deadline_seconds
                    != other.operations_connection_protection.idle_deadline_seconds
            },
            Setting::ListenerApiTlsHandshakeLimit => {
                self.api_connection_protection.tls_handshake_limit
                    != other.api_connection_protection.tls_handshake_limit
            },
            Setting::ListenerApiTlsHandshakeDeadlineSeconds => {
                self.api_connection_protection
                    .tls_handshake_deadline_seconds
                    != other
                        .api_connection_protection
                        .tls_handshake_deadline_seconds
            },
            Setting::ListenerApiHeaderDeadlineSeconds => {
                self.api_connection_protection.header_deadline_seconds
                    != other.api_connection_protection.header_deadline_seconds
            },
            Setting::ListenerApiBodyDeadlineSeconds => {
                self.api_connection_protection.body_deadline_seconds
                    != other.api_connection_protection.body_deadline_seconds
            },
            Setting::ListenerApiRequestDeadlineSeconds => {
                self.api_connection_protection.request_deadline_seconds
                    != other.api_connection_protection.request_deadline_seconds
            },
            Setting::ListenerApiIdleDeadlineSeconds => {
                self.api_connection_protection.idle_deadline_seconds
                    != other.api_connection_protection.idle_deadline_seconds
            },
            Setting::ListenerApiHttp2MaxConcurrentStreams => {
                self.api_http2_profile.max_concurrent_streams
                    != other.api_http2_profile.max_concurrent_streams
            },
            Setting::ListenerApiHttp2InitialStreamWindowBytes => {
                self.api_http2_profile.initial_stream_window_bytes
                    != other.api_http2_profile.initial_stream_window_bytes
            },
            Setting::ListenerApiHttp2InitialConnectionWindowBytes => {
                self.api_http2_profile.initial_connection_window_bytes
                    != other.api_http2_profile.initial_connection_window_bytes
            },
            Setting::ListenerApiHttp2MaxFrameBytes => {
                self.api_http2_profile.max_frame_bytes != other.api_http2_profile.max_frame_bytes
            },
            Setting::ListenerApiHttp2MaxHeaderListBytes => {
                self.api_http2_profile.max_header_list_bytes
                    != other.api_http2_profile.max_header_list_bytes
            },
            Setting::ListenerApiHttp2MinimumPingIntervalSeconds => {
                self.api_http2_profile.minimum_ping_interval_seconds
                    != other.api_http2_profile.minimum_ping_interval_seconds
            },
            Setting::ListenerOtlpGrpcTlsHandshakeLimit => {
                self.otlp_grpc_connection_protection.tls_handshake_limit
                    != other.otlp_grpc_connection_protection.tls_handshake_limit
            },
            Setting::ListenerOtlpGrpcTlsHandshakeDeadlineSeconds => {
                self.otlp_grpc_connection_protection
                    .tls_handshake_deadline_seconds
                    != other
                        .otlp_grpc_connection_protection
                        .tls_handshake_deadline_seconds
            },
            Setting::ListenerOtlpGrpcHeaderDeadlineSeconds => {
                self.otlp_grpc_connection_protection.header_deadline_seconds
                    != other
                        .otlp_grpc_connection_protection
                        .header_deadline_seconds
            },
            Setting::ListenerOtlpGrpcBodyDeadlineSeconds => {
                self.otlp_grpc_connection_protection.body_deadline_seconds
                    != other.otlp_grpc_connection_protection.body_deadline_seconds
            },
            Setting::ListenerOtlpGrpcRequestDeadlineSeconds => {
                self.otlp_grpc_connection_protection
                    .request_deadline_seconds
                    != other
                        .otlp_grpc_connection_protection
                        .request_deadline_seconds
            },
            Setting::ListenerOtlpGrpcIdleDeadlineSeconds => {
                self.otlp_grpc_connection_protection.idle_deadline_seconds
                    != other.otlp_grpc_connection_protection.idle_deadline_seconds
            },
            Setting::ListenerOtlpGrpcHttp2MaxConcurrentStreams => {
                self.otlp_grpc_http2_profile.max_concurrent_streams
                    != other.otlp_grpc_http2_profile.max_concurrent_streams
            },
            Setting::ListenerOtlpGrpcHttp2InitialStreamWindowBytes => {
                self.otlp_grpc_http2_profile.initial_stream_window_bytes
                    != other.otlp_grpc_http2_profile.initial_stream_window_bytes
            },
            Setting::ListenerOtlpGrpcHttp2InitialConnectionWindowBytes => {
                self.otlp_grpc_http2_profile.initial_connection_window_bytes
                    != other
                        .otlp_grpc_http2_profile
                        .initial_connection_window_bytes
            },
            Setting::ListenerOtlpGrpcHttp2MaxFrameBytes => {
                self.otlp_grpc_http2_profile.max_frame_bytes
                    != other.otlp_grpc_http2_profile.max_frame_bytes
            },
            Setting::ListenerOtlpGrpcHttp2MaxHeaderListBytes => {
                self.otlp_grpc_http2_profile.max_header_list_bytes
                    != other.otlp_grpc_http2_profile.max_header_list_bytes
            },
            Setting::ListenerOtlpGrpcHttp2MinimumPingIntervalSeconds => {
                self.otlp_grpc_http2_profile.minimum_ping_interval_seconds
                    != other.otlp_grpc_http2_profile.minimum_ping_interval_seconds
            },
            Setting::ListenerOtlpGrpcMaxMessageBytes => {
                self.otlp_grpc_http2_profile.max_grpc_message_bytes
                    != other.otlp_grpc_http2_profile.max_grpc_message_bytes
            },
            Setting::ListenerOtlpHttpTlsHandshakeLimit => {
                self.otlp_http_connection_protection.tls_handshake_limit
                    != other.otlp_http_connection_protection.tls_handshake_limit
            },
            Setting::ListenerOtlpHttpTlsHandshakeDeadlineSeconds => {
                self.otlp_http_connection_protection
                    .tls_handshake_deadline_seconds
                    != other
                        .otlp_http_connection_protection
                        .tls_handshake_deadline_seconds
            },
            Setting::ListenerOtlpHttpHeaderDeadlineSeconds => {
                self.otlp_http_connection_protection.header_deadline_seconds
                    != other
                        .otlp_http_connection_protection
                        .header_deadline_seconds
            },
            Setting::ListenerOtlpHttpBodyDeadlineSeconds => {
                self.otlp_http_connection_protection.body_deadline_seconds
                    != other.otlp_http_connection_protection.body_deadline_seconds
            },
            Setting::ListenerOtlpHttpRequestDeadlineSeconds => {
                self.otlp_http_connection_protection
                    .request_deadline_seconds
                    != other
                        .otlp_http_connection_protection
                        .request_deadline_seconds
            },
            Setting::ListenerOtlpHttpIdleDeadlineSeconds => {
                self.otlp_http_connection_protection.idle_deadline_seconds
                    != other.otlp_http_connection_protection.idle_deadline_seconds
            },
            Setting::ListenerLokiPushTlsHandshakeLimit => {
                self.loki_push_connection_protection.tls_handshake_limit
                    != other.loki_push_connection_protection.tls_handshake_limit
            },
            Setting::ListenerLokiPushTlsHandshakeDeadlineSeconds => {
                self.loki_push_connection_protection
                    .tls_handshake_deadline_seconds
                    != other
                        .loki_push_connection_protection
                        .tls_handshake_deadline_seconds
            },
            Setting::ListenerLokiPushHeaderDeadlineSeconds => {
                self.loki_push_connection_protection.header_deadline_seconds
                    != other
                        .loki_push_connection_protection
                        .header_deadline_seconds
            },
            Setting::ListenerLokiPushBodyDeadlineSeconds => {
                self.loki_push_connection_protection.body_deadline_seconds
                    != other.loki_push_connection_protection.body_deadline_seconds
            },
            Setting::ListenerLokiPushRequestDeadlineSeconds => {
                self.loki_push_connection_protection
                    .request_deadline_seconds
                    != other
                        .loki_push_connection_protection
                        .request_deadline_seconds
            },
            Setting::ListenerLokiPushIdleDeadlineSeconds => {
                self.loki_push_connection_protection.idle_deadline_seconds
                    != other.loki_push_connection_protection.idle_deadline_seconds
            },
            Setting::StorageDataDirectory => self.data_directory != other.data_directory,
            Setting::StorageSecretsDirectory => self.secrets_directory != other.secrets_directory,
            Setting::SecurityLocalKeyFile => self.local_key_file != other.local_key_file,
            Setting::ExportDestinations => self.export_destinations != other.export_destinations,
        }
    }

    fn canonical_identity_value(&self, setting: Setting) -> String {
        match setting {
            Setting::SchemaVersion => self.schema_version.to_string(),
            Setting::DiagnosticsLogLevel => self.log_level.as_str().to_owned(),
            Setting::RuntimeShutdownGraceSeconds => self.shutdown_grace_seconds.to_string(),
            Setting::RuntimeMaxRegisteredTenants => self.max_registered_tenants.to_string(),
            Setting::ListenerControlPath => self.control_path.clone(),
            Setting::ListenerAdmissionRatePerSecond => {
                self.admission_rate_per_second.get().to_string()
            },
            Setting::ListenerPerAddressAdmissionRatePerSecond => {
                self.per_address_admission_rate_per_second.get().to_string()
            },
            Setting::ListenerOperationsBindAddress => self.operations_bind_address.to_string(),
            Setting::ListenerOperationsTransport => self.operations_transport.as_str().to_owned(),
            Setting::ListenerOperationsAcceptedSocketLimit => {
                self.operations_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerOperationsPerAddressAcceptedSocketLimit => self
                .operations_per_address_accepted_socket_limit
                .get()
                .to_string(),
            Setting::ListenerOperationsTlsCertificateFile => {
                self.operations_tls_certificate_file.path.clone()
            },
            Setting::ListenerOperationsTlsPrivateKeyFile => {
                self.operations_tls_private_key_file.path.clone()
            },
            Setting::ListenerOperationsTlsClientCaFile => {
                self.operations_tls_client_ca_file.path.clone()
            },
            Setting::ListenerOperationsTrustedProxyCidrs => {
                trusted_proxy_cidrs_value(&self.operations_trusted_proxy_cidrs)
            },
            Setting::ListenerOperationsForwardedHops => {
                forwarded_hops_value(self.operations_forwarded_hops)
            },
            Setting::ListenerApiBindAddress => self.api_bind_address.to_string(),
            Setting::ListenerApiTransport => self.api_transport.as_str().to_owned(),
            Setting::ListenerApiAcceptedSocketLimit => {
                self.api_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerApiPerAddressAcceptedSocketLimit => {
                self.api_per_address_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerApiTrustedProxyCidrs => {
                trusted_proxy_cidrs_value(&self.api_trusted_proxy_cidrs)
            },
            Setting::ListenerApiCorsAllowedOrigins => {
                cors_allowed_origins_value(&self.api_cors_allowed_origins)
            },
            Setting::ListenerApiForwardedHops => forwarded_hops_value(self.api_forwarded_hops),
            Setting::ListenerApiTlsCertificateFile => self.api_tls_certificate_file.path.clone(),
            Setting::ListenerApiTlsPrivateKeyFile => self.api_tls_private_key_file.path.clone(),
            Setting::ListenerApiTlsClientCaFile => self.api_tls_client_ca_file.path.clone(),
            Setting::ListenerOtlpGrpcBindAddress => self.otlp_grpc_bind_address.to_string(),
            Setting::ListenerOtlpGrpcTransport => self.otlp_grpc_transport.as_str().to_owned(),
            Setting::ListenerOtlpGrpcAcceptedSocketLimit => {
                self.otlp_grpc_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerOtlpGrpcPerAddressAcceptedSocketLimit => self
                .otlp_grpc_per_address_accepted_socket_limit
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcTlsCertificateFile => {
                self.otlp_grpc_tls_certificate_file.path.clone()
            },
            Setting::ListenerOtlpGrpcTlsPrivateKeyFile => {
                self.otlp_grpc_tls_private_key_file.path.clone()
            },
            Setting::ListenerOtlpGrpcTlsClientCaFile => {
                self.otlp_grpc_tls_client_ca_file.path.clone()
            },
            Setting::ListenerOtlpGrpcTrustedProxyCidrs => {
                trusted_proxy_cidrs_value(&self.otlp_grpc_trusted_proxy_cidrs)
            },
            Setting::ListenerOtlpGrpcForwardedHops => {
                forwarded_hops_value(self.otlp_grpc_forwarded_hops)
            },
            Setting::ListenerOtlpHttpBindAddress => self.otlp_http_bind_address.to_string(),
            Setting::ListenerOtlpHttpTransport => self.otlp_http_transport.as_str().to_owned(),
            Setting::ListenerOtlpHttpAcceptedSocketLimit => {
                self.otlp_http_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerOtlpHttpPerAddressAcceptedSocketLimit => self
                .otlp_http_per_address_accepted_socket_limit
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpTlsCertificateFile => {
                self.otlp_http_tls_certificate_file.path.clone()
            },
            Setting::ListenerOtlpHttpTlsPrivateKeyFile => {
                self.otlp_http_tls_private_key_file.path.clone()
            },
            Setting::ListenerOtlpHttpTlsClientCaFile => {
                self.otlp_http_tls_client_ca_file.path.clone()
            },
            Setting::ListenerOtlpHttpTrustedProxyCidrs => {
                trusted_proxy_cidrs_value(&self.otlp_http_trusted_proxy_cidrs)
            },
            Setting::ListenerOtlpHttpForwardedHops => {
                forwarded_hops_value(self.otlp_http_forwarded_hops)
            },
            Setting::ListenerLokiPushBindAddress => self.loki_push_bind_address.to_string(),
            Setting::ListenerLokiPushTransport => self.loki_push_transport.as_str().to_owned(),
            Setting::ListenerLokiPushAcceptedSocketLimit => {
                self.loki_push_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerLokiPushPerAddressAcceptedSocketLimit => self
                .loki_push_per_address_accepted_socket_limit
                .get()
                .to_string(),
            Setting::ListenerLokiPushTlsCertificateFile => {
                self.loki_push_tls_certificate_file.path.clone()
            },
            Setting::ListenerLokiPushTlsPrivateKeyFile => {
                self.loki_push_tls_private_key_file.path.clone()
            },
            Setting::ListenerLokiPushTlsClientCaFile => {
                self.loki_push_tls_client_ca_file.path.clone()
            },
            Setting::ListenerLokiPushTrustedProxyCidrs => {
                trusted_proxy_cidrs_value(&self.loki_push_trusted_proxy_cidrs)
            },
            Setting::ListenerLokiPushForwardedHops => {
                forwarded_hops_value(self.loki_push_forwarded_hops)
            },
            Setting::ListenerOperationsTlsHandshakeLimit => self
                .operations_connection_protection
                .tls_handshake_limit
                .get()
                .to_string(),
            Setting::ListenerOperationsTlsHandshakeDeadlineSeconds => self
                .operations_connection_protection
                .tls_handshake_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOperationsHeaderDeadlineSeconds => self
                .operations_connection_protection
                .header_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOperationsBodyDeadlineSeconds => self
                .operations_connection_protection
                .body_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOperationsRequestDeadlineSeconds => self
                .operations_connection_protection
                .request_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOperationsIdleDeadlineSeconds => self
                .operations_connection_protection
                .idle_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiTlsHandshakeLimit => self
                .api_connection_protection
                .tls_handshake_limit
                .get()
                .to_string(),
            Setting::ListenerApiTlsHandshakeDeadlineSeconds => self
                .api_connection_protection
                .tls_handshake_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiHeaderDeadlineSeconds => self
                .api_connection_protection
                .header_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiBodyDeadlineSeconds => self
                .api_connection_protection
                .body_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiRequestDeadlineSeconds => self
                .api_connection_protection
                .request_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiIdleDeadlineSeconds => self
                .api_connection_protection
                .idle_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiHttp2MaxConcurrentStreams => self
                .api_http2_profile
                .max_concurrent_streams
                .get()
                .to_string(),
            Setting::ListenerApiHttp2InitialStreamWindowBytes => self
                .api_http2_profile
                .initial_stream_window_bytes
                .get()
                .to_string(),
            Setting::ListenerApiHttp2InitialConnectionWindowBytes => self
                .api_http2_profile
                .initial_connection_window_bytes
                .get()
                .to_string(),
            Setting::ListenerApiHttp2MaxFrameBytes => {
                self.api_http2_profile.max_frame_bytes.get().to_string()
            },
            Setting::ListenerApiHttp2MaxHeaderListBytes => self
                .api_http2_profile
                .max_header_list_bytes
                .get()
                .to_string(),
            Setting::ListenerApiHttp2MinimumPingIntervalSeconds => self
                .api_http2_profile
                .minimum_ping_interval_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcTlsHandshakeLimit => self
                .otlp_grpc_connection_protection
                .tls_handshake_limit
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcTlsHandshakeDeadlineSeconds => self
                .otlp_grpc_connection_protection
                .tls_handshake_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHeaderDeadlineSeconds => self
                .otlp_grpc_connection_protection
                .header_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcBodyDeadlineSeconds => self
                .otlp_grpc_connection_protection
                .body_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcRequestDeadlineSeconds => self
                .otlp_grpc_connection_protection
                .request_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcIdleDeadlineSeconds => self
                .otlp_grpc_connection_protection
                .idle_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2MaxConcurrentStreams => self
                .otlp_grpc_http2_profile
                .max_concurrent_streams
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2InitialStreamWindowBytes => self
                .otlp_grpc_http2_profile
                .initial_stream_window_bytes
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2InitialConnectionWindowBytes => self
                .otlp_grpc_http2_profile
                .initial_connection_window_bytes
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2MaxFrameBytes => self
                .otlp_grpc_http2_profile
                .max_frame_bytes
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2MaxHeaderListBytes => self
                .otlp_grpc_http2_profile
                .max_header_list_bytes
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2MinimumPingIntervalSeconds => self
                .otlp_grpc_http2_profile
                .minimum_ping_interval_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcMaxMessageBytes => self
                .otlp_grpc_http2_profile
                .max_grpc_message_bytes
                .map(NonZeroU32::get)
                .unwrap_or_default()
                .to_string(),
            Setting::ListenerOtlpHttpTlsHandshakeLimit => self
                .otlp_http_connection_protection
                .tls_handshake_limit
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpTlsHandshakeDeadlineSeconds => self
                .otlp_http_connection_protection
                .tls_handshake_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpHeaderDeadlineSeconds => self
                .otlp_http_connection_protection
                .header_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpBodyDeadlineSeconds => self
                .otlp_http_connection_protection
                .body_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpRequestDeadlineSeconds => self
                .otlp_http_connection_protection
                .request_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpIdleDeadlineSeconds => self
                .otlp_http_connection_protection
                .idle_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerLokiPushTlsHandshakeLimit => self
                .loki_push_connection_protection
                .tls_handshake_limit
                .get()
                .to_string(),
            Setting::ListenerLokiPushTlsHandshakeDeadlineSeconds => self
                .loki_push_connection_protection
                .tls_handshake_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerLokiPushHeaderDeadlineSeconds => self
                .loki_push_connection_protection
                .header_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerLokiPushBodyDeadlineSeconds => self
                .loki_push_connection_protection
                .body_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerLokiPushRequestDeadlineSeconds => self
                .loki_push_connection_protection
                .request_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerLokiPushIdleDeadlineSeconds => self
                .loki_push_connection_protection
                .idle_deadline_seconds
                .get()
                .to_string(),
            Setting::StorageDataDirectory => self.data_directory.clone(),
            Setting::StorageSecretsDirectory => self.secrets_directory.clone(),
            Setting::SecurityLocalKeyFile => self.local_key_file.path.clone(),
            Setting::ExportDestinations => self.redacted_export_destinations(),
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
            Setting::ListenerAdmissionRatePerSecond => {
                self.admission_rate_per_second.get().to_string()
            },
            Setting::ListenerPerAddressAdmissionRatePerSecond => {
                self.per_address_admission_rate_per_second.get().to_string()
            },
            Setting::ListenerOperationsBindAddress => self.operations_bind_address.to_string(),
            Setting::ListenerOperationsTransport => self.operations_transport.as_str().to_owned(),
            Setting::ListenerOperationsAcceptedSocketLimit => {
                self.operations_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerOperationsPerAddressAcceptedSocketLimit => self
                .operations_per_address_accepted_socket_limit
                .get()
                .to_string(),
            Setting::ListenerOperationsTrustedProxyCidrs => {
                trusted_proxy_cidrs_value(&self.operations_trusted_proxy_cidrs)
            },
            Setting::ListenerOperationsForwardedHops => {
                forwarded_hops_value(self.operations_forwarded_hops)
            },
            Setting::ListenerApiBindAddress => self.api_bind_address.to_string(),
            Setting::ListenerApiTransport => self.api_transport.as_str().to_owned(),
            Setting::ListenerApiAcceptedSocketLimit => {
                self.api_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerApiPerAddressAcceptedSocketLimit => {
                self.api_per_address_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerApiTrustedProxyCidrs => {
                trusted_proxy_cidrs_value(&self.api_trusted_proxy_cidrs)
            },
            Setting::ListenerApiCorsAllowedOrigins => {
                cors_allowed_origins_value(&self.api_cors_allowed_origins)
            },
            Setting::ListenerApiForwardedHops => forwarded_hops_value(self.api_forwarded_hops),
            Setting::ListenerOperationsTlsCertificateFile
            | Setting::ListenerOperationsTlsPrivateKeyFile
            | Setting::ListenerOperationsTlsClientCaFile
            | Setting::ListenerApiTlsCertificateFile
            | Setting::ListenerApiTlsPrivateKeyFile
            | Setting::ListenerApiTlsClientCaFile
            | Setting::ListenerOtlpGrpcTlsCertificateFile
            | Setting::ListenerOtlpGrpcTlsPrivateKeyFile
            | Setting::ListenerOtlpGrpcTlsClientCaFile
            | Setting::ListenerOtlpHttpTlsCertificateFile
            | Setting::ListenerOtlpHttpTlsPrivateKeyFile
            | Setting::ListenerOtlpHttpTlsClientCaFile
            | Setting::ListenerLokiPushTlsCertificateFile
            | Setting::ListenerLokiPushTlsPrivateKeyFile
            | Setting::ListenerLokiPushTlsClientCaFile
            | Setting::SecurityLocalKeyFile => "<redacted>".to_owned(),
            Setting::ListenerOtlpGrpcBindAddress => self.otlp_grpc_bind_address.to_string(),
            Setting::ListenerOtlpGrpcTransport => self.otlp_grpc_transport.as_str().to_owned(),
            Setting::ListenerOtlpGrpcAcceptedSocketLimit => {
                self.otlp_grpc_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerOtlpGrpcPerAddressAcceptedSocketLimit => self
                .otlp_grpc_per_address_accepted_socket_limit
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcTrustedProxyCidrs => {
                trusted_proxy_cidrs_value(&self.otlp_grpc_trusted_proxy_cidrs)
            },
            Setting::ListenerOtlpGrpcForwardedHops => {
                forwarded_hops_value(self.otlp_grpc_forwarded_hops)
            },
            Setting::ListenerOtlpHttpBindAddress => self.otlp_http_bind_address.to_string(),
            Setting::ListenerOtlpHttpTransport => self.otlp_http_transport.as_str().to_owned(),
            Setting::ListenerOtlpHttpAcceptedSocketLimit => {
                self.otlp_http_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerOtlpHttpPerAddressAcceptedSocketLimit => self
                .otlp_http_per_address_accepted_socket_limit
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpTrustedProxyCidrs => {
                trusted_proxy_cidrs_value(&self.otlp_http_trusted_proxy_cidrs)
            },
            Setting::ListenerOtlpHttpForwardedHops => {
                forwarded_hops_value(self.otlp_http_forwarded_hops)
            },
            Setting::ListenerLokiPushBindAddress => self.loki_push_bind_address.to_string(),
            Setting::ListenerLokiPushTransport => self.loki_push_transport.as_str().to_owned(),
            Setting::ListenerLokiPushAcceptedSocketLimit => {
                self.loki_push_accepted_socket_limit.get().to_string()
            },
            Setting::ListenerLokiPushPerAddressAcceptedSocketLimit => self
                .loki_push_per_address_accepted_socket_limit
                .get()
                .to_string(),
            Setting::ListenerLokiPushTrustedProxyCidrs => {
                trusted_proxy_cidrs_value(&self.loki_push_trusted_proxy_cidrs)
            },
            Setting::ListenerLokiPushForwardedHops => {
                forwarded_hops_value(self.loki_push_forwarded_hops)
            },
            Setting::ListenerOperationsTlsHandshakeLimit => self
                .operations_connection_protection
                .tls_handshake_limit
                .get()
                .to_string(),
            Setting::ListenerOperationsTlsHandshakeDeadlineSeconds => self
                .operations_connection_protection
                .tls_handshake_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOperationsHeaderDeadlineSeconds => self
                .operations_connection_protection
                .header_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOperationsBodyDeadlineSeconds => self
                .operations_connection_protection
                .body_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOperationsRequestDeadlineSeconds => self
                .operations_connection_protection
                .request_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOperationsIdleDeadlineSeconds => self
                .operations_connection_protection
                .idle_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiTlsHandshakeLimit => self
                .api_connection_protection
                .tls_handshake_limit
                .get()
                .to_string(),
            Setting::ListenerApiTlsHandshakeDeadlineSeconds => self
                .api_connection_protection
                .tls_handshake_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiHeaderDeadlineSeconds => self
                .api_connection_protection
                .header_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiBodyDeadlineSeconds => self
                .api_connection_protection
                .body_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiRequestDeadlineSeconds => self
                .api_connection_protection
                .request_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiIdleDeadlineSeconds => self
                .api_connection_protection
                .idle_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerApiHttp2MaxConcurrentStreams => self
                .api_http2_profile
                .max_concurrent_streams
                .get()
                .to_string(),
            Setting::ListenerApiHttp2InitialStreamWindowBytes => self
                .api_http2_profile
                .initial_stream_window_bytes
                .get()
                .to_string(),
            Setting::ListenerApiHttp2InitialConnectionWindowBytes => self
                .api_http2_profile
                .initial_connection_window_bytes
                .get()
                .to_string(),
            Setting::ListenerApiHttp2MaxFrameBytes => {
                self.api_http2_profile.max_frame_bytes.get().to_string()
            },
            Setting::ListenerApiHttp2MaxHeaderListBytes => self
                .api_http2_profile
                .max_header_list_bytes
                .get()
                .to_string(),
            Setting::ListenerApiHttp2MinimumPingIntervalSeconds => self
                .api_http2_profile
                .minimum_ping_interval_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcTlsHandshakeLimit => self
                .otlp_grpc_connection_protection
                .tls_handshake_limit
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcTlsHandshakeDeadlineSeconds => self
                .otlp_grpc_connection_protection
                .tls_handshake_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHeaderDeadlineSeconds => self
                .otlp_grpc_connection_protection
                .header_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcBodyDeadlineSeconds => self
                .otlp_grpc_connection_protection
                .body_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcRequestDeadlineSeconds => self
                .otlp_grpc_connection_protection
                .request_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcIdleDeadlineSeconds => self
                .otlp_grpc_connection_protection
                .idle_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2MaxConcurrentStreams => self
                .otlp_grpc_http2_profile
                .max_concurrent_streams
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2InitialStreamWindowBytes => self
                .otlp_grpc_http2_profile
                .initial_stream_window_bytes
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2InitialConnectionWindowBytes => self
                .otlp_grpc_http2_profile
                .initial_connection_window_bytes
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2MaxFrameBytes => self
                .otlp_grpc_http2_profile
                .max_frame_bytes
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2MaxHeaderListBytes => self
                .otlp_grpc_http2_profile
                .max_header_list_bytes
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcHttp2MinimumPingIntervalSeconds => self
                .otlp_grpc_http2_profile
                .minimum_ping_interval_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpGrpcMaxMessageBytes => self
                .otlp_grpc_http2_profile
                .max_grpc_message_bytes
                .map(NonZeroU32::get)
                .unwrap_or_default()
                .to_string(),
            Setting::ListenerOtlpHttpTlsHandshakeLimit => self
                .otlp_http_connection_protection
                .tls_handshake_limit
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpTlsHandshakeDeadlineSeconds => self
                .otlp_http_connection_protection
                .tls_handshake_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpHeaderDeadlineSeconds => self
                .otlp_http_connection_protection
                .header_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpBodyDeadlineSeconds => self
                .otlp_http_connection_protection
                .body_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpRequestDeadlineSeconds => self
                .otlp_http_connection_protection
                .request_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerOtlpHttpIdleDeadlineSeconds => self
                .otlp_http_connection_protection
                .idle_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerLokiPushTlsHandshakeLimit => self
                .loki_push_connection_protection
                .tls_handshake_limit
                .get()
                .to_string(),
            Setting::ListenerLokiPushTlsHandshakeDeadlineSeconds => self
                .loki_push_connection_protection
                .tls_handshake_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerLokiPushHeaderDeadlineSeconds => self
                .loki_push_connection_protection
                .header_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerLokiPushBodyDeadlineSeconds => self
                .loki_push_connection_protection
                .body_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerLokiPushRequestDeadlineSeconds => self
                .loki_push_connection_protection
                .request_deadline_seconds
                .get()
                .to_string(),
            Setting::ListenerLokiPushIdleDeadlineSeconds => self
                .loki_push_connection_protection
                .idle_deadline_seconds
                .get()
                .to_string(),
            Setting::StorageDataDirectory => self.data_directory.clone(),
            Setting::StorageSecretsDirectory => self.secrets_directory.clone(),
            Setting::ExportDestinations => self.redacted_export_destinations(),
        }
    }

    fn redacted_export_destinations(&self) -> String {
        let mut rendered = String::new();
        for (index, destination) in self.export_destinations.iter().enumerate() {
            if index != 0 {
                rendered.push(';');
            }
            rendered.push_str("name=");
            rendered.push_str(&destination.name);
            rendered.push_str(",identity=");
            rendered.push_str(&hexadecimal_identity(destination.identity));
            rendered.push_str(",allowed_tenants=[");
            for (tenant_index, tenant) in destination.allowed_tenants.iter().enumerate() {
                if tenant_index != 0 {
                    rendered.push(',');
                }
                rendered.push_str(&tenant.to_canonical_text());
            }
            rendered.push(']');
        }
        rendered
    }
}

fn update_digest_string(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn trusted_proxy_cidrs_value(cidrs: &[String]) -> String {
    cidrs.join(",")
}

fn cors_allowed_origins_value(origins: &[String]) -> String {
    origins.join(",")
}

fn forwarded_hops_value(hops: Option<NonZeroU8>) -> String {
    hops.map_or_else(|| "0".to_owned(), |hops| hops.get().to_string())
}

fn append_proxy_trust_reference(
    rendered: &mut String,
    role: &str,
    cidrs: &[String],
    forwarded_hops: Option<NonZeroU8>,
) {
    rendered.push_str("\n\n[listener.");
    rendered.push_str(role);
    rendered.push_str("]\ntrusted_proxy_cidrs = [");
    for (index, cidr) in cidrs.iter().enumerate() {
        if index != 0 {
            rendered.push_str(", ");
        }
        rendered.push_str(&super::render_toml_basic_string(cidr));
    }
    rendered.push_str("]\nforwarded_hops = ");
    rendered.push_str(&forwarded_hops_value(forwarded_hops));
}

fn append_accepted_socket_limits(
    rendered: &mut String,
    role: &str,
    global: NonZeroU16,
    per_address: NonZeroU16,
) {
    rendered.push('\n');
    rendered.push_str(role);
    rendered.push_str("_accepted_socket_limit = ");
    rendered.push_str(&global.get().to_string());
    rendered.push('\n');
    rendered.push_str(role);
    rendered.push_str("_per_address_accepted_socket_limit = ");
    rendered.push_str(&per_address.get().to_string());
}

fn append_connection_protection_reference(
    rendered: &mut String,
    role: &str,
    protection: ConnectionProtectionProfile,
) {
    for (name, value) in [
        ("tls_handshake_limit", protection.tls_handshake_limit),
        (
            "tls_handshake_deadline_seconds",
            protection.tls_handshake_deadline_seconds,
        ),
        (
            "header_deadline_seconds",
            protection.header_deadline_seconds,
        ),
        ("body_deadline_seconds", protection.body_deadline_seconds),
        (
            "request_deadline_seconds",
            protection.request_deadline_seconds,
        ),
        ("idle_deadline_seconds", protection.idle_deadline_seconds),
    ] {
        rendered.push('\n');
        rendered.push_str(role);
        rendered.push('_');
        rendered.push_str(name);
        rendered.push_str(" = ");
        rendered.push_str(&value.get().to_string());
    }
}

fn append_redacted_listener_tls_references(rendered: &mut String, role: &str) {
    rendered.push('\n');
    rendered.push_str(role);
    rendered.push_str("_tls_certificate_file = \"<redacted>\"\n");
    rendered.push_str(role);
    rendered.push_str("_tls_private_key_file = \"<redacted>\"\n");
    rendered.push_str(role);
    rendered.push_str("_tls_client_ca_file = \"<redacted>\"");
}

fn hexadecimal_identity(identity: [u8; 16]) -> String {
    let mut rendered = String::with_capacity(32);
    for byte in identity {
        rendered.push_str(&format!("{byte:02x}"));
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

/// The operator-visible disposition of desired versus observed configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationDrift {
    diff: ConfigurationDiff,
    disposition: ConfigurationDriftDisposition,
}

impl ConfigurationDrift {
    fn from_diff(diff: ConfigurationDiff) -> Self {
        let disposition = if diff.changes.is_empty() {
            ConfigurationDriftDisposition::None
        } else if diff
            .changes
            .iter()
            .any(|change| change.setting().requires_drift_fence())
        {
            ConfigurationDriftDisposition::Fence
        } else {
            ConfigurationDriftDisposition::Reconcile
        };
        Self { diff, disposition }
    }

    #[must_use]
    pub const fn diff(&self) -> &ConfigurationDiff {
        &self.diff
    }

    #[must_use]
    pub const fn disposition(&self) -> ConfigurationDriftDisposition {
        self.disposition
    }
}

/// The only safe automatic handling for detected configuration drift.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationDriftDisposition {
    None,
    Reconcile,
    Fence,
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
