use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroU8;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use positron_config::{
    ConfigurationInputs, EffectiveConfiguration, Http2Profile, NetworkListenerProfile,
    NetworkListenerRole, NetworkTransport, resolve,
};
use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixListener;

use crate::{
    BoundEndpoint, BoundListener, ConnectionProtection, HealthState, ListenerFactory,
    ListenerFailure, ListenerGeneration, ListenerGenerationFactory, ListenerProfile,
    ListenerRequest, ListenerRole, RegisteredTask, RunningTask, ServiceHandle, TaskCancellation,
    TaskFailure, TaskJoinOutcome, TaskRegistrar, TaskRole, ValidatedListenerSet,
};

mod api_http;
mod connection_admission;
mod generation;
mod h2_observer;
mod loki_http;
mod native_http;
mod otlp_grpc;
mod otlp_http;
mod otlp_outcome;
mod tls;
mod trusted_proxy;

#[cfg(feature = "test-support")]
pub fn fuzz_h2_observer(data: &[u8]) -> usize {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let bounded = &data[..data.len().min(4096)];
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return 0,
    };
    runtime.block_on(async {
        let (mut writer, reader) = tokio::io::duplex(4096);
        let bytes = bounded.to_vec();
        let writer = tokio::spawn(async move {
            let _ = writer.write_all(&bytes).await;
            let _ = writer.shutdown().await;
        });
        let mut observer = h2_observer::H2Observer::new(
            reader,
            Duration::from_millis(1),
            Duration::from_millis(1),
        );
        let mut buffer = [0_u8; 37];
        let mut replayed = 0;
        loop {
            match observer.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => replayed += read,
                Err(_) => break,
            }
        }
        let _ = writer.await;
        replayed
    })
}

use generation::{ActivationGate, NativeGenerationActivation};

pub use tls::{
    ApiTransportProfile, TlsFailure, TlsIdentity, TlsProfile, TlsTrust, TransportProfile,
};
pub use trusted_proxy::{ProxyTrustFailure, TrustedCidr, TrustedProxyPolicy};

/// A fixed deployment fact for one reverse proxy that may supply forwarded
/// actor metadata. It never delegates credential authority to that metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedProxy(TrustedProxyPolicy);

impl TrustedProxy {
    pub fn exact_peer(peer: IpAddr, fixed_hops: u8) -> Result<Self, NativeHostFailure> {
        let prefix = match peer {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let cidr = TrustedCidr::new(peer, prefix).map_err(|_| NativeHostFailure::InvalidBinding)?;
        let fixed_hops = NonZeroU8::new(fixed_hops).ok_or(NativeHostFailure::InvalidBinding)?;
        TrustedProxyPolicy::new(vec![cidr], fixed_hops)
            .map(Self)
            .map_err(|_| NativeHostFailure::InvalidBinding)
    }

    pub fn cidrs(
        cidrs: Vec<TrustedCidr>,
        fixed_hops: NonZeroU8,
    ) -> Result<Self, ProxyTrustFailure> {
        TrustedProxyPolicy::new(cidrs, fixed_hops).map(Self)
    }

    fn validates(&self, peer: SocketAddr, forwarded_for: Option<&str>) -> bool {
        self.0.validates(peer, forwarded_for)
    }
}

#[derive(Clone, Debug)]
pub struct NativeBindings {
    control: PathBuf,
    operations: SocketAddr,
    operations_transport: TransportProfile,
    api: SocketAddr,
    api_transport: ApiTransportProfile,
    otlp_grpc: SocketAddr,
    otlp_grpc_transport: TransportProfile,
    otlp_http: SocketAddr,
    otlp_http_transport: TransportProfile,
    loki_push: SocketAddr,
    loki_push_transport: TransportProfile,
    operations_admission: (NonZeroU16, NonZeroU16),
    api_admission: (NonZeroU16, NonZeroU16),
    otlp_grpc_admission: (NonZeroU16, NonZeroU16),
    otlp_http_admission: (NonZeroU16, NonZeroU16),
    loki_push_admission: (NonZeroU16, NonZeroU16),
    operations_protection: ConnectionProtection,
    api_protection: ConnectionProtection,
    otlp_grpc_protection: ConnectionProtection,
    otlp_http_protection: ConnectionProtection,
    loki_push_protection: ConnectionProtection,
    api_http2_profile: Option<Http2Profile>,
    otlp_grpc_http2_profile: Option<Http2Profile>,
    operations_trusted_proxy: Option<TrustedProxy>,
    api_trusted_proxy: Option<TrustedProxy>,
    otlp_grpc_trusted_proxy: Option<TrustedProxy>,
    otlp_http_trusted_proxy: Option<TrustedProxy>,
    loki_push_trusted_proxy: Option<TrustedProxy>,
}

impl NativeBindings {
    /// Builds the native listener bindings from the one resolved Configuration
    /// Contract. The composition root cannot independently select transport,
    /// certificate, or endpoint values.
    pub fn from_effective(effective: &EffectiveConfiguration) -> Result<Self, NativeHostFailure> {
        let operations = effective_profile(effective, NetworkListenerRole::Operations)?;
        let api = effective_profile(effective, NetworkListenerRole::Api)?;
        let otlp_grpc = effective_profile(effective, NetworkListenerRole::OtlpGrpc)?;
        let otlp_http = effective_profile(effective, NetworkListenerRole::OtlpHttp)?;
        let loki_push = effective_profile(effective, NetworkListenerRole::LokiPush)?;
        let mut bindings = Self::new_with_listener_transports(
            PathBuf::from(effective.control_path()),
            operations.0,
            api.0,
            otlp_grpc.0,
            otlp_http.0,
            loki_push.0,
            operations.1,
            api.1,
            otlp_grpc.1,
            otlp_http.1,
            loki_push.1,
        )?;
        bindings.operations_trusted_proxy = operations.2;
        bindings.api_trusted_proxy = api.2;
        bindings.otlp_grpc_trusted_proxy = otlp_grpc.2;
        bindings.otlp_http_trusted_proxy = otlp_http.2;
        bindings.loki_push_trusted_proxy = loki_push.2;
        bindings.operations_admission = operations.3;
        bindings.api_admission = api.3;
        bindings.otlp_grpc_admission = otlp_grpc.3;
        bindings.otlp_http_admission = otlp_http.3;
        bindings.loki_push_admission = loki_push.3;
        bindings.operations_protection = operations.4;
        bindings.api_protection = api.4;
        bindings.otlp_grpc_protection = otlp_grpc.4;
        bindings.otlp_http_protection = otlp_http.4;
        bindings.loki_push_protection = loki_push.4;
        bindings.api_http2_profile = api.5;
        bindings.otlp_grpc_http2_profile = otlp_grpc.5;
        Ok(bindings)
    }

    fn staged_material_identity(&self) -> Result<[u8; 32], NativeHostFailure> {
        let mut hasher = Sha256::new();
        for (role, transport) in [
            (ListenerRole::Operations, &self.operations_transport),
            (ListenerRole::Api, &self.api_transport),
            (ListenerRole::OtlpGrpc, &self.otlp_grpc_transport),
            (ListenerRole::OtlpHttp, &self.otlp_http_transport),
            (ListenerRole::LokiPush, &self.loki_push_transport),
        ] {
            hasher.update([role as u8]);
            hasher.update(
                transport
                    .material_identity()
                    .map_err(|_| NativeHostFailure::InvalidTlsProfile)?,
            );
        }
        Ok(hasher.finalize().into())
    }

    pub fn new(
        control: PathBuf,
        operations: SocketAddr,
        api: SocketAddr,
        otlp_grpc: SocketAddr,
        otlp_http: SocketAddr,
        loki_push: SocketAddr,
    ) -> Result<Self, NativeHostFailure> {
        if !api.ip().is_loopback()
            || !operations.ip().is_loopback()
            || !otlp_grpc.ip().is_loopback()
            || !otlp_http.ip().is_loopback()
            || !loki_push.ip().is_loopback()
        {
            return Err(NativeHostFailure::InvalidBinding);
        }
        Self::new_with_api_transport(
            control,
            operations,
            api,
            otlp_grpc,
            otlp_http,
            loki_push,
            ApiTransportProfile::PlaintextOptOut,
        )
    }

    pub fn new_with_api_transport(
        control: PathBuf,
        operations: SocketAddr,
        api: SocketAddr,
        otlp_grpc: SocketAddr,
        otlp_http: SocketAddr,
        loki_push: SocketAddr,
        api_transport: ApiTransportProfile,
    ) -> Result<Self, NativeHostFailure> {
        Self::new_with_listener_transports(
            control,
            operations,
            api,
            otlp_grpc,
            otlp_http,
            loki_push,
            TransportProfile::plaintext_opt_out(),
            api_transport,
            TransportProfile::plaintext_opt_out(),
            TransportProfile::plaintext_opt_out(),
            TransportProfile::plaintext_opt_out(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_listener_transports(
        control: PathBuf,
        operations: SocketAddr,
        api: SocketAddr,
        otlp_grpc: SocketAddr,
        otlp_http: SocketAddr,
        loki_push: SocketAddr,
        operations_transport: TransportProfile,
        api_transport: TransportProfile,
        otlp_grpc_transport: TransportProfile,
        otlp_http_transport: TransportProfile,
        loki_push_transport: TransportProfile,
    ) -> Result<Self, NativeHostFailure> {
        BoundEndpoint::control(control.clone()).map_err(|_| NativeHostFailure::InvalidBinding)?;
        for (role, address) in [
            (ListenerRole::Operations, operations),
            (ListenerRole::Api, api),
            (ListenerRole::OtlpGrpc, otlp_grpc),
            (ListenerRole::OtlpHttp, otlp_http),
            (ListenerRole::LokiPush, loki_push),
        ] {
            BoundEndpoint::tcp(role, address).map_err(|_| NativeHostFailure::InvalidBinding)?;
        }
        for transport in [
            &operations_transport,
            &api_transport,
            &otlp_grpc_transport,
            &otlp_http_transport,
            &loki_push_transport,
        ] {
            transport
                .material_identity()
                .map_err(|_| NativeHostFailure::InvalidTlsProfile)?;
        }
        Ok(Self {
            control,
            operations,
            operations_transport,
            api,
            api_transport,
            otlp_grpc,
            otlp_grpc_transport,
            otlp_http,
            otlp_http_transport,
            loki_push,
            loki_push_transport,
            operations_admission: default_admission_limits(),
            api_admission: default_admission_limits(),
            otlp_grpc_admission: default_admission_limits(),
            otlp_http_admission: default_admission_limits(),
            loki_push_admission: default_admission_limits(),
            operations_protection: default_connection_protection(),
            api_protection: default_connection_protection(),
            otlp_grpc_protection: default_connection_protection(),
            otlp_http_protection: default_connection_protection(),
            loki_push_protection: default_connection_protection(),
            api_http2_profile: compiled_http2_profile(NetworkListenerRole::Api)?,
            otlp_grpc_http2_profile: compiled_http2_profile(NetworkListenerRole::OtlpGrpc)?,
            operations_trusted_proxy: None,
            api_trusted_proxy: None,
            otlp_grpc_trusted_proxy: None,
            otlp_http_trusted_proxy: None,
            loki_push_trusted_proxy: None,
        })
    }

    pub fn with_api_transport(
        mut self,
        profile: ApiTransportProfile,
    ) -> Result<Self, NativeHostFailure> {
        self.api_transport = profile;
        Ok(self)
    }

    #[must_use]
    pub fn with_trusted_proxy(mut self, trusted_proxy: TrustedProxy) -> Self {
        self.operations_trusted_proxy = Some(trusted_proxy.clone());
        self.api_trusted_proxy = Some(trusted_proxy.clone());
        self.otlp_grpc_trusted_proxy = Some(trusted_proxy.clone());
        self.otlp_http_trusted_proxy = Some(trusted_proxy.clone());
        self.loki_push_trusted_proxy = Some(trusted_proxy);
        self
    }

    fn address(&self, role: ListenerRole) -> Option<SocketAddr> {
        match role {
            ListenerRole::Operations => Some(self.operations),
            ListenerRole::Api => Some(self.api),
            ListenerRole::OtlpGrpc => Some(self.otlp_grpc),
            ListenerRole::OtlpHttp => Some(self.otlp_http),
            ListenerRole::LokiPush => Some(self.loki_push),
            ListenerRole::Control => None,
        }
    }

    fn transport(&self, role: ListenerRole) -> Option<TransportProfile> {
        match role {
            ListenerRole::Operations => Some(self.operations_transport.clone()),
            ListenerRole::Api => Some(self.api_transport.clone()),
            ListenerRole::OtlpGrpc => Some(self.otlp_grpc_transport.clone()),
            ListenerRole::OtlpHttp => Some(self.otlp_http_transport.clone()),
            ListenerRole::LokiPush => Some(self.loki_push_transport.clone()),
            ListenerRole::Control => None,
        }
    }

    fn trusted_proxy(&self, role: ListenerRole) -> Option<TrustedProxy> {
        match role {
            ListenerRole::Operations => self.operations_trusted_proxy.clone(),
            ListenerRole::Api => self.api_trusted_proxy.clone(),
            ListenerRole::OtlpGrpc => self.otlp_grpc_trusted_proxy.clone(),
            ListenerRole::OtlpHttp => self.otlp_http_trusted_proxy.clone(),
            ListenerRole::LokiPush => self.loki_push_trusted_proxy.clone(),
            ListenerRole::Control => None,
        }
    }

    fn admission(&self, role: ListenerRole) -> Option<(NonZeroU16, NonZeroU16)> {
        match role {
            ListenerRole::Operations => Some(self.operations_admission),
            ListenerRole::Api => Some(self.api_admission),
            ListenerRole::OtlpGrpc => Some(self.otlp_grpc_admission),
            ListenerRole::OtlpHttp => Some(self.otlp_http_admission),
            ListenerRole::LokiPush => Some(self.loki_push_admission),
            ListenerRole::Control => None,
        }
    }

    fn protection(&self, role: ListenerRole) -> Option<ConnectionProtection> {
        match role {
            ListenerRole::Operations => Some(self.operations_protection),
            ListenerRole::Api => Some(self.api_protection),
            ListenerRole::OtlpGrpc => Some(self.otlp_grpc_protection),
            ListenerRole::OtlpHttp => Some(self.otlp_http_protection),
            ListenerRole::LokiPush => Some(self.loki_push_protection),
            ListenerRole::Control => None,
        }
    }

    fn http2_profile(&self, role: ListenerRole) -> Option<Http2Profile> {
        match role {
            ListenerRole::Api => self.api_http2_profile,
            ListenerRole::OtlpGrpc => self.otlp_grpc_http2_profile,
            _ => None,
        }
    }
}

fn compiled_http2_profile(
    role: NetworkListenerRole,
) -> Result<Option<Http2Profile>, NativeHostFailure> {
    let inputs = ConfigurationInputs::try_from_sources(
        None,
        [] as [(&str, &str); 0],
        [] as [(&str, &str); 0],
    )
    .map_err(|_| NativeHostFailure::InvalidBinding)?;
    let effective = resolve(inputs).map_err(|_| NativeHostFailure::InvalidBinding)?;
    effective
        .network_listener_profile(role)
        .and_then(|profile| profile.http2_profile())
        .map(Some)
        .ok_or(NativeHostFailure::InvalidBinding)
}

const DEFAULT_ACCEPTED_SOCKET_LIMIT: NonZeroU16 = nonzero_u16(128);
const DEFAULT_PEER_SOCKET_LIMIT: NonZeroU16 = nonzero_u16(16);
const DEFAULT_TLS_HANDSHAKE_LIMIT: NonZeroU16 = nonzero_u16(16);

const fn nonzero_u16(value: u16) -> NonZeroU16 {
    match NonZeroU16::new(value) {
        Some(value) => value,
        None => panic!("native listener default must be nonzero"),
    }
}

const fn default_admission_limits() -> (NonZeroU16, NonZeroU16) {
    (DEFAULT_ACCEPTED_SOCKET_LIMIT, DEFAULT_PEER_SOCKET_LIMIT)
}

fn default_connection_protection() -> ConnectionProtection {
    ConnectionProtection::new(
        DEFAULT_TLS_HANDSHAKE_LIMIT,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(30),
        Duration::from_secs(30),
    )
}

type EffectiveNativeProfile = (
    SocketAddr,
    TransportProfile,
    Option<TrustedProxy>,
    (NonZeroU16, NonZeroU16),
    ConnectionProtection,
    Option<Http2Profile>,
);

fn effective_profile(
    effective: &EffectiveConfiguration,
    role: NetworkListenerRole,
) -> Result<EffectiveNativeProfile, NativeHostFailure> {
    let profile = effective
        .network_listener_profile(role)
        .ok_or(NativeHostFailure::InvalidBinding)?;
    let transport = match profile.transport() {
        NetworkTransport::PlaintextOptOut => TransportProfile::plaintext_opt_out(),
        NetworkTransport::Tls | NetworkTransport::MutualTls => {
            let identity = TlsIdentity::new(
                profile.tls_certificate_file().as_path().to_path_buf(),
                profile.tls_private_key_file().as_path().to_path_buf(),
            );
            let trust = profile
                .tls_client_ca_file()
                .map(|reference| TlsTrust::new(reference.as_path().to_path_buf()));
            let tls = TlsProfile::new(identity, trust);
            tls.load()
                .map_err(|_| NativeHostFailure::InvalidTlsProfile)?;
            TransportProfile::Tls(tls)
        },
    };
    Ok((
        profile.bind_address(),
        transport,
        trusted_proxy_from_profile(&profile)?,
        (
            profile
                .connection_admission()
                .global_accepted_socket_limit(),
            profile
                .connection_admission()
                .per_address_accepted_socket_limit(),
        ),
        ConnectionProtection::new(
            profile.connection_protection().tls_handshake_limit(),
            profile.connection_protection().tls_handshake_deadline(),
            profile.connection_protection().header_deadline(),
            profile.connection_protection().body_deadline(),
            profile.connection_protection().request_deadline(),
            profile.connection_protection().idle_deadline(),
        ),
        profile.http2_profile(),
    ))
}

fn trusted_proxy_from_profile(
    profile: &NetworkListenerProfile<'_>,
) -> Result<Option<TrustedProxy>, NativeHostFailure> {
    match (
        profile.trusted_proxy_cidrs().is_empty(),
        profile.forwarded_hops(),
    ) {
        (true, None) => Ok(None),
        (false, Some(hops)) => {
            let mut cidrs = Vec::with_capacity(profile.trusted_proxy_cidrs().len());
            for configured in profile.trusted_proxy_cidrs() {
                let (address, prefix) = configured
                    .split_once('/')
                    .ok_or(NativeHostFailure::InvalidBinding)?;
                let address = address
                    .parse()
                    .map_err(|_| NativeHostFailure::InvalidBinding)?;
                let prefix = prefix
                    .parse()
                    .map_err(|_| NativeHostFailure::InvalidBinding)?;
                cidrs.push(
                    TrustedCidr::new(address, prefix)
                        .map_err(|_| NativeHostFailure::InvalidBinding)?,
                );
            }
            TrustedProxy::cidrs(cidrs, hops)
                .map(Some)
                .map_err(|_| NativeHostFailure::InvalidBinding)
        },
        _ => Err(NativeHostFailure::InvalidBinding),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHostFailure {
    InvalidBinding,
    InvalidTlsProfile,
}

impl Display for NativeHostFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native host configuration is invalid")
    }
}

impl Error for NativeHostFailure {}

pub struct NativeHost {
    bindings: NativeBindings,
    admissions: AdmissionRegistry,
    staged_admissions: Option<StagedAdmissions>,
}

impl Clone for NativeHost {
    fn clone(&self) -> Self {
        Self {
            bindings: self.bindings.clone(),
            admissions: Arc::clone(&self.admissions),
            staged_admissions: self.staged_admissions.as_ref().map(Arc::clone),
        }
    }
}

impl NativeHost {
    fn staged_profile(&self, configured: &Self, role: ListenerRole) -> Option<ListenerProfile> {
        if role == ListenerRole::Control {
            return configured.profile_for(role);
        }
        let configured_address = configured.bindings.address(role)?;
        if configured_address.port() != 0 || self.bindings.address(role) != Some(configured_address)
        {
            return configured.profile_for(role);
        }
        let active_address =
            self.admissions
                .lock()
                .ok()?
                .iter()
                .rev()
                .find_map(|(active_role, admission)| {
                    (*active_role == role).then(|| match &admission.listener {
                        NativeListener::Tcp(listener) => listener.local_addr().ok(),
                        #[cfg(unix)]
                        NativeListener::Unix(_) => None,
                    })?
                })?;
        ListenerProfile::network_with_admission_protection_and_http2(
            role,
            active_address,
            configured.bindings.transport(role)?.listener_transport(),
            configured.bindings.admission(role)?.0,
            configured.bindings.admission(role)?.1,
            configured.bindings.protection(role)?,
            configured.bindings.http2_profile(role),
        )
        .ok()
    }

    #[must_use]
    pub fn new(bindings: NativeBindings) -> Self {
        Self {
            bindings,
            admissions: Arc::new(Mutex::new(Vec::with_capacity(6))),
            staged_admissions: None,
        }
    }
}

enum NativeListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl NativeListener {
    fn duplicate(&self) -> Result<Self, ListenerFailure> {
        match self {
            Self::Tcp(listener) => listener
                .try_clone()
                .map(Self::Tcp)
                .map_err(|_| ListenerFailure::BindUnavailable),
            #[cfg(unix)]
            Self::Unix(listener) => listener
                .try_clone()
                .map(Self::Unix)
                .map_err(|_| ListenerFailure::BindUnavailable),
        }
    }
}

struct Admission {
    role: ListenerRole,
    listener: NativeListener,
    accepting: AtomicBool,
    accepted_connections: AtomicUsize,
    control_path: Option<Arc<ControlPathLease>>,
    transport: Option<TransportProfile>,
    trusted_proxy: Option<TrustedProxy>,
    connection_admission: Option<Arc<connection_admission::ConnectionAdmission>>,
    connection_protection: Option<ConnectionProtection>,
    http2_profile: Option<Http2Profile>,
}

type AdmissionRegistry = Arc<Mutex<Vec<(ListenerRole, Arc<Admission>)>>>;
type StagedAdmissions = Arc<Mutex<Vec<(ListenerRole, Arc<Admission>)>>>;

/// Keeps the control socket pathname alive for every descriptor that shares
/// the same Unix listener. A replacement duplicates the descriptor, so the
/// retiring generation must never unlink the pathname while its successor is
/// still serving it.
struct ControlPathLease {
    path: PathBuf,
}

impl Drop for ControlPathLease {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(_) => {},
        }
    }
}

impl Admission {
    fn stop(&self) {
        self.accepting.store(false, Ordering::Release);
    }

    fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }

    pub(super) fn accept_connection(self: &Arc<Self>, peer: IpAddr) -> Option<ConnectionLease> {
        let reservation = match &self.connection_admission {
            Some(admission) => Some(admission.reserve(peer)?),
            None => None,
        };
        self.accepted_connections.fetch_add(1, Ordering::AcqRel);
        Some(ConnectionLease {
            admission: Arc::clone(self),
            _reservation: reservation,
        })
    }

    pub(super) fn connection_protection(&self) -> ConnectionProtection {
        self.connection_protection
            .unwrap_or_else(default_connection_protection)
    }

    pub(super) fn http2_profile(&self) -> Option<Http2Profile> {
        self.http2_profile
    }

    pub(super) fn reserve_tls_handshake(
        &self,
    ) -> Option<connection_admission::HandshakeReservation> {
        self.connection_admission.as_ref()?.reserve_tls_handshake()
    }

    fn drain_within(&self, deadline: Instant) -> bool {
        self.stop();
        while self.accepted_connections.load(Ordering::Acquire) != 0 {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }

    pub(super) fn grpc_tls_config(
        &self,
    ) -> Result<Option<Arc<rustls::ServerConfig>>, NativeHostFailure> {
        self.transport
            .as_ref()
            .ok_or(NativeHostFailure::InvalidTlsProfile)?
            .grpc_server_config()
    }

    fn tcp_listener(&self) -> Result<TcpListener, ListenerFailure> {
        match &self.listener {
            NativeListener::Tcp(listener) => listener
                .try_clone()
                .map_err(|_| ListenerFailure::BindUnavailable),
            #[cfg(unix)]
            NativeListener::Unix(_) => Err(ListenerFailure::InvalidEndpoint),
        }
    }
}

pub(super) struct ConnectionLease {
    admission: Arc<Admission>,
    _reservation: Option<connection_admission::ConnectionReservation>,
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.admission
            .accepted_connections
            .fetch_sub(1, Ordering::AcqRel);
    }
}

struct NativeBoundListener {
    endpoint: BoundEndpoint,
    admission: Arc<Admission>,
    registry: AdmissionRegistry,
}

impl BoundListener for NativeBoundListener {
    fn endpoint(&self) -> &BoundEndpoint {
        &self.endpoint
    }

    fn close(&mut self) -> Result<(), ListenerFailure> {
        self.admission.stop();
        Ok(())
    }

    fn drain_within(&mut self, limit: Duration) -> Result<bool, ListenerFailure> {
        Ok(self.admission.drain_within(Instant::now() + limit))
    }
}

impl Drop for NativeBoundListener {
    fn drop(&mut self) {
        match self.close() {
            Ok(()) | Err(_) => {},
        }
        if let Ok(mut admissions) = self.registry.lock() {
            admissions.retain(|(_, current)| !Arc::ptr_eq(current, &self.admission));
        }
    }
}

impl ListenerFactory for NativeHost {
    fn bind(&self, request: ListenerRequest) -> Result<Box<dyn BoundListener>, ListenerFailure> {
        let role = request.role();
        let expected = self
            .profile_for(role)
            .ok_or(ListenerFailure::InvalidEndpoint)?;
        let requested = request
            .profile()
            .cloned()
            .unwrap_or_else(|| expected.clone());
        let requested_address = match (&requested, &expected) {
            (
                ListenerProfile::Control { path },
                ListenerProfile::Control {
                    path: expected_path,
                },
            ) if path == expected_path => None,
            (
                ListenerProfile::Network {
                    role: requested_role,
                    address,
                    transport,
                    global_accepted_socket_limit,
                    per_address_accepted_socket_limit,
                    connection_protection,
                    http2_profile,
                },
                ListenerProfile::Network {
                    role: expected_role,
                    transport: expected_transport,
                    global_accepted_socket_limit: expected_global_limit,
                    per_address_accepted_socket_limit: expected_per_address_limit,
                    connection_protection: expected_connection_protection,
                    http2_profile: expected_http2_profile,
                    ..
                },
            ) if requested_role == expected_role
                && transport == expected_transport
                && global_accepted_socket_limit == expected_global_limit
                && per_address_accepted_socket_limit == expected_per_address_limit
                && connection_protection == expected_connection_protection
                && http2_profile == expected_http2_profile =>
            {
                Some(*address)
            },
            _ => return Err(ListenerFailure::InvalidTransport),
        };
        let retained = self
            .admissions
            .lock()
            .map_err(|_| ListenerFailure::BindUnavailable)?
            .iter()
            .rev()
            .find(|(active_role, admission)| {
                if *active_role != role {
                    return false;
                }
                match requested_address {
                    None => {
                        role == ListenerRole::Control
                            && admission
                                .control_path
                                .as_ref()
                                .is_some_and(|path| path.path == self.bindings.control)
                    },
                    Some(address) => matches!(
                        &admission.listener,
                        NativeListener::Tcp(listener)
                            if listener.local_addr().is_ok_and(|local| local == address)
                    ),
                }
            })
            .map(|(_, admission)| Arc::clone(admission));
        let (endpoint, listener, control_path) = if let Some(active) = retained {
            let endpoint = if role == ListenerRole::Control {
                BoundEndpoint::control(self.bindings.control.clone())?
            } else {
                let local = match &active.listener {
                    NativeListener::Tcp(listener) => listener
                        .local_addr()
                        .map_err(|_| ListenerFailure::BindUnavailable)?,
                    #[cfg(unix)]
                    NativeListener::Unix(_) => return Err(ListenerFailure::InvalidEndpoint),
                };
                BoundEndpoint::tcp(role, local)?
            };
            (
                endpoint,
                active.listener.duplicate()?,
                active.control_path.as_ref().map(Arc::clone),
            )
        } else if role == ListenerRole::Control {
            #[cfg(unix)]
            {
                if let Some(parent) = self.bindings.control.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|_| ListenerFailure::BindUnavailable)?;
                }
                let listener = UnixListener::bind(&self.bindings.control)
                    .map_err(|_| ListenerFailure::BindUnavailable)?;
                std::fs::set_permissions(
                    &self.bindings.control,
                    std::fs::Permissions::from_mode(0o600),
                )
                .map_err(|_| ListenerFailure::BindUnavailable)?;
                listener
                    .set_nonblocking(true)
                    .map_err(|_| ListenerFailure::BindUnavailable)?;
                (
                    BoundEndpoint::control(self.bindings.control.clone())?,
                    NativeListener::Unix(listener),
                    Some(Arc::new(ControlPathLease {
                        path: self.bindings.control.clone(),
                    })),
                )
            }
            #[cfg(not(unix))]
            {
                return Err(ListenerFailure::BindUnavailable);
            }
        } else {
            let address = requested_address.ok_or(ListenerFailure::InvalidEndpoint)?;
            let listener =
                TcpListener::bind(address).map_err(|_| ListenerFailure::BindUnavailable)?;
            listener
                .set_nonblocking(true)
                .map_err(|_| ListenerFailure::BindUnavailable)?;
            let local = listener
                .local_addr()
                .map_err(|_| ListenerFailure::BindUnavailable)?;
            (
                BoundEndpoint::tcp(role, local)?,
                NativeListener::Tcp(listener),
                None,
            )
        };
        let connection_protection = self.bindings.protection(role);
        let connection_admission = match (self.bindings.admission(role), connection_protection) {
            (Some((global, per_address)), Some(protection)) => Some(Arc::new(
                connection_admission::ConnectionAdmission::new(global, per_address, protection),
            )),
            (None, None) => None,
            _ => return Err(ListenerFailure::InvalidEndpoint),
        };
        let admission = Arc::new(Admission {
            role,
            listener,
            accepting: AtomicBool::new(self.staged_admissions.is_none()),
            accepted_connections: AtomicUsize::new(0),
            control_path,
            transport: self.bindings.transport(role),
            trusted_proxy: self.bindings.trusted_proxy(role),
            connection_admission,
            connection_protection,
            http2_profile: self.bindings.http2_profile(role),
        });
        self.admissions
            .lock()
            .map_err(|_| ListenerFailure::BindUnavailable)?
            .push((role, Arc::clone(&admission)));
        if let Some(staged) = self.staged_admissions.as_ref() {
            staged
                .lock()
                .map_err(|_| ListenerFailure::BindUnavailable)?
                .push((role, Arc::clone(&admission)));
        }
        Ok(Box::new(NativeBoundListener {
            endpoint,
            admission,
            registry: Arc::clone(&self.admissions),
        }))
    }

    fn profile_for(&self, role: ListenerRole) -> Option<ListenerProfile> {
        if role == ListenerRole::Control {
            return ListenerProfile::control(self.bindings.control.clone()).ok();
        }
        let address = self.bindings.address(role)?;
        let transport = self.bindings.transport(role)?.listener_transport();
        let (global, per_address) = self.bindings.admission(role)?;
        ListenerProfile::network_with_admission_protection_and_http2(
            role,
            address,
            transport,
            global,
            per_address,
            self.bindings.protection(role)?,
            self.bindings.http2_profile(role),
        )
        .ok()
    }

    fn generation_factory(&self) -> Option<Arc<dyn ListenerGenerationFactory>> {
        Some(Arc::new(self.clone()))
    }
}

impl ListenerGenerationFactory for NativeHost {
    fn stage(
        &self,
        configuration: &EffectiveConfiguration,
        health: HealthState,
        services: Option<ServiceHandle>,
    ) -> Result<ListenerGeneration, ListenerFailure> {
        let bindings = NativeBindings::from_effective(configuration)
            .map_err(|_| ListenerFailure::BindUnavailable)?;
        let material_identity = bindings
            .staged_material_identity()
            .map_err(|_| ListenerFailure::BindUnavailable)?;
        let staged_admissions = Arc::new(Mutex::new(Vec::with_capacity(6)));
        let configured = Self {
            bindings,
            admissions: Arc::clone(&self.admissions),
            staged_admissions: Some(Arc::clone(&staged_admissions)),
        };
        let profiles = ListenerRole::all().map(|role| {
            self.staged_profile(&configured, role)
                .ok_or(ListenerFailure::InvalidEndpoint)
        });
        let [control, operations, api, otlp_grpc, otlp_http, loki_push] = profiles;
        let candidate = ValidatedListenerSet::new([
            control?,
            operations?,
            api?,
            otlp_grpc?,
            otlp_http?,
            loki_push?,
        ])?;
        let generation = ListenerGeneration::activate(candidate, &configured, health.clone())
            .map(|generation| generation.with_material_identity(material_identity))?;
        let admissions = staged_admissions
            .lock()
            .map_err(|_| ListenerFailure::BindUnavailable)?
            .clone();
        let gate = Arc::new(ActivationGate::new());
        let registered = register_staged_tasks(&configured, &admissions, Arc::clone(&gate))?;
        let cancellation = TaskCancellation::new();
        let mut tasks = Vec::with_capacity(registered.len());
        for (role, task) in registered {
            match task.spawn(cancellation.clone(), health.clone(), services.clone()) {
                Ok(task) => tasks.push((role, task)),
                Err(_) => {
                    cancellation.cancel();
                    abort_tasks(&mut tasks)?;
                    return Err(ListenerFailure::BindUnavailable);
                },
            }
        }
        if gate.wait_parked(ListenerRole::all().len()).is_err() {
            cancellation.cancel();
            abort_tasks(&mut tasks)?;
            return Err(ListenerFailure::BindUnavailable);
        }
        Ok(generation.with_staged_tasks(
            tasks,
            cancellation,
            Box::new(NativeGenerationActivation {
                gate,
                task_count: ListenerRole::all().len(),
            }),
        ))
    }
}

fn abort_tasks(tasks: &mut [(TaskRole, Box<dyn RunningTask>)]) -> Result<(), ListenerFailure> {
    for (_, task) in tasks {
        task.abort().map_err(|_| ListenerFailure::BindUnavailable)?;
    }
    Ok(())
}

type NativeRegisteredTasks = Vec<(TaskRole, Box<dyn RegisteredTask>)>;

fn register_staged_tasks(
    host: &NativeHost,
    admissions: &[(ListenerRole, Arc<Admission>)],
    gate: Arc<ActivationGate>,
) -> Result<NativeRegisteredTasks, ListenerFailure> {
    let mut registered = Vec::with_capacity(ListenerRole::all().len());
    for role in ListenerRole::all() {
        let admission = admissions
            .iter()
            .find(|(admission_role, _)| *admission_role == role)
            .map(|(_, admission)| Arc::clone(admission))
            .ok_or(ListenerFailure::IncompleteGeneration)?;
        registered.push((
            task_role(role),
            host.register_exact(role, admission, Arc::clone(&gate))?,
        ));
    }
    Ok(registered)
}

impl TaskRegistrar for NativeHost {
    fn register(&self, role: TaskRole) -> Result<Box<dyn RegisteredTask>, TaskFailure> {
        Ok(Box::new(NativeRegisteredTask {
            role,
            admissions: Arc::clone(&self.admissions),
            admission: None,
            gate: None,
        }))
    }
}

impl NativeHost {
    fn register_exact(
        &self,
        role: ListenerRole,
        admission: Arc<Admission>,
        gate: Arc<ActivationGate>,
    ) -> Result<Box<dyn RegisteredTask>, ListenerFailure> {
        Ok(Box::new(NativeRegisteredTask {
            role: task_role(role),
            admissions: Arc::clone(&self.admissions),
            admission: Some(admission),
            gate: Some(gate),
        }))
    }
}

struct NativeRegisteredTask {
    role: TaskRole,
    admissions: AdmissionRegistry,
    admission: Option<Arc<Admission>>,
    gate: Option<Arc<ActivationGate>>,
}

impl RegisteredTask for NativeRegisteredTask {
    fn spawn(
        self: Box<Self>,
        cancellation: TaskCancellation,
        health: HealthState,
        services: Option<ServiceHandle>,
    ) -> Result<Box<dyn RunningTask>, TaskFailure> {
        let listener_role = listener_role(self.role);
        let task_cancellation = cancellation.clone();
        let force = TaskCancellation::new();
        let force_cancellation = force.clone();
        let admissions = Arc::clone(&self.admissions);
        let admission = self.admission.as_ref().map(Arc::clone);
        let gate = self.gate.as_ref().map(Arc::clone);
        let handle = std::thread::Builder::new()
            .name(format!("positron-{listener_role:?}"))
            .spawn(move || match (admission, gate) {
                (Some(admission), Some(gate)) => serve_exact_listener_role(
                    listener_role,
                    admission,
                    gate,
                    task_cancellation,
                    force_cancellation,
                    health,
                    services,
                ),
                (None, None) => serve_listener_role(
                    listener_role,
                    admissions,
                    task_cancellation,
                    force_cancellation,
                    health,
                    services,
                ),
                _ => Err(TaskFailure::SpawnUnavailable),
            })
            .map_err(|_| TaskFailure::SpawnUnavailable)?;
        Ok(Box::new(NativeRunningTask {
            cancellation,
            force,
            handle: Some(handle),
        }))
    }
}

const fn task_role(role: ListenerRole) -> TaskRole {
    match role {
        ListenerRole::Control => TaskRole::Control,
        ListenerRole::Operations => TaskRole::Operations,
        ListenerRole::Api => TaskRole::Api,
        ListenerRole::OtlpGrpc => TaskRole::OtlpGrpc,
        ListenerRole::OtlpHttp => TaskRole::OtlpHttp,
        ListenerRole::LokiPush => TaskRole::LokiPush,
    }
}

const fn listener_role(role: TaskRole) -> ListenerRole {
    match role {
        TaskRole::Control => ListenerRole::Control,
        TaskRole::Operations => ListenerRole::Operations,
        TaskRole::Api => ListenerRole::Api,
        TaskRole::OtlpGrpc => ListenerRole::OtlpGrpc,
        TaskRole::OtlpHttp => ListenerRole::OtlpHttp,
        TaskRole::LokiPush => ListenerRole::LokiPush,
    }
}

fn serve_exact_listener_role(
    role: ListenerRole,
    admission: Arc<Admission>,
    gate: Arc<ActivationGate>,
    cancellation: TaskCancellation,
    force: TaskCancellation,
    health: HealthState,
    services: Option<ServiceHandle>,
) -> Result<(), TaskFailure> {
    let prepared_grpc = if role == ListenerRole::OtlpGrpc {
        Some(
            otlp_grpc::prepare(Arc::clone(&admission), services.clone())
                .map_err(|_| TaskFailure::SpawnUnavailable)?,
        )
    } else {
        None
    };
    gate.park_then_wait(&cancellation)?;
    if cancellation.is_cancelled() {
        if let Some(prepared) = prepared_grpc {
            prepared
                .discard()
                .map_err(|_| TaskFailure::JoinUnavailable)?;
        }
        return Ok(());
    }
    gate.mark_ready()?;
    gate.wait_for_admission(&cancellation);
    if cancellation.is_cancelled() {
        if let Some(prepared) = prepared_grpc {
            prepared
                .discard()
                .map_err(|_| TaskFailure::JoinUnavailable)?;
        }
        return Ok(());
    }
    admission.accepting.store(true, Ordering::Release);
    if let Some(prepared) = prepared_grpc {
        prepared
            .serve(cancellation, force)
            .map_err(|_| TaskFailure::JoinUnavailable)
    } else {
        serve_http(admission, cancellation, force, health, services)
    }
}

fn serve_listener_role(
    role: ListenerRole,
    admissions: AdmissionRegistry,
    cancellation: TaskCancellation,
    force: TaskCancellation,
    health: HealthState,
    services: Option<ServiceHandle>,
) -> Result<(), TaskFailure> {
    if cancellation.is_cancelled() {
        return Ok(());
    }
    let admission = current_admission(&admissions, role)?;
    if role == ListenerRole::OtlpGrpc {
        otlp_grpc::serve(
            Arc::clone(&admission),
            cancellation.clone(),
            force.clone(),
            services.clone(),
        )
        .map_err(|_| TaskFailure::JoinUnavailable)?;
    } else {
        serve_http(
            Arc::clone(&admission),
            cancellation.clone(),
            force,
            health.clone(),
            services.clone(),
        )?;
    }
    if cancellation.is_cancelled() || !admission.is_accepting() {
        // A worker belongs to exactly one admitted generation. Replacement
        // workers are registered and parked separately, so retiring work must
        // never adopt an entry from the shared descriptor registry.
        Ok(())
    } else {
        Err(TaskFailure::JoinUnavailable)
    }
}

fn current_admission(
    admissions: &AdmissionRegistry,
    role: ListenerRole,
) -> Result<Arc<Admission>, TaskFailure> {
    latest_admission(admissions, role)?.ok_or(TaskFailure::SpawnUnavailable)
}

fn latest_admission(
    admissions: &AdmissionRegistry,
    role: ListenerRole,
) -> Result<Option<Arc<Admission>>, TaskFailure> {
    let admission = admissions
        .lock()
        .map_err(|_| TaskFailure::SpawnUnavailable)?
        .iter()
        .rev()
        .find(|(active_role, _)| *active_role == role)
        .map(|(_, admission)| Arc::clone(admission));
    Ok(admission)
}

struct NativeRunningTask {
    cancellation: TaskCancellation,
    force: TaskCancellation,
    handle: Option<JoinHandle<Result<(), TaskFailure>>>,
}

impl RunningTask for NativeRunningTask {
    fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
        if self.handle.as_ref().is_none_or(JoinHandle::is_finished) {
            join_thread(&mut self.handle)?;
            Ok(Some(TaskJoinOutcome::Joined))
        } else {
            Ok(None)
        }
    }

    fn join_within(&mut self, remaining: Duration) -> Result<TaskJoinOutcome, TaskFailure> {
        if join_thread_within(&mut self.handle, remaining)? {
            Ok(TaskJoinOutcome::Joined)
        } else {
            Ok(TaskJoinOutcome::DeadlineExpired)
        }
    }

    fn abort(&mut self) -> Result<(), TaskFailure> {
        self.cancellation.cancel();
        self.force.cancel();
        if join_thread_within(&mut self.handle, Duration::from_millis(250))? {
            Ok(())
        } else {
            Err(TaskFailure::AbortUnavailable)
        }
    }
}

fn join_thread_within(
    handle: &mut Option<JoinHandle<Result<(), TaskFailure>>>,
    limit: Duration,
) -> Result<bool, TaskFailure> {
    let deadline = Instant::now() + limit;
    while handle.as_ref().is_some_and(|handle| !handle.is_finished()) {
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    join_thread(handle)?;
    Ok(true)
}

fn join_thread(
    handle: &mut Option<JoinHandle<Result<(), TaskFailure>>>,
) -> Result<(), TaskFailure> {
    if let Some(handle) = handle.take() {
        return handle.join().map_err(|_| TaskFailure::JoinUnavailable)?;
    }
    Ok(())
}

#[cfg(test)]
mod listener_generation_tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use super::{
        ActivationGate, Admission, NativeBindings, NativeHost, NativeListener, TransportProfile,
        serve_exact_listener_role,
    };
    use crate::{
        ListenerFactory, ListenerFailure, ListenerGeneration, ListenerProfile, ListenerRole,
        ValidatedListenerSet, health::ProcessState,
    };

    #[test]
    fn same_endpoint_candidate_reuses_native_descriptors_before_old_admission_stops()
    -> Result<(), Box<dyn std::error::Error>> {
        let control = std::env::temp_dir().join(format!(
            "positron-native-generation-{}.sock",
            std::process::id()
        ));
        let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let host = NativeHost::new(NativeBindings::new(
            PathBuf::from(&control),
            loopback,
            loopback,
            loopback,
            loopback,
            loopback,
        )?);
        let [
            control_profile,
            operations,
            api,
            otlp_grpc,
            otlp_http,
            loki_push,
        ] = ListenerRole::all().map(|role| {
            host.profile_for(role).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "native profile unavailable")
            })
        });
        let candidate = ValidatedListenerSet::new([
            control_profile?,
            operations?,
            api?,
            otlp_grpc?,
            otlp_http?,
            loki_push?,
        ])?;
        let state = ProcessState::starting();
        let mut active = ListenerGeneration::activate(candidate.clone(), &host, state.health())?;
        let endpoints = active.endpoints();
        let replacement = active.replace(
            candidate_with_bound_addresses(&candidate, &endpoints)?,
            &host,
            state.health(),
        )?;
        assert_eq!(replacement.endpoints(), endpoints);
        active.drain()?;
        assert!(
            control.exists(),
            "dropping the retired control generation must retain the successor pathname"
        );
        replacement.drain()?;
        Ok(())
    }

    #[test]
    fn changed_endpoint_candidate_binds_a_fresh_socket_before_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let control = std::env::temp_dir().join(format!(
            "positron-native-generation-changed-{}.sock",
            std::process::id()
        ));
        let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let host = NativeHost::new(NativeBindings::new(
            PathBuf::from(&control),
            loopback,
            loopback,
            loopback,
            loopback,
            loopback,
        )?);
        let candidate = native_candidate(&host)?;
        let state = ProcessState::starting();
        let mut active = ListenerGeneration::activate(candidate.clone(), &host, state.health())?;
        let old_endpoints = active.endpoints();
        let changed = candidate_with_address(
            &candidate_with_bound_addresses(&candidate, &old_endpoints)?,
            ListenerRole::Operations,
            loopback,
        )?;

        let replacement = active.replace(changed, &host, state.health())?;
        let replacement_endpoints = replacement.endpoints();
        assert_ne!(
            endpoint_address(&old_endpoints, ListenerRole::Operations)?,
            endpoint_address(&replacement_endpoints, ListenerRole::Operations)?,
            "a changed endpoint must bind a fresh descriptor rather than clone the old socket"
        );
        active.drain()?;
        replacement.drain()?;
        Ok(())
    }

    #[test]
    fn failed_changed_endpoint_candidate_preserves_active_native_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let control = std::env::temp_dir().join(format!(
            "positron-native-generation-rollback-{}.sock",
            std::process::id()
        ));
        let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let host = NativeHost::new(NativeBindings::new(
            PathBuf::from(&control),
            loopback,
            loopback,
            loopback,
            loopback,
            loopback,
        )?);
        let candidate = native_candidate(&host)?;
        let state = ProcessState::starting();
        let mut active = ListenerGeneration::activate(candidate.clone(), &host, state.health())?;
        let endpoints = active.endpoints();
        let occupied = endpoint_address(&endpoints, ListenerRole::Api)?;
        let blocked = candidate_with_address(
            &candidate_with_bound_addresses(&candidate, &endpoints)?,
            ListenerRole::Operations,
            occupied,
        )?;

        let result = active.replace(blocked, &host, state.health());
        assert!(
            matches!(result, Err(ListenerFailure::BindUnavailable)),
            "occupied candidate must fail before old admission stops: {result:?}"
        );
        assert_eq!(active.endpoints(), endpoints);
        active.drain()?;
        Ok(())
    }

    #[test]
    fn grpc_preparation_failure_never_reaches_the_publication_readiness_gate()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let admission = Arc::new(Admission {
            role: ListenerRole::OtlpGrpc,
            listener: NativeListener::Tcp(listener),
            accepting: AtomicBool::new(false),
            accepted_connections: std::sync::atomic::AtomicUsize::new(0),
            control_path: None,
            transport: Some(TransportProfile::plaintext_opt_out()),
            trusted_proxy: None,
            connection_admission: None,
            connection_protection: None,
            http2_profile: None,
        });
        let gate = Arc::new(ActivationGate::new());
        let cancellation = crate::TaskCancellation::new();
        let result = serve_exact_listener_role(
            ListenerRole::OtlpGrpc,
            admission,
            Arc::clone(&gate),
            cancellation.clone(),
            crate::TaskCancellation::new(),
            ProcessState::starting().health(),
            None,
        );
        assert!(matches!(result, Err(crate::TaskFailure::SpawnUnavailable)));
        assert!(
            gate.wait_parked(1).is_err(),
            "an OTLP gRPC preparation failure must not make a candidate ready for publication"
        );
        Ok(())
    }

    #[test]
    fn accepted_socket_is_not_served_after_its_generation_stops_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let admission = Admission {
            role: ListenerRole::Api,
            listener: NativeListener::Tcp(listener),
            accepting: AtomicBool::new(true),
            accepted_connections: std::sync::atomic::AtomicUsize::new(0),
            control_path: None,
            transport: Some(TransportProfile::plaintext_opt_out()),
            trusted_proxy: None,
            connection_admission: None,
            connection_protection: None,
            http2_profile: None,
        };
        let cancellation = crate::TaskCancellation::new();
        admission.stop();
        assert!(
            !super::can_serve_accepted_connection(&admission, &cancellation),
            "the post-accept admission check must discard a socket accepted by a retired generation"
        );
        Ok(())
    }

    fn native_candidate(
        host: &NativeHost,
    ) -> Result<ValidatedListenerSet, Box<dyn std::error::Error>> {
        let [control, operations, api, otlp_grpc, otlp_http, loki_push] =
            ListenerRole::all().map(|role| {
                host.profile_for(role).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "native profile unavailable")
                })
            });
        Ok(ValidatedListenerSet::new([
            control?,
            operations?,
            api?,
            otlp_grpc?,
            otlp_http?,
            loki_push?,
        ])?)
    }

    fn candidate_with_address(
        candidate: &ValidatedListenerSet,
        changed_role: ListenerRole,
        address: SocketAddr,
    ) -> Result<ValidatedListenerSet, Box<dyn std::error::Error>> {
        let profiles = candidate.profiles().clone().map(|profile| match profile {
            ListenerProfile::Network {
                role,
                transport,
                global_accepted_socket_limit,
                per_address_accepted_socket_limit,
                connection_protection,
                http2_profile,
                ..
            } if role == changed_role => {
                ListenerProfile::network_with_admission_protection_and_http2(
                    role,
                    address,
                    transport,
                    global_accepted_socket_limit,
                    per_address_accepted_socket_limit,
                    connection_protection,
                    http2_profile,
                )
            },
            profile => Ok(profile),
        });
        let [control, operations, api, otlp_grpc, otlp_http, loki_push] = profiles;
        Ok(ValidatedListenerSet::new([
            control?,
            operations?,
            api?,
            otlp_grpc?,
            otlp_http?,
            loki_push?,
        ])?)
    }

    fn endpoint_address(
        endpoints: &[crate::BoundEndpoint],
        role: ListenerRole,
    ) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        endpoints
            .iter()
            .find(|endpoint| endpoint.role() == role)
            .and_then(crate::BoundEndpoint::socket_address)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "bound endpoint missing").into()
            })
    }

    fn candidate_with_bound_addresses(
        candidate: &ValidatedListenerSet,
        endpoints: &[crate::BoundEndpoint],
    ) -> Result<ValidatedListenerSet, Box<dyn std::error::Error>> {
        let [control, operations, api, otlp_grpc, otlp_http, loki_push] =
            candidate.profiles().clone();
        let bound = |role| {
            endpoints
                .iter()
                .find(|endpoint| endpoint.role() == role)
                .and_then(crate::BoundEndpoint::socket_address)
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "bound endpoint missing")
                })
        };
        let profile = |role, original: ListenerProfile| -> Result<_, Box<dyn std::error::Error>> {
            match original {
                ListenerProfile::Network {
                    transport,
                    global_accepted_socket_limit,
                    per_address_accepted_socket_limit,
                    connection_protection,
                    http2_profile,
                    ..
                } => Ok(
                    ListenerProfile::network_with_admission_protection_and_http2(
                        role,
                        bound(role)?,
                        transport,
                        global_accepted_socket_limit,
                        per_address_accepted_socket_limit,
                        connection_protection,
                        http2_profile,
                    )?,
                ),
                ListenerProfile::Control { .. } => Ok(control.clone()),
            }
        };
        Ok(ValidatedListenerSet::new([
            control.clone(),
            profile(ListenerRole::Operations, operations)?,
            profile(ListenerRole::Api, api)?,
            profile(ListenerRole::OtlpGrpc, otlp_grpc)?,
            profile(ListenerRole::OtlpHttp, otlp_http)?,
            profile(ListenerRole::LokiPush, loki_push)?,
        ])?)
    }
}

fn serve_http(
    admission: Arc<Admission>,
    cancellation: TaskCancellation,
    force: TaskCancellation,
    health: HealthState,
    services: Option<ServiceHandle>,
) -> Result<(), TaskFailure> {
    let mut handlers = Vec::new();
    while admission.accepting.load(Ordering::Acquire) && !cancellation.is_cancelled() {
        reap_completed_http_handlers(&mut handlers)?;
        let accepted = match &admission.listener {
            NativeListener::Tcp(listener) => listener.accept(),
            #[cfg(unix)]
            NativeListener::Unix(listener) => match listener.accept() {
                Ok((mut stream, _)) => {
                    match std::io::Write::write_all(&mut stream, b"positron-control-v1\n") {
                        Ok(()) => continue,
                        Err(_) => break,
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                },
                Err(_) => break,
            },
        };
        match accepted {
            Ok((mut stream, peer)) => {
                if !can_serve_accepted_connection(&admission, &cancellation) {
                    continue;
                }
                let Some(lease) = admission.accept_connection(peer.ip()) else {
                    continue;
                };
                let connection_protection = admission.connection_protection();
                let http2_profile = admission.http2_profile;
                let stream_configured = if admission.role == ListenerRole::Api {
                    stream.set_nonblocking(true).is_ok()
                } else {
                    stream.set_nonblocking(false).is_ok()
                };
                if !stream_configured {
                    continue;
                }
                let role = admission.role;
                let transport = admission.transport.clone();
                let trusted_proxy = admission.trusted_proxy.clone();
                let connection_health = health.clone();
                let connection_services = services.clone();
                let connection_admission = Arc::clone(&admission);
                let connection_cancellation = cancellation.clone();
                let Ok(interrupt) = stream.try_clone() else {
                    continue;
                };
                // Register the handler before spawning it. Admission bounds the
                // registry and its leases identify the exact accepting generation.
                handlers.push(HttpConnectionHandler {
                    interrupt,
                    handle: None,
                });
                let handler = std::thread::Builder::new()
                    .name(format!("positron-{role:?}-connection"))
                    .spawn(move || {
                        let _lease = lease;
                        if role == ListenerRole::Api {
                            let _ = api_http::serve_connection(
                                stream,
                                api_http::ConnectionContext {
                                    transport,
                                    admission: connection_admission,
                                    cancellation: connection_cancellation,
                                    peer,
                                    trusted_proxy,
                                    health: connection_health,
                                    services: connection_services,
                                    protection: connection_protection,
                                    http2_profile,
                                },
                            );
                        } else if let Some(profile) = transport {
                            if profile.is_tls() {
                                if let Ok(connection) = profile.server_connection() {
                                    let mut tls = rustls::StreamOwned::new(connection, stream);
                                    let handshaken = {
                                        let Some(_handshake) =
                                            connection_admission.reserve_tls_handshake()
                                        else {
                                            return;
                                        };
                                        complete_tls_handshake(
                                            &mut tls,
                                            connection_protection.tls_handshake_deadline(),
                                        )
                                        .is_ok()
                                    };
                                    if handshaken {
                                        let _ = native_http::serve_tls_connection(
                                            &mut tls,
                                            role,
                                            peer,
                                            trusted_proxy,
                                            &connection_health,
                                            connection_services.as_ref(),
                                            connection_protection,
                                        );
                                    }
                                }
                            } else {
                                let _ = native_http::serve_connection(
                                    &mut stream,
                                    role,
                                    peer,
                                    trusted_proxy,
                                    &connection_health,
                                    connection_services.as_ref(),
                                    connection_protection,
                                );
                            }
                        } else {
                            let _ = native_http::serve_connection(
                                &mut stream,
                                role,
                                peer,
                                trusted_proxy,
                                &connection_health,
                                connection_services.as_ref(),
                                connection_protection,
                            );
                        }
                    });
                match handler {
                    Ok(handler) => {
                        if let Some(registered) = handlers.last_mut() {
                            registered.handle = Some(handler);
                        } else {
                            return Err(TaskFailure::SpawnUnavailable);
                        }
                    },
                    Err(_) => {
                        let _ = handlers.pop();
                    },
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            },
            Err(_) => break,
        }
    }
    join_http_handlers(&mut handlers, &force)
}

fn complete_tls_handshake(
    stream: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    deadline: Duration,
) -> Result<(), std::io::Error> {
    let expires = Instant::now() + deadline;
    while stream.conn.is_handshaking() {
        let remaining = expires.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TLS handshake deadline elapsed",
            ));
        }
        stream.sock.set_read_timeout(Some(remaining))?;
        stream.sock.set_write_timeout(Some(remaining))?;
        stream.conn.complete_io(&mut stream.sock)?;
    }
    Ok(())
}

struct HttpConnectionHandler {
    interrupt: TcpStream,
    handle: Option<JoinHandle<()>>,
}

fn reap_completed_http_handlers(
    handlers: &mut Vec<HttpConnectionHandler>,
) -> Result<(), TaskFailure> {
    let mut index = 0;
    while index < handlers.len() {
        if handlers[index]
            .handle
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            let handler = handlers.swap_remove(index);
            join_http_handler(handler)?;
        } else {
            index = index.saturating_add(1);
        }
    }
    Ok(())
}

fn join_http_handlers(
    handlers: &mut Vec<HttpConnectionHandler>,
    force: &TaskCancellation,
) -> Result<(), TaskFailure> {
    while handlers.iter().any(|handler| {
        handler
            .handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }) {
        if force.is_cancelled() {
            for handler in &*handlers {
                let _ = handler.interrupt.shutdown(std::net::Shutdown::Both);
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    while let Some(handler) = handlers.pop() {
        join_http_handler(handler)?;
    }
    Ok(())
}

fn join_http_handler(mut handler: HttpConnectionHandler) -> Result<(), TaskFailure> {
    let Some(handle) = handler.handle.take() else {
        return Err(TaskFailure::SpawnUnavailable);
    };
    handle.join().map_err(|_| TaskFailure::JoinUnavailable)
}

fn can_serve_accepted_connection(admission: &Admission, cancellation: &TaskCancellation) -> bool {
    admission.is_accepting() && !cancellation.is_cancelled()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;

    use super::{NativeBindings, NativeHostFailure};

    #[test]
    fn legacy_bindings_refuse_public_data_endpoints_without_a_complete_transport_profile() {
        let result = NativeBindings::new(
            PathBuf::from("/tmp/positron-native-host.sock"),
            loopback(13_133),
            loopback(8_080),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 4_317)),
            loopback(4_318),
            loopback(3_100),
        );
        assert!(matches!(result, Err(NativeHostFailure::InvalidBinding)));
    }

    const fn loopback(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn h2_fuzz_hook_replays_a_complete_fragmented_header_block() {
        let mut seed = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        seed.extend_from_slice(&[0, 0, 1, 1, 0, 0, 0, 0, 1, b'a']);
        seed.extend_from_slice(&[0, 0, 1, 9, 4, 0, 0, 0, 1, b'b']);
        assert_eq!(super::fuzz_h2_observer(&seed), seed.len());
    }
}
