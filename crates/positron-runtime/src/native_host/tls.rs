use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use sha2::{Digest, Sha256};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use zeroize::Zeroizing;

use super::NativeHostFailure;

/// One certificate-chain and private-key pair used to identify a TLS listener.
#[derive(Clone, Eq, PartialEq)]
pub struct TlsIdentity {
    certificate_file: PathBuf,
    private_key_file: PathBuf,
}

impl TlsIdentity {
    #[must_use]
    pub fn new(certificate_file: PathBuf, private_key_file: PathBuf) -> Self {
        Self {
            certificate_file,
            private_key_file,
        }
    }
}

impl Debug for TlsIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TlsIdentity(<redacted>)")
    }
}

/// The certificate authorities permitted to authenticate TLS peers.
#[derive(Clone, Eq, PartialEq)]
pub struct TlsTrust {
    certificate_file: PathBuf,
}

impl TlsTrust {
    #[must_use]
    pub fn new(certificate_file: PathBuf) -> Self {
        Self { certificate_file }
    }
}

impl Debug for TlsTrust {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TlsTrust(<redacted>)")
    }
}

/// The role-neutral TLS material for one network listener.
#[derive(Clone, Debug)]
pub struct TlsProfile {
    identity: TlsIdentity,
    client_trust: Option<TlsTrust>,
    loaded: Arc<Mutex<Option<Arc<LoadedTls>>>>,
}

struct LoadedTls {
    server: Arc<ServerConfig>,
    certificate_pem: Vec<u8>,
    private_key_pem: Zeroizing<Vec<u8>>,
    trust_pem: Option<Vec<u8>>,
}

impl Debug for LoadedTls {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LoadedTls(<redacted>)")
    }
}

impl TlsProfile {
    #[must_use]
    pub fn new(identity: TlsIdentity, client_trust: Option<TlsTrust>) -> Self {
        Self {
            identity,
            client_trust,
            loaded: Arc::new(Mutex::new(None)),
        }
    }

    /// Loads and cryptographically validates the complete server identity.
    ///
    /// Supplying client trust enables mandatory mTLS peer validation. The peer
    /// certificate remains a transport fact and never becomes a Positron
    /// Principal, Scope, or Tenant identity.
    pub fn load(&self) -> Result<Arc<ServerConfig>, TlsFailure> {
        let mut loaded = self
            .loaded
            .lock()
            .map_err(|_| TlsFailure::LoadUnavailable)?;
        if let Some(configuration) = loaded.as_ref() {
            return Ok(Arc::clone(&configuration.server));
        }
        let configuration = Arc::new(load_tls(&self.identity, self.client_trust.as_ref())?);
        *loaded = Some(Arc::clone(&configuration));
        Ok(Arc::clone(&configuration.server))
    }

    pub(super) const fn requires_client_authentication(&self) -> bool {
        self.client_trust.is_some()
    }

    pub(super) fn grpc_server_config(&self) -> Result<ServerTlsConfig, TlsFailure> {
        let mut loaded = self
            .loaded
            .lock()
            .map_err(|_| TlsFailure::LoadUnavailable)?;
        if loaded.is_none() {
            *loaded = Some(Arc::new(load_tls(
                &self.identity,
                self.client_trust.as_ref(),
            )?));
        }
        let material = loaded.as_ref().ok_or(TlsFailure::LoadUnavailable)?;
        let configuration = ServerTlsConfig::new().identity(Identity::from_pem(
            material.certificate_pem.clone(),
            &material.private_key_pem,
        ));
        match material.trust_pem.as_ref() {
            Some(authority) => {
                Ok(configuration.client_ca_root(Certificate::from_pem(authority.clone())))
            },
            None => Ok(configuration),
        }
    }

    pub(super) fn material_identity(&self) -> Result<[u8; 32], TlsFailure> {
        let mut loaded = self
            .loaded
            .lock()
            .map_err(|_| TlsFailure::LoadUnavailable)?;
        if loaded.is_none() {
            *loaded = Some(Arc::new(load_tls(
                &self.identity,
                self.client_trust.as_ref(),
            )?));
        }
        let material = loaded.as_ref().ok_or(TlsFailure::LoadUnavailable)?;
        let mut hasher = Sha256::new();
        hasher.update(&material.certificate_pem);
        match material.trust_pem.as_ref() {
            Some(trust) => hasher.update(trust),
            None => hasher.update([0]),
        }
        Ok(hasher.finalize().into())
    }
}

/// A classified TLS-profile construction failure that never exposes material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsFailure {
    IncompleteIdentity,
    CertificateUnreadable,
    CertificateInvalid,
    PrivateKeyUnreadable,
    PrivateKeyInvalid,
    TrustUnreadable,
    TrustInvalid,
    IdentityInvalid,
    ClientAuthenticationInvalid,
    LoadUnavailable,
}

impl Display for TlsFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::IncompleteIdentity => "TLS identity is incomplete",
            Self::CertificateUnreadable => "TLS certificate cannot be read",
            Self::CertificateInvalid => "TLS certificate is invalid",
            Self::PrivateKeyUnreadable => "TLS private key cannot be read",
            Self::PrivateKeyInvalid => "TLS private key is invalid",
            Self::TrustUnreadable => "TLS trust store cannot be read",
            Self::TrustInvalid => "TLS trust store is invalid",
            Self::IdentityInvalid => "TLS identity is invalid",
            Self::ClientAuthenticationInvalid => "TLS client authentication is invalid",
            Self::LoadUnavailable => "TLS profile load state is unavailable",
        };
        formatter.write_str(message)
    }
}

impl Error for TlsFailure {}

/// The native API transport policy, including the explicit plaintext choice.
#[derive(Clone, Debug)]
pub enum TransportProfile {
    /// TLS authenticated by the configured identity and optional peer trust.
    Tls(TlsProfile),
    /// A deliberate operator opt-out, never selected as a TLS fallback.
    PlaintextOptOut,
}

/// Compatibility name retained while listener callers migrate to the neutral
/// transport profile.
pub type ApiTransportProfile = TransportProfile;

impl TransportProfile {
    /// Loads a TLS-only API profile through the role-neutral TLS constructor.
    pub fn tls(
        certificate_file: PathBuf,
        private_key_file: PathBuf,
    ) -> Result<Self, NativeHostFailure> {
        let profile = TlsProfile::new(TlsIdentity::new(certificate_file, private_key_file), None);
        profile
            .load()
            .map_err(|_| NativeHostFailure::InvalidTlsProfile)?;
        Ok(Self::Tls(profile))
    }

    #[must_use]
    pub const fn plaintext_opt_out() -> Self {
        Self::PlaintextOptOut
    }

    #[must_use]
    pub(super) const fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    pub(super) const fn listener_transport(&self) -> crate::ListenerTransport {
        match self {
            Self::Tls(profile) if profile.requires_client_authentication() => {
                crate::ListenerTransport::MutualTls
            },
            Self::Tls(_) => crate::ListenerTransport::Tls,
            Self::PlaintextOptOut => crate::ListenerTransport::PlaintextOptOut,
        }
    }

    pub(super) fn material_identity(&self) -> Result<[u8; 32], TlsFailure> {
        match self {
            Self::Tls(profile) => profile.material_identity(),
            Self::PlaintextOptOut => Ok([0; 32]),
        }
    }

    pub(super) fn server_connection(&self) -> Result<ServerConnection, NativeHostFailure> {
        match self {
            Self::Tls(profile) => ServerConnection::new(
                profile
                    .load()
                    .map_err(|_| NativeHostFailure::InvalidTlsProfile)?,
            )
            .map_err(|_| NativeHostFailure::InvalidTlsProfile),
            Self::PlaintextOptOut => Err(NativeHostFailure::InvalidTlsProfile),
        }
    }

    pub(super) fn grpc_server_config(&self) -> Result<Option<ServerTlsConfig>, NativeHostFailure> {
        match self {
            Self::Tls(profile) => profile
                .grpc_server_config()
                .map(Some)
                .map_err(|_| NativeHostFailure::InvalidTlsProfile),
            Self::PlaintextOptOut => Ok(None),
        }
    }
}

fn load_tls(
    identity: &TlsIdentity,
    client_trust: Option<&TlsTrust>,
) -> Result<LoadedTls, TlsFailure> {
    if identity.certificate_file.as_os_str().is_empty()
        || identity.private_key_file.as_os_str().is_empty()
    {
        return Err(TlsFailure::IncompleteIdentity);
    }
    let certificate_pem =
        fs::read(&identity.certificate_file).map_err(|_| TlsFailure::CertificateUnreadable)?;
    let private_key_pem = Zeroizing::new(
        fs::read(&identity.private_key_file).map_err(|_| TlsFailure::PrivateKeyUnreadable)?,
    );
    let certificates = read_certificates(&certificate_pem, false)?;
    let private_key = read_private_key(&private_key_pem)?;
    let trust_pem = client_trust
        .map(|trust| fs::read(&trust.certificate_file).map_err(|_| TlsFailure::TrustUnreadable))
        .transpose()?;
    let configuration = match client_trust {
        Some(_) => {
            let roots = read_trust_store(trust_pem.as_deref().ok_or(TlsFailure::TrustUnreadable)?)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|_| TlsFailure::ClientAuthenticationInvalid)?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certificates, private_key)
        },
        None => ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key),
    }
    .map_err(|_| TlsFailure::IdentityInvalid)?;
    Ok(LoadedTls {
        server: Arc::new(configuration),
        certificate_pem,
        private_key_pem,
        trust_pem,
    })
}

fn read_certificates(
    bytes: &[u8],
    trust_store: bool,
) -> Result<Vec<CertificateDer<'static>>, TlsFailure> {
    let certificates = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            if trust_store {
                TlsFailure::TrustInvalid
            } else {
                TlsFailure::CertificateInvalid
            }
        })?;
    if certificates.is_empty() {
        return Err(if trust_store {
            TlsFailure::TrustInvalid
        } else {
            TlsFailure::CertificateInvalid
        });
    }
    Ok(certificates)
}

fn read_private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, TlsFailure> {
    PrivateKeyDer::from_pem_slice(bytes).map_err(|_| TlsFailure::PrivateKeyInvalid)
}

fn read_trust_store(bytes: &[u8]) -> Result<RootCertStore, TlsFailure> {
    let certificates = read_certificates(bytes, true)?;
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| TlsFailure::TrustInvalid)?;
    }
    if roots.is_empty() {
        return Err(TlsFailure::TrustInvalid);
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{TlsIdentity, TlsProfile};

    static NEXT_TEST_PATH: AtomicU64 = AtomicU64::new(0);

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(format!(
            "{}/tests/native_transport/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
    }

    #[test]
    fn grpc_configuration_uses_the_material_validated_before_the_file_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let sequence = NEXT_TEST_PATH.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!("positron-tls-cache-{sequence}"));
        fs::create_dir(&directory)?;
        let certificate = directory.join("certificate.pem");
        let private_key = directory.join("private-key.pem");
        fs::copy(fixture("api-test-cert.pem"), &certificate)?;
        fs::copy(fixture("api-test-key.pem"), &private_key)?;
        let profile = TlsProfile::new(TlsIdentity::new(certificate.clone(), private_key), None);
        assert!(profile.load().is_ok());
        fs::write(&certificate, b"not a certificate")?;
        assert!(profile.grpc_server_config().is_ok());
        fs::remove_dir_all(directory)?;
        Ok(())
    }
}
