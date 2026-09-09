use std::fmt::{Debug, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{ServerConfig, ServerConnection};
use zeroize::Zeroizing;

use super::NativeHostFailure;

/// The one transport policy for the native API listener.
#[derive(Clone)]
pub enum ApiTransportProfile {
    /// TLS authenticated by the configured certificate chain and private key.
    Tls(Arc<ServerConfig>),
    /// A deliberate operator opt-out, never selected as a TLS fallback.
    PlaintextOptOut,
}

impl ApiTransportProfile {
    /// Loads one complete PEM identity before the listener can bind.
    pub fn tls(
        certificate_file: PathBuf,
        private_key_file: PathBuf,
    ) -> Result<Self, NativeHostFailure> {
        let certificates = read_certificates(&certificate_file)?;
        let private_key = read_private_key(&private_key_file)?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|_| NativeHostFailure::InvalidTlsProfile)?;
        Ok(Self::Tls(Arc::new(config)))
    }

    #[must_use]
    pub const fn plaintext_opt_out() -> Self {
        Self::PlaintextOptOut
    }

    #[must_use]
    pub(super) const fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    pub(super) fn server_connection(&self) -> Result<ServerConnection, NativeHostFailure> {
        match self {
            Self::Tls(config) => ServerConnection::new(Arc::clone(config))
                .map_err(|_| NativeHostFailure::InvalidTlsProfile),
            Self::PlaintextOptOut => Err(NativeHostFailure::InvalidTlsProfile),
        }
    }
}

impl Debug for ApiTransportProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls(_) => formatter.write_str("ApiTransportProfile::Tls(<redacted identity>)"),
            Self::PlaintextOptOut => formatter.write_str("ApiTransportProfile::PlaintextOptOut"),
        }
    }
}

fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, NativeHostFailure> {
    let bytes = fs::read(path).map_err(|_| NativeHostFailure::InvalidTlsProfile)?;
    let certificates = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NativeHostFailure::InvalidTlsProfile)?;
    if certificates.is_empty() {
        return Err(NativeHostFailure::InvalidTlsProfile);
    }
    Ok(certificates)
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, NativeHostFailure> {
    let bytes = Zeroizing::new(fs::read(path).map_err(|_| NativeHostFailure::InvalidTlsProfile)?);
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|_| NativeHostFailure::InvalidTlsProfile)
}
