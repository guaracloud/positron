use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};
use positron_kernel::{BootstrapKeyIdentity, InstanceId, TransactionId};
use zeroize::Zeroizing;

use super::{BootstrapFailure, BootstrapFailureCode};

const PENDING_MAGIC: [u8; 8] = *b"POSIPN01";
const INITIALIZED_MAGIC: [u8; 8] = *b"POSINI01";
const CLAIM_MAGIC: [u8; 8] = *b"POSCLM01";
const RECORD_BYTES_WITHOUT_SECRET: usize = 224;
const RECORD_BYTES_WITH_SECRET: usize = 288;
const CLAIM_BYTES: usize = 72;

pub(super) struct BootstrapRecord {
    pub(super) instance: InstanceId,
    pub(super) key: BootstrapKeyIdentity,
    pub(super) tenant: TenantId,
    pub(super) administrator: PrincipalId,
    pub(super) transaction: TransactionId,
    pub(super) api_key_salt: [u8; 32],
    pub(super) api_key_hash: [u8; 32],
    pub(super) integrity_fingerprint: [u8; 32],
    pub(super) api_key_secret: Option<Zeroizing<[u8; 32]>>,
    pub(super) integrity_key_secret: Option<Zeroizing<[u8; 32]>>,
}

impl BootstrapRecord {
    pub(super) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(if self.api_key_secret.is_some() {
            RECORD_BYTES_WITH_SECRET
        } else {
            RECORD_BYTES_WITHOUT_SECRET
        }));
        bytes.extend_from_slice(if self.api_key_secret.is_some() {
            &PENDING_MAGIC
        } else {
            &INITIALIZED_MAGIC
        });
        bytes.extend_from_slice(&self.instance.to_bytes());
        bytes.extend_from_slice(&self.key.key_id());
        bytes.extend_from_slice(&self.key.fingerprint());
        bytes.extend_from_slice(&self.key.created_at_unix_seconds().to_be_bytes());
        bytes.extend_from_slice(&self.tenant.to_bytes());
        bytes.extend_from_slice(&self.administrator.to_bytes());
        bytes.extend_from_slice(&self.transaction.to_bytes());
        bytes.extend_from_slice(&self.api_key_salt);
        bytes.extend_from_slice(&self.api_key_hash);
        bytes.extend_from_slice(&self.integrity_fingerprint);
        if let Some(secret) = &self.api_key_secret {
            bytes.extend_from_slice(secret.as_ref());
        }
        if let Some(secret) = &self.integrity_key_secret {
            bytes.extend_from_slice(secret.as_ref());
        }
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, BootstrapFailure> {
        let pending = bytes.get(..8) == Some(PENDING_MAGIC.as_slice());
        let initialized = bytes.get(..8) == Some(INITIALIZED_MAGIC.as_slice());
        let expected = if pending {
            RECORD_BYTES_WITH_SECRET
        } else {
            RECORD_BYTES_WITHOUT_SECRET
        };
        if (!pending && !initialized) || bytes.len() != expected {
            return Err(corrupt());
        }
        let instance = InstanceId::new(array(bytes, 8, 24)?).map_err(|_| corrupt())?;
        let key = BootstrapKeyIdentity::from_parts(
            array(bytes, 24, 40)?,
            array(bytes, 40, 72)?,
            u64::from_be_bytes(array(bytes, 72, 80)?),
        )
        .map_err(|_| corrupt())?;
        let tenant = TenantId::from_bytes(array(bytes, 80, 96)?).map_err(|_| corrupt())?;
        let administrator =
            PrincipalId::from_bytes(array(bytes, 96, 112)?).map_err(|_| corrupt())?;
        let transaction = TransactionId::new(array(bytes, 112, 128)?).map_err(|_| corrupt())?;
        Ok(Self {
            instance,
            key,
            tenant,
            administrator,
            transaction,
            api_key_salt: array(bytes, 128, 160)?,
            api_key_hash: array(bytes, 160, 192)?,
            integrity_fingerprint: array(bytes, 192, 224)?,
            api_key_secret: if pending {
                Some(Zeroizing::new(array(bytes, 224, 256)?))
            } else {
                None
            },
            integrity_key_secret: if pending {
                Some(Zeroizing::new(array(bytes, 256, 288)?))
            } else {
                None
            },
        })
    }

    pub(super) fn initialized(&self) -> Self {
        Self {
            instance: self.instance,
            key: self.key,
            tenant: self.tenant,
            administrator: self.administrator,
            transaction: self.transaction,
            api_key_salt: self.api_key_salt,
            api_key_hash: self.api_key_hash,
            integrity_fingerprint: self.integrity_fingerprint,
            api_key_secret: None,
            integrity_key_secret: None,
        }
    }

    pub(super) fn tenant_slug() -> Result<TenantSlug, BootstrapFailure> {
        TenantSlug::parse_canonical("default").map_err(|_| corrupt())
    }
}

pub(super) fn encode_claim(
    instance: InstanceId,
    principal: PrincipalId,
    secret: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(CLAIM_BYTES));
    bytes.extend_from_slice(&CLAIM_MAGIC);
    bytes.extend_from_slice(&instance.to_bytes());
    bytes.extend_from_slice(&principal.to_bytes());
    bytes.extend_from_slice(secret);
    bytes
}

pub(super) fn decode_claim(
    expected_instance: InstanceId,
    bytes: &[u8],
) -> Result<(PrincipalId, Zeroizing<[u8; 32]>), BootstrapFailure> {
    if bytes.len() != CLAIM_BYTES || bytes.get(..8) != Some(CLAIM_MAGIC.as_slice()) {
        return Err(corrupt());
    }
    if array::<16>(bytes, 8, 24)? != expected_instance.to_bytes() {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::IdentityMismatch,
        ));
    }
    Ok((
        PrincipalId::from_bytes(array(bytes, 24, 40)?).map_err(|_| corrupt())?,
        Zeroizing::new(array(bytes, 40, 72)?),
    ))
}

fn array<const N: usize>(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Result<[u8; N], BootstrapFailure> {
    bytes
        .get(start..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(corrupt)
}

fn corrupt() -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::CorruptState)
}
