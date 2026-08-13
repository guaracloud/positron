use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};
use positron_kernel::{BootstrapKeyIdentity, InstanceId, TransactionId};
use zeroize::Zeroizing;

use super::{BootstrapFailure, BootstrapFailureCode};

const PENDING_MAGIC_V1: [u8; 8] = *b"POSIPN01";
const INITIALIZED_MAGIC_V1: [u8; 8] = *b"POSINI01";
const PENDING_MAGIC_V2: [u8; 8] = *b"POSIPN02";
const INITIALIZED_MAGIC_V2: [u8; 8] = *b"POSINI02";
const CLAIM_MAGIC_V1: [u8; 8] = *b"POSCLM01";
const CLAIM_MAGIC_V2: [u8; 8] = *b"POSCLM02";
const PENDING_MAGIC_V3: [u8; 8] = *b"POSIPN03";
const INITIALIZED_MAGIC_V3: [u8; 8] = *b"POSINI03";
const CLAIM_MAGIC_V3: [u8; 8] = *b"POSCLM03";
const RECORD_V1_INITIALIZED_BYTES: usize = 224;
const RECORD_V1_PENDING_BYTES: usize = 288;
const RECORD_V2_INITIALIZED_BYTES: usize = 304;
const RECORD_V2_PENDING_BYTES: usize = 400;
const CLAIM_V1_BYTES: usize = 72;
const CLAIM_V2_BYTES: usize = 120;
const RECORD_V3_INITIALIZED_BYTES: usize = 384;
const RECORD_V3_PENDING_BYTES: usize = 512;
const CLAIM_V3_BYTES: usize = 168;

pub(super) struct BootstrapIngestIdentity {
    pub(super) principal: PrincipalId,
    pub(super) api_key_salt: [u8; 32],
    pub(super) api_key_hash: [u8; 32],
    pub(super) api_key_secret: Option<Zeroizing<[u8; 32]>>,
}

pub(super) struct BootstrapQueryIdentity {
    pub(super) principal: PrincipalId,
    pub(super) api_key_salt: [u8; 32],
    pub(super) api_key_hash: [u8; 32],
    pub(super) api_key_secret: Option<Zeroizing<[u8; 32]>>,
}

pub(super) struct BootstrapRecord {
    pub(super) instance: InstanceId,
    pub(super) key: BootstrapKeyIdentity,
    pub(super) tenant: TenantId,
    pub(super) administrator: PrincipalId,
    pub(super) transaction: TransactionId,
    pub(super) api_key_salt: [u8; 32],
    pub(super) api_key_hash: [u8; 32],
    pub(super) integrity_fingerprint: [u8; 32],
    pub(super) ingest: Option<BootstrapIngestIdentity>,
    pub(super) query: Option<BootstrapQueryIdentity>,
    pub(super) api_key_secret: Option<Zeroizing<[u8; 32]>>,
    pub(super) integrity_key_secret: Option<Zeroizing<[u8; 32]>>,
}

impl BootstrapRecord {
    pub(super) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let pending = self.api_key_secret.is_some();
        let version = match (self.ingest.is_some(), self.query.is_some()) {
            (false, false) => 1,
            (true, false) => 2,
            (true, true) => 3,
            (false, true) => 0,
        };
        let capacity = match (version, pending) {
            (1, false) => RECORD_V1_INITIALIZED_BYTES,
            (1, true) => RECORD_V1_PENDING_BYTES,
            (2, false) => RECORD_V2_INITIALIZED_BYTES,
            (2, true) => RECORD_V2_PENDING_BYTES,
            (3, false) => RECORD_V3_INITIALIZED_BYTES,
            (3, true) => RECORD_V3_PENDING_BYTES,
            _ => 0,
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
        bytes.extend_from_slice(match (version, pending) {
            (1, false) => &INITIALIZED_MAGIC_V1,
            (1, true) => &PENDING_MAGIC_V1,
            (2, false) => &INITIALIZED_MAGIC_V2,
            (2, true) => &PENDING_MAGIC_V2,
            (3, false) => &INITIALIZED_MAGIC_V3,
            (3, true) => &PENDING_MAGIC_V3,
            _ => &INITIALIZED_MAGIC_V3,
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
        if let Some(ingest) = &self.ingest {
            bytes.extend_from_slice(&ingest.principal.to_bytes());
            bytes.extend_from_slice(&ingest.api_key_salt);
            bytes.extend_from_slice(&ingest.api_key_hash);
        }
        if let Some(query) = &self.query {
            bytes.extend_from_slice(&query.principal.to_bytes());
            bytes.extend_from_slice(&query.api_key_salt);
            bytes.extend_from_slice(&query.api_key_hash);
        }
        if let Some(secret) = &self.api_key_secret {
            bytes.extend_from_slice(secret.as_ref());
        }
        if let Some(secret) = self
            .ingest
            .as_ref()
            .and_then(|ingest| ingest.api_key_secret.as_ref())
        {
            bytes.extend_from_slice(secret.as_ref());
        }
        if let Some(secret) = self
            .query
            .as_ref()
            .and_then(|query| query.api_key_secret.as_ref())
        {
            bytes.extend_from_slice(secret.as_ref());
        }
        if let Some(secret) = &self.integrity_key_secret {
            bytes.extend_from_slice(secret.as_ref());
        }
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, BootstrapFailure> {
        let magic = bytes.get(..8).ok_or_else(corrupt)?;
        let (version, pending, expected) = match magic {
            value if value == PENDING_MAGIC_V1 => (1, true, RECORD_V1_PENDING_BYTES),
            value if value == INITIALIZED_MAGIC_V1 => (1, false, RECORD_V1_INITIALIZED_BYTES),
            value if value == PENDING_MAGIC_V2 => (2, true, RECORD_V2_PENDING_BYTES),
            value if value == INITIALIZED_MAGIC_V2 => (2, false, RECORD_V2_INITIALIZED_BYTES),
            value if value == PENDING_MAGIC_V3 => (3, true, RECORD_V3_PENDING_BYTES),
            value if value == INITIALIZED_MAGIC_V3 => (3, false, RECORD_V3_INITIALIZED_BYTES),
            _ => return Err(corrupt()),
        };
        if bytes.len() != expected {
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
            ingest: if version >= 2 {
                Some(BootstrapIngestIdentity {
                    principal: PrincipalId::from_bytes(array(bytes, 224, 240)?)
                        .map_err(|_| corrupt())?,
                    api_key_salt: array(bytes, 240, 272)?,
                    api_key_hash: array(bytes, 272, 304)?,
                    api_key_secret: if pending {
                        let start = if version == 2 { 336 } else { 416 };
                        Some(Zeroizing::new(array(bytes, start, start + 32)?))
                    } else {
                        None
                    },
                })
            } else {
                None
            },
            query: if version >= 3 {
                Some(BootstrapQueryIdentity {
                    principal: PrincipalId::from_bytes(array(bytes, 304, 320)?)
                        .map_err(|_| corrupt())?,
                    api_key_salt: array(bytes, 320, 352)?,
                    api_key_hash: array(bytes, 352, 384)?,
                    api_key_secret: if pending {
                        Some(Zeroizing::new(array(bytes, 448, 480)?))
                    } else {
                        None
                    },
                })
            } else {
                None
            },
            api_key_secret: if pending {
                let start = match version {
                    1 => 224,
                    2 => 304,
                    _ => 384,
                };
                Some(Zeroizing::new(array(bytes, start, start + 32)?))
            } else {
                None
            },
            integrity_key_secret: if pending {
                let start = match version {
                    1 => 256,
                    2 => 368,
                    _ => 480,
                };
                Some(Zeroizing::new(array(bytes, start, start + 32)?))
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
            ingest: self.ingest.as_ref().map(|ingest| BootstrapIngestIdentity {
                principal: ingest.principal,
                api_key_salt: ingest.api_key_salt,
                api_key_hash: ingest.api_key_hash,
                api_key_secret: None,
            }),
            query: self.query.as_ref().map(|query| BootstrapQueryIdentity {
                principal: query.principal,
                api_key_salt: query.api_key_salt,
                api_key_hash: query.api_key_hash,
                api_key_secret: None,
            }),
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
    ingest_principal: PrincipalId,
    ingest_secret: &[u8; 32],
    query_principal: PrincipalId,
    query_secret: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(CLAIM_V3_BYTES));
    bytes.extend_from_slice(&CLAIM_MAGIC_V3);
    bytes.extend_from_slice(&instance.to_bytes());
    bytes.extend_from_slice(&principal.to_bytes());
    bytes.extend_from_slice(secret);
    bytes.extend_from_slice(&ingest_principal.to_bytes());
    bytes.extend_from_slice(ingest_secret);
    bytes.extend_from_slice(&query_principal.to_bytes());
    bytes.extend_from_slice(query_secret);
    bytes
}

pub(super) fn encode_legacy_claim(
    instance: InstanceId,
    principal: PrincipalId,
    secret: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(CLAIM_V1_BYTES));
    bytes.extend_from_slice(&CLAIM_MAGIC_V1);
    bytes.extend_from_slice(&instance.to_bytes());
    bytes.extend_from_slice(&principal.to_bytes());
    bytes.extend_from_slice(secret);
    bytes
}

pub(super) struct DecodedBootstrapClaim {
    pub(super) principal: PrincipalId,
    pub(super) secret: Zeroizing<[u8; 32]>,
    pub(super) ingest: Option<(PrincipalId, Zeroizing<[u8; 32]>)>,
    pub(super) query: Option<(PrincipalId, Zeroizing<[u8; 32]>)>,
}

impl std::fmt::Debug for DecodedBootstrapClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DecodedBootstrapClaim { <redacted> }")
    }
}

pub(super) fn decode_claim(
    expected_instance: InstanceId,
    bytes: &[u8],
) -> Result<DecodedBootstrapClaim, BootstrapFailure> {
    let version = match bytes.get(..8) {
        Some(magic) if magic == CLAIM_MAGIC_V1 && bytes.len() == CLAIM_V1_BYTES => 1,
        Some(magic) if magic == CLAIM_MAGIC_V2 && bytes.len() == CLAIM_V2_BYTES => 2,
        Some(magic) if magic == CLAIM_MAGIC_V3 && bytes.len() == CLAIM_V3_BYTES => 3,
        _ => return Err(corrupt()),
    };
    if array::<16>(bytes, 8, 24)? != expected_instance.to_bytes() {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::IdentityMismatch,
        ));
    }
    Ok(DecodedBootstrapClaim {
        principal: PrincipalId::from_bytes(array(bytes, 24, 40)?).map_err(|_| corrupt())?,
        secret: Zeroizing::new(array(bytes, 40, 72)?),
        ingest: if version >= 2 {
            Some((
                PrincipalId::from_bytes(array(bytes, 72, 88)?).map_err(|_| corrupt())?,
                Zeroizing::new(array(bytes, 88, 120)?),
            ))
        } else {
            None
        },
        query: if version >= 3 {
            Some((
                PrincipalId::from_bytes(array(bytes, 120, 136)?).map_err(|_| corrupt())?,
                Zeroizing::new(array(bytes, 136, 168)?),
            ))
        } else {
            None
        },
    })
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
