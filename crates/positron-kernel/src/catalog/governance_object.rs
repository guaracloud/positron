use std::num::NonZeroU64;

use positron_domain::identity::{ExternalTenantAlias, PrincipalId, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_domain::routing::SignalKind;

use super::{CatalogFailure, CatalogFailureCode, CatalogObjectId, CatalogSnapshot, InstanceId};

const MAGIC_V1: [u8; 8] = *b"POSGOV01";
const MAGIC_V2: [u8; 8] = *b"POSGOV02";
const MAGIC_V3: [u8; 8] = *b"POSGOV03";
const MAGIC_V4: [u8; 8] = *b"POSGOV04";
const MAX_RETENTION_SECONDS: u64 = i64::MAX as u64 / 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogGovernanceVersion {
    V1,
    V2,
    V3,
    V4,
}

#[derive(Clone)]
struct CredentialRecord {
    principal: PrincipalId,
    salt: [u8; 32],
    hash: [u8; 32],
}

/// Structurally validated immutable governance record decoded from Catalog bytes.
///
/// Authorization and lifecycle interpretation remain Governance-owned. This
/// type centralizes only the persistent object layout shared by Catalog policy
/// evidence and Governance identity reconstruction.
#[derive(Clone)]
pub struct CatalogGovernanceObject {
    version: CatalogGovernanceVersion,
    instance: [u8; 16],
    tenant: TenantId,
    tenant_slug: TenantSlug,
    external_alias: Option<ExternalTenantAlias>,
    principal: PrincipalId,
    salt: [u8; 32],
    hash: [u8; 32],
    ingest: Option<CredentialRecord>,
    query: Option<CredentialRecord>,
    retention_seconds: u64,
    lifecycle: TenantLifecycleState,
}

impl CatalogGovernanceObject {
    /// Decodes one immutable governance object without authenticating Catalog membership.
    /// Product authority is established only by [`CatalogSnapshot::governance_object`].
    pub fn decode(encoded: &[u8]) -> Result<Self, CatalogFailure> {
        decode(encoded)
    }

    #[must_use]
    pub const fn instance(&self) -> [u8; 16] {
        self.instance
    }

    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn tenant_slug(&self) -> TenantSlug {
        self.tenant_slug.clone()
    }

    #[must_use]
    pub fn external_tenant_alias(&self) -> Option<ExternalTenantAlias> {
        self.external_alias.clone()
    }

    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub const fn principal_secret(&self) -> ([u8; 32], [u8; 32]) {
        (self.salt, self.hash)
    }

    #[must_use]
    pub fn ingest_credential(&self) -> Option<(PrincipalId, [u8; 32], [u8; 32])> {
        self.ingest
            .as_ref()
            .map(|credential| (credential.principal, credential.salt, credential.hash))
    }

    #[must_use]
    pub fn query_credential(&self) -> Option<(PrincipalId, [u8; 32], [u8; 32])> {
        self.query
            .as_ref()
            .map(|credential| (credential.principal, credential.salt, credential.hash))
    }

    #[must_use]
    pub const fn lifecycle(&self) -> TenantLifecycleState {
        self.lifecycle
    }
}

/// Opaque v3/v4 signal retention evidence from one authenticated Catalog snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogLogRetentionPolicy {
    instance: InstanceId,
    tenant: TenantId,
    signal: SignalKind,
    retention_seconds: NonZeroU64,
    object: CatalogObjectId,
}

impl CatalogLogRetentionPolicy {
    #[must_use]
    pub const fn instance(&self) -> InstanceId {
        self.instance
    }

    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub const fn signal_kind(&self) -> SignalKind {
        self.signal
    }

    #[must_use]
    pub const fn retention_seconds(&self) -> NonZeroU64 {
        self.retention_seconds
    }
}

impl CatalogSnapshot {
    /// Returns the unique structurally valid governance object in this authenticated snapshot.
    pub fn governance_object(
        &self,
    ) -> Result<(CatalogObjectId, CatalogGovernanceObject), CatalogFailure> {
        let mut found = None;
        for (identity, bytes) in &self.0.objects {
            if !is_governance(bytes) {
                continue;
            }
            if found.is_some() {
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            }
            found = Some((*identity, CatalogGovernanceObject::decode(bytes)?));
        }
        found.ok_or_else(|| CatalogFailure::new(CatalogFailureCode::StaleGeneration))
    }

    /// Derives exact current Log-retention evidence from this authenticated snapshot.
    pub fn log_retention_policy(&self) -> Result<CatalogLogRetentionPolicy, CatalogFailure> {
        self.retention_policy(SignalKind::Logs)
    }

    /// Derives retention evidence scoped to one implemented physical signal.
    pub fn retention_policy(
        &self,
        signal: SignalKind,
    ) -> Result<CatalogLogRetentionPolicy, CatalogFailure> {
        if !matches!(signal, SignalKind::Logs | SignalKind::Traces) {
            return Err(CatalogFailure::new(CatalogFailureCode::UnsupportedFormat));
        }
        let (object, governance) = self.governance_object()?;
        if !matches!(
            governance.version,
            CatalogGovernanceVersion::V3 | CatalogGovernanceVersion::V4
        ) {
            return Err(CatalogFailure::new(CatalogFailureCode::UnsupportedFormat));
        }
        let retention_seconds = NonZeroU64::new(governance.retention_seconds)
            .filter(|duration| duration.get() <= MAX_RETENTION_SECONDS)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        Ok(CatalogLogRetentionPolicy {
            instance: InstanceId::new(governance.instance)?,
            tenant: governance.tenant,
            signal,
            retention_seconds,
            object,
        })
    }
}

fn decode(encoded: &[u8]) -> Result<CatalogGovernanceObject, CatalogFailure> {
    let mut cursor = Cursor::new(encoded);
    let version = match cursor.take_array::<8>()? {
        MAGIC_V1 => CatalogGovernanceVersion::V1,
        MAGIC_V2 => CatalogGovernanceVersion::V2,
        MAGIC_V3 => CatalogGovernanceVersion::V3,
        MAGIC_V4 => CatalogGovernanceVersion::V4,
        _ => return Err(corrupt()),
    };
    let instance = cursor.take_array::<16>()?;
    require_nonzero(instance)?;
    let tenant = TenantId::from_bytes(cursor.take_array::<16>()?).map_err(|_| corrupt())?;
    let tenant_slug =
        TenantSlug::parse_canonical(cursor.take_text_u8(63)?).map_err(|_| corrupt())?;
    let external_alias = if version == CatalogGovernanceVersion::V4 {
        match cursor.take_u8()? {
            1 => {
                Some(ExternalTenantAlias::parse(cursor.take_text_u8(128)?).map_err(|_| corrupt())?)
            },
            _ => return Err(corrupt()),
        }
    } else {
        None
    };
    if cursor.take_text_u8(128)?.is_empty() {
        return Err(corrupt());
    }
    let principal = PrincipalId::from_bytes(cursor.take_array::<16>()?).map_err(|_| corrupt())?;
    let salt = cursor.take_array::<32>()?;
    let hash = cursor.take_array::<32>()?;
    require_nonzero(salt)?;
    require_nonzero(hash)?;
    let ingest = if matches!(
        version,
        CatalogGovernanceVersion::V2 | CatalogGovernanceVersion::V3 | CatalogGovernanceVersion::V4
    ) {
        let credential = cursor.take_credential()?;
        if credential.principal == principal {
            return Err(corrupt());
        }
        Some(credential)
    } else {
        None
    };
    let query = if matches!(
        version,
        CatalogGovernanceVersion::V3 | CatalogGovernanceVersion::V4
    ) {
        let credential = cursor.take_credential()?;
        if credential.principal == principal
            || ingest
                .as_ref()
                .is_some_and(|ingest| ingest.principal == credential.principal)
        {
            return Err(corrupt());
        }
        Some(credential)
    } else {
        None
    };
    require_nonzero(cursor.take_array::<32>()?)?;
    require_nonzero(cursor.take_array::<32>()?)?;
    cursor.skip_u16_bytes()?;
    cursor.skip_u16_bytes()?;
    let retention_seconds = cursor.take_u64()?;
    if retention_seconds == 0 || cursor.take_u64()? == 0 || cursor.take_u32()? == 0 {
        return Err(corrupt());
    }
    for _ in 0..11 {
        if cursor.take_u64()? == 0 {
            return Err(corrupt());
        }
    }
    let lifecycle = match cursor.take_array::<5>()? {
        [1, 4, 0, 1, 1] => TenantLifecycleState::Active,
        [2, 4, 0, 1, 1] => TenantLifecycleState::ReadOnly,
        [3, 4, 0, 1, 1] => TenantLifecycleState::Suspended,
        [4, 4, 0, 1, 1] => TenantLifecycleState::Purging,
        [5, 4, 0, 1, 1] => TenantLifecycleState::Purged,
        _ => return Err(corrupt()),
    };
    if !cursor.is_empty() {
        return Err(corrupt());
    }
    Ok(CatalogGovernanceObject {
        version,
        instance,
        tenant,
        tenant_slug,
        external_alias,
        principal,
        salt,
        hash,
        ingest,
        query,
        retention_seconds,
        lifecycle,
    })
}

fn is_governance(bytes: &[u8]) -> bool {
    bytes.starts_with(&MAGIC_V1)
        || bytes.starts_with(&MAGIC_V2)
        || bytes.starts_with(&MAGIC_V3)
        || bytes.starts_with(&MAGIC_V4)
}

fn require_nonzero<const N: usize>(bytes: [u8; N]) -> Result<(), CatalogFailure> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(corrupt())
    } else {
        Ok(())
    }
}

const fn corrupt() -> CatalogFailure {
    CatalogFailure::new(CatalogFailureCode::IntegrityCorruption)
}

struct Cursor<'encoded> {
    remaining: &'encoded [u8],
}

impl<'encoded> Cursor<'encoded> {
    const fn new(encoded: &'encoded [u8]) -> Self {
        Self { remaining: encoded }
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CatalogFailure> {
        let (value, remaining) = self.remaining.split_at_checked(N).ok_or_else(corrupt)?;
        self.remaining = remaining;
        value.try_into().map_err(|_| corrupt())
    }

    fn take_u32(&mut self) -> Result<u32, CatalogFailure> {
        self.take_array().map(u32::from_be_bytes)
    }

    fn take_u8(&mut self) -> Result<u8, CatalogFailure> {
        self.take_array::<1>().map(|bytes| bytes[0])
    }

    fn take_u64(&mut self) -> Result<u64, CatalogFailure> {
        self.take_array().map(u64::from_be_bytes)
    }

    fn take_text_u8(&mut self, maximum: usize) -> Result<&'encoded str, CatalogFailure> {
        let length = usize::from(self.take_array::<1>()?[0]);
        if length > maximum {
            return Err(corrupt());
        }
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or_else(corrupt)?;
        self.remaining = remaining;
        std::str::from_utf8(value).map_err(|_| corrupt())
    }

    fn take_credential(&mut self) -> Result<CredentialRecord, CatalogFailure> {
        let principal = PrincipalId::from_bytes(self.take_array::<16>()?).map_err(|_| corrupt())?;
        let salt = self.take_array::<32>()?;
        let hash = self.take_array::<32>()?;
        require_nonzero(salt)?;
        require_nonzero(hash)?;
        Ok(CredentialRecord {
            principal,
            salt,
            hash,
        })
    }

    fn skip_u16_bytes(&mut self) -> Result<(), CatalogFailure> {
        let length = usize::from(u16::from_be_bytes(self.take_array()?));
        if length == 0 {
            return Err(corrupt());
        }
        let (_, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or_else(corrupt)?;
        self.remaining = remaining;
        Ok(())
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{CatalogFailureCode, CatalogGovernanceObject};

    #[test]
    fn current_governance_object_requires_an_external_alias() {
        let encoded = valid_v4_object(false);
        let failure = match CatalogGovernanceObject::decode(&encoded) {
            Ok(_) => panic!("a current object without an alias must fail closed"),
            Err(failure) => failure,
        };
        assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
    }

    fn valid_v4_object(with_alias: bool) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"POSGOV04");
        encoded.extend_from_slice(&[1; 16]);
        encoded.extend_from_slice(&[2; 16]);
        encoded.push(7);
        encoded.extend_from_slice(b"default");
        encoded.push(u8::from(with_alias));
        if with_alias {
            encoded.push(13);
            encoded.extend_from_slice(b"trace-external");
        }
        encoded.push(7);
        encoded.extend_from_slice(b"Default");
        encoded.extend_from_slice(&[3; 16]);
        encoded.extend_from_slice(&[4; 32]);
        encoded.extend_from_slice(&[5; 32]);
        encoded.extend_from_slice(&[6; 16]);
        encoded.extend_from_slice(&[7; 32]);
        encoded.extend_from_slice(&[8; 32]);
        encoded.extend_from_slice(&[9; 16]);
        encoded.extend_from_slice(&[10; 32]);
        encoded.extend_from_slice(&[11; 32]);
        encoded.extend_from_slice(&[12; 32]);
        encoded.extend_from_slice(&[13; 32]);
        encoded.extend_from_slice(&2_u16.to_be_bytes());
        encoded.extend_from_slice(&[14; 2]);
        encoded.extend_from_slice(&2_u16.to_be_bytes());
        encoded.extend_from_slice(&[15; 2]);
        encoded.extend_from_slice(&2_u64.to_be_bytes());
        encoded.extend_from_slice(&1_u64.to_be_bytes());
        encoded.extend_from_slice(&1_u32.to_be_bytes());
        for _ in 0..11 {
            encoded.extend_from_slice(&1_u64.to_be_bytes());
        }
        encoded.extend_from_slice(&[1, 4, 0, 1, 1]);
        encoded
    }
}
