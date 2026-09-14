use std::num::NonZeroU64;

use positron_domain::identity::{ExternalTenantAlias, PrincipalId, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_domain::routing::SignalKind;

use super::{CatalogFailure, CatalogFailureCode, CatalogObjectId, CatalogSnapshot, InstanceId};

const MAGIC_V1: [u8; 8] = *b"POSGOV01";
const MAGIC_V2: [u8; 8] = *b"POSGOV02";
const MAGIC_V3: [u8; 8] = *b"POSGOV03";
const MAGIC_V4: [u8; 8] = *b"POSGOV04";
const MAGIC_V5: [u8; 8] = *b"POSGOV05";
const MAGIC_V6: [u8; 8] = *b"POSGOV06";
const MAGIC_V7: [u8; 8] = *b"POSGOV07";
const MAGIC_V8: [u8; 8] = *b"POSGOV08";
const MAX_CREDENTIALS: usize = 128;
const MAX_RETENTION_SECONDS: u64 = i64::MAX as u64 / 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogGovernanceVersion {
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
    V7,
    V8,
}

#[derive(Clone)]
struct CredentialRecord {
    principal: PrincipalId,
    salt: [u8; 32],
    hash: [u8; 32],
}

/// One redacted credential descriptor from an authenticated governance object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogCredential {
    principal: PrincipalId,
    scope: u8,
    active: bool,
    expires_at_unix_seconds: Option<u64>,
    salt: [u8; 32],
    hash: [u8; 32],
}

impl CatalogCredential {
    pub fn new(
        principal: PrincipalId,
        scope: u8,
        active: bool,
        expires_at_unix_seconds: Option<u64>,
        salt: [u8; 32],
        hash: [u8; 32],
    ) -> Result<Self, CatalogFailure> {
        if !(1..=4).contains(&scope)
            || salt.iter().all(|byte| *byte == 0)
            || hash.iter().all(|byte| *byte == 0)
        {
            return Err(corrupt());
        }
        Ok(Self {
            principal,
            scope,
            active,
            expires_at_unix_seconds,
            salt,
            hash,
        })
    }
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
    #[must_use]
    pub const fn scope_code(&self) -> u8 {
        self.scope
    }
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> Option<u64> {
        self.expires_at_unix_seconds
    }
    #[must_use]
    pub const fn with_active(self, active: bool) -> Self {
        Self { active, ..self }
    }
    #[must_use]
    pub const fn salted_hash(&self) -> ([u8; 32], [u8; 32]) {
        (self.salt, self.hash)
    }
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
    display_name: String,
    principal: PrincipalId,
    salt: [u8; 32],
    hash: [u8; 32],
    ingest: Option<CredentialRecord>,
    query: Option<CredentialRecord>,
    retention_seconds: u64,
    retention_offset: usize,
    quota_generation: u64,
    quota_weight: u32,
    quota_resources: [u64; 11],
    quota_offset: usize,
    tenant_key_envelope: Vec<u8>,
    lifecycle: TenantLifecycleState,
    #[cfg(feature = "test-support")]
    lifecycle_end: usize,
    lifecycle_generation: u64,
    display_generation: u64,
    retention_generation: u64,
    alias_generation: u64,
    credentials: Vec<CatalogCredential>,
    credential_generation: u64,
    credential_prefix: Vec<u8>,
}

impl CatalogGovernanceObject {
    /// Decodes one immutable governance object without authenticating Catalog membership.
    /// Product authority is established only by [`CatalogSnapshot::governance_object`].
    pub fn decode(encoded: &[u8]) -> Result<Self, CatalogFailure> {
        codec::decode(encoded)
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
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub const fn display_generation(&self) -> u64 {
        self.display_generation
    }

    #[must_use]
    pub const fn retention_generation(&self) -> u64 {
        self.retention_generation
    }

    /// Returns the generation of the immutable external-alias resource.
    #[must_use]
    pub const fn alias_generation(&self) -> u64 {
        self.alias_generation
    }

    #[must_use]
    pub const fn retention_seconds(&self) -> u64 {
        self.retention_seconds
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

    /// Returns the independently durable generation for tenant lifecycle mutations.
    #[must_use]
    pub const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_generation
    }

    /// Returns the independently durable generation for tenant quota mutations.
    #[must_use]
    pub const fn quota_generation(&self) -> u64 {
        self.quota_generation
    }

    #[must_use]
    pub const fn quota_weight(&self) -> u32 {
        self.quota_weight
    }

    #[must_use]
    pub const fn quota_resources(&self) -> [u64; 11] {
        self.quota_resources
    }

    /// Returns the opaque tenant KEK envelope carried by this authenticated
    /// governance record. Callers must bind it to the exact instance and
    /// tenant through Data Protection before using it.
    #[must_use]
    pub fn tenant_key_envelope(&self) -> &[u8] {
        &self.tenant_key_envelope
    }

    /// Returns redacted credential descriptors; secret material is never decoded.
    #[must_use]
    pub fn credentials(&self) -> &[CatalogCredential] {
        &self.credentials
    }

    #[must_use]
    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    #[cfg(feature = "test-support")]
    pub fn fixture_lifecycle_end(&self) -> Result<usize, CatalogFailure> {
        Ok(self.lifecycle_end)
    }

    /// Encodes a successor credential set while preserving all non-credential
    /// governance authority verbatim.
    pub fn with_credentials(
        &self,
        generation: u64,
        credentials: &[CatalogCredential],
    ) -> Result<Vec<u8>, CatalogFailure> {
        if generation == 0 || !(1..=MAX_CREDENTIALS).contains(&credentials.len()) {
            return Err(corrupt());
        }
        if credentials
            .iter()
            .filter(|credential| credential.scope == 4)
            .count()
            != 1
            || credentials.iter().enumerate().any(|(index, credential)| {
                credentials[..index]
                    .iter()
                    .any(|prior| prior.principal == credential.principal)
            })
        {
            return Err(corrupt());
        }
        let mut prefix = self.credential_prefix.clone();
        if !matches!(
            self.version,
            CatalogGovernanceVersion::V6
                | CatalogGovernanceVersion::V7
                | CatalogGovernanceVersion::V8
        ) {
            let lifecycle_end = prefix.len();
            prefix
                .get_mut(..8)
                .ok_or_else(corrupt)?
                .copy_from_slice(&MAGIC_V6);
            prefix.try_reserve_exact(8).map_err(|_| corrupt())?;
            prefix.extend_from_slice(&self.lifecycle_generation.to_be_bytes());
            debug_assert_eq!(prefix.len(), lifecycle_end + 8);
        }
        let bytes = credentials
            .len()
            .checked_mul(90)
            .and_then(|size| {
                prefix
                    .len()
                    .checked_add(10)
                    .and_then(|prefix| prefix.checked_add(size))
            })
            .ok_or_else(corrupt)?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(bytes).map_err(|_| corrupt())?;
        encoded.extend_from_slice(&prefix);
        encoded.extend_from_slice(&generation.to_be_bytes());
        encoded.extend_from_slice(
            &u16::try_from(credentials.len())
                .map_err(|_| corrupt())?
                .to_be_bytes(),
        );
        for credential in credentials {
            encoded.extend_from_slice(&credential.principal.to_bytes());
            encoded.push(credential.scope);
            encoded.push(u8::from(credential.active));
            encoded.extend_from_slice(
                &credential
                    .expires_at_unix_seconds
                    .unwrap_or(0)
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(&credential.salt);
            encoded.extend_from_slice(&credential.hash);
        }
        Ok(encoded)
    }

    /// Encodes a successor lifecycle while preserving every non-lifecycle authority.
    pub fn with_lifecycle(
        &self,
        lifecycle: TenantLifecycleState,
        lifecycle_generation: u64,
    ) -> Result<Vec<u8>, CatalogFailure> {
        if lifecycle_generation == 0 {
            return Err(corrupt());
        }
        let mut prefix = self.credential_prefix.clone();
        let lifecycle_end = prefix.len();
        if !matches!(
            self.version,
            CatalogGovernanceVersion::V6 | CatalogGovernanceVersion::V7
        ) {
            prefix
                .get_mut(..8)
                .ok_or_else(corrupt)?
                .copy_from_slice(&MAGIC_V6);
            prefix.try_reserve_exact(8).map_err(|_| corrupt())?;
            prefix.extend_from_slice(&lifecycle_generation.to_be_bytes());
        } else {
            let generation_start = lifecycle_end
                .checked_sub(if self.version == CatalogGovernanceVersion::V7 {
                    24
                } else {
                    8
                })
                .ok_or_else(corrupt)?;
            prefix
                .get_mut(generation_start..generation_start.checked_add(8).ok_or_else(corrupt)?)
                .ok_or_else(corrupt)?
                .copy_from_slice(&lifecycle_generation.to_be_bytes());
            let state_start = generation_start.checked_sub(5).ok_or_else(corrupt)?;
            let state = prefix.get_mut(state_start).ok_or_else(corrupt)?;
            *state = lifecycle_code(lifecycle);
        }
        if !matches!(
            self.version,
            CatalogGovernanceVersion::V6 | CatalogGovernanceVersion::V7
        ) {
            let state_start = lifecycle_end.checked_sub(5).ok_or_else(corrupt)?;
            let state = prefix.get_mut(state_start).ok_or_else(corrupt)?;
            *state = lifecycle_code(lifecycle);
        }
        let credentials = self.credentials.clone();
        let bytes = prefix
            .len()
            .checked_add(10)
            .and_then(|size| size.checked_add(credentials.len().checked_mul(90)?))
            .ok_or_else(corrupt)?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(bytes).map_err(|_| corrupt())?;
        encoded.extend_from_slice(&prefix);
        encoded.extend_from_slice(&self.credential_generation.to_be_bytes());
        encoded.extend_from_slice(
            &u16::try_from(credentials.len())
                .map_err(|_| corrupt())?
                .to_be_bytes(),
        );
        for credential in credentials {
            encoded.extend_from_slice(&credential.principal.to_bytes());
            encoded.push(credential.scope);
            encoded.push(u8::from(credential.active));
            encoded.extend_from_slice(
                &credential
                    .expires_at_unix_seconds
                    .unwrap_or(0)
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(&credential.salt);
            encoded.extend_from_slice(&credential.hash);
        }
        Ok(encoded)
    }

    /// Encodes a successor quota while preserving every other governance authority.
    pub fn with_quota(
        &self,
        quota_generation: u64,
        quota_weight: u32,
        quota_resources: [u64; 11],
    ) -> Result<Vec<u8>, CatalogFailure> {
        if quota_generation == 0
            || quota_weight == 0
            || quota_weight > u32::from(u16::MAX)
            || quota_resources.contains(&0)
        {
            return Err(corrupt());
        }
        let generation_end = self.quota_offset.checked_add(8).ok_or_else(corrupt)?;
        let weight_end = generation_end.checked_add(4).ok_or_else(corrupt)?;
        let resources_end = weight_end.checked_add(88).ok_or_else(corrupt)?;
        let mut prefix = self.credential_prefix.clone();
        prefix
            .get_mut(self.quota_offset..generation_end)
            .ok_or_else(corrupt)?
            .copy_from_slice(&quota_generation.to_be_bytes());
        prefix
            .get_mut(generation_end..weight_end)
            .ok_or_else(corrupt)?
            .copy_from_slice(&quota_weight.to_be_bytes());
        let resources = prefix
            .get_mut(weight_end..resources_end)
            .ok_or_else(corrupt)?;
        for (slot, value) in resources.chunks_exact_mut(8).zip(quota_resources) {
            slot.copy_from_slice(&value.to_be_bytes());
        }
        encode_credentials(&prefix, self.credential_generation, &self.credentials)
    }

    /// Encodes a successor display resource, upgrading a legacy record only
    /// when that resource first changes.
    pub fn with_display_name(
        &self,
        display_name: &str,
        display_generation: u64,
    ) -> Result<Vec<u8>, CatalogFailure> {
        if display_name.is_empty() || display_name.len() > 128 || display_generation == 0 {
            return Err(corrupt());
        }
        let prefix = self.display_successor_prefix(display_name)?;
        let prefix = append_or_replace_profile_generations(
            prefix,
            self.version,
            display_generation,
            self.retention_generation,
        )?;
        encode_credentials(&prefix, self.credential_generation, &self.credentials)
    }

    /// Encodes a successor retention resource without changing the display
    /// label or its independent generation.
    pub fn with_retention_seconds(
        &self,
        retention_seconds: u64,
        retention_generation: u64,
    ) -> Result<Vec<u8>, CatalogFailure> {
        if retention_seconds == 0
            || retention_seconds > MAX_RETENTION_SECONDS
            || retention_generation == 0
        {
            return Err(corrupt());
        }
        let retention_offset = self
            .retention_offset
            .checked_add(usize::from(matches!(
                self.version,
                CatalogGovernanceVersion::V1
                    | CatalogGovernanceVersion::V2
                    | CatalogGovernanceVersion::V3
            )))
            .ok_or_else(corrupt)?;
        let mut prefix = self.credential_prefix.clone();
        let retention_end = retention_offset.checked_add(8).ok_or_else(corrupt)?;
        prefix
            .get_mut(retention_offset..retention_end)
            .ok_or_else(corrupt)?
            .copy_from_slice(&retention_seconds.to_be_bytes());
        let prefix = append_or_replace_profile_generations(
            prefix,
            self.version,
            self.display_generation,
            retention_generation,
        )?;
        encode_credentials(&prefix, self.credential_generation, &self.credentials)
    }

    /// Binds the one protocol compatibility alias while preserving every
    /// unrelated governance authority. Only the alias-administration layer
    /// decides whether this successor is legal; this codec only validates its
    /// bounded durable representation.
    pub fn with_external_tenant_alias(
        &self,
        alias: ExternalTenantAlias,
        alias_generation: u64,
    ) -> Result<Vec<u8>, CatalogFailure> {
        if alias_generation == 0
            || !matches!(
                self.version,
                CatalogGovernanceVersion::V7 | CatalogGovernanceVersion::V8
            )
        {
            return Err(corrupt());
        }
        let prefix = &self.credential_prefix;
        let slug_length = usize::from(*prefix.get(40).ok_or_else(corrupt)?);
        let alias_at = 41_usize.checked_add(slug_length).ok_or_else(corrupt)?;
        let old_alias_end = match *prefix.get(alias_at).ok_or_else(corrupt)? {
            1 => {
                let length = usize::from(
                    *prefix
                        .get(alias_at.checked_add(1).ok_or_else(corrupt)?)
                        .ok_or_else(corrupt)?,
                );
                alias_at
                    .checked_add(2)
                    .and_then(|at| at.checked_add(length))
                    .ok_or_else(corrupt)?
            },
            _ => return Err(corrupt()),
        };
        let suffix_end = if self.version == CatalogGovernanceVersion::V8 {
            prefix.len().checked_sub(8).ok_or_else(corrupt)?
        } else {
            prefix.len()
        };
        let alias_text = alias.as_str();
        let capacity = prefix
            .len()
            .checked_sub(old_alias_end.checked_sub(alias_at).ok_or_else(corrupt)?)
            .and_then(|size| size.checked_add(2))
            .and_then(|size| size.checked_add(alias_text.len()))
            .and_then(|size| size.checked_add(8))
            .ok_or_else(corrupt)?;
        let mut successor = Vec::new();
        successor
            .try_reserve_exact(capacity)
            .map_err(|_| corrupt())?;
        successor.extend_from_slice(&MAGIC_V8);
        successor.extend_from_slice(prefix.get(8..alias_at).ok_or_else(corrupt)?);
        successor.push(1);
        successor.push(u8::try_from(alias_text.len()).map_err(|_| corrupt())?);
        successor.extend_from_slice(alias_text.as_bytes());
        successor.extend_from_slice(prefix.get(old_alias_end..suffix_end).ok_or_else(corrupt)?);
        successor.extend_from_slice(&alias_generation.to_be_bytes());
        encode_credentials(&successor, self.credential_generation, &self.credentials)
    }

    fn display_successor_prefix(&self, display_name: &str) -> Result<Vec<u8>, CatalogFailure> {
        let prefix = &self.credential_prefix;
        let slug_length = usize::from(*prefix.get(40).ok_or_else(corrupt)?);
        let alias_at = 41_usize.checked_add(slug_length).ok_or_else(corrupt)?;
        let display_length_at = match *prefix.get(alias_at).ok_or_else(corrupt)? {
            0 => alias_at.checked_add(1).ok_or_else(corrupt)?,
            1 => {
                let alias_length = usize::from(
                    *prefix
                        .get(alias_at.checked_add(1).ok_or_else(corrupt)?)
                        .ok_or_else(corrupt)?,
                );
                alias_at
                    .checked_add(2)
                    .and_then(|at| at.checked_add(alias_length))
                    .ok_or_else(corrupt)?
            },
            _ => return Err(corrupt()),
        };
        let display_length = usize::from(*prefix.get(display_length_at).ok_or_else(corrupt)?);
        let display_end = display_length_at
            .checked_add(1)
            .and_then(|at| at.checked_add(display_length))
            .ok_or_else(corrupt)?;
        let capacity = prefix
            .len()
            .checked_sub(display_length)
            .and_then(|size| size.checked_add(display_name.len()))
            .ok_or_else(corrupt)?;
        let mut successor = Vec::new();
        successor
            .try_reserve_exact(capacity)
            .map_err(|_| corrupt())?;
        successor.extend_from_slice(if self.version == CatalogGovernanceVersion::V8 {
            &MAGIC_V8
        } else {
            &MAGIC_V7
        });
        successor.extend_from_slice(prefix.get(8..display_length_at).ok_or_else(corrupt)?);
        successor.push(u8::try_from(display_name.len()).map_err(|_| corrupt())?);
        successor.extend_from_slice(display_name.as_bytes());
        successor.extend_from_slice(prefix.get(display_end..).ok_or_else(corrupt)?);
        Ok(successor)
    }
}

fn append_or_replace_profile_generations(
    mut prefix: Vec<u8>,
    version: CatalogGovernanceVersion,
    display_generation: u64,
    retention_generation: u64,
) -> Result<Vec<u8>, CatalogFailure> {
    if display_generation == 0 || retention_generation == 0 {
        return Err(corrupt());
    }
    let (display_at, retention_at) = match version {
        CatalogGovernanceVersion::V7 => (
            prefix.len().checked_sub(16).ok_or_else(corrupt)?,
            prefix.len().checked_sub(8).ok_or_else(corrupt)?,
        ),
        CatalogGovernanceVersion::V8 => (
            prefix.len().checked_sub(24).ok_or_else(corrupt)?,
            prefix.len().checked_sub(16).ok_or_else(corrupt)?,
        ),
        _ => {
            prefix
                .get_mut(..8)
                .ok_or_else(corrupt)?
                .copy_from_slice(&MAGIC_V7);
            prefix.try_reserve_exact(16).map_err(|_| corrupt())?;
            prefix.extend_from_slice(&display_generation.to_be_bytes());
            prefix.extend_from_slice(&retention_generation.to_be_bytes());
            return Ok(prefix);
        },
    };
    prefix
        .get_mut(display_at..retention_at)
        .ok_or_else(corrupt)?
        .copy_from_slice(&display_generation.to_be_bytes());
    prefix
        .get_mut(retention_at..retention_at.checked_add(8).ok_or_else(corrupt)?)
        .ok_or_else(corrupt)?
        .copy_from_slice(&retention_generation.to_be_bytes());
    Ok(prefix)
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
            CatalogGovernanceVersion::V3
                | CatalogGovernanceVersion::V4
                | CatalogGovernanceVersion::V5
                | CatalogGovernanceVersion::V6
                | CatalogGovernanceVersion::V7
                | CatalogGovernanceVersion::V8
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

mod codec;

use codec::{corrupt, encode_credentials, is_governance, lifecycle_code};

#[cfg(test)]
mod tests;
