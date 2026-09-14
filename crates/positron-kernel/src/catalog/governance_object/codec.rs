//! Versioned governance-object encoding and bounded cursor decoding.

use super::*;

pub(super) fn decode(encoded: &[u8]) -> Result<CatalogGovernanceObject, CatalogFailure> {
    let mut cursor = Cursor::new(encoded);
    let version = match cursor.take_array::<8>()? {
        MAGIC_V1 => CatalogGovernanceVersion::V1,
        MAGIC_V2 => CatalogGovernanceVersion::V2,
        MAGIC_V3 => CatalogGovernanceVersion::V3,
        MAGIC_V4 => CatalogGovernanceVersion::V4,
        MAGIC_V5 => CatalogGovernanceVersion::V5,
        MAGIC_V6 => CatalogGovernanceVersion::V6,
        MAGIC_V7 => CatalogGovernanceVersion::V7,
        MAGIC_V8 => CatalogGovernanceVersion::V8,
        _ => return Err(corrupt()),
    };
    let instance = cursor.take_array::<16>()?;
    require_nonzero(instance)?;
    let tenant = TenantId::from_bytes(cursor.take_array::<16>()?).map_err(|_| corrupt())?;
    let tenant_slug =
        TenantSlug::parse_canonical(cursor.take_text_u8(63)?).map_err(|_| corrupt())?;
    let (external_alias, optional_base_credentials) = match version {
        CatalogGovernanceVersion::V4 => match cursor.take_u8()? {
            1 => (
                Some(ExternalTenantAlias::parse(cursor.take_text_u8(128)?).map_err(|_| corrupt())?),
                false,
            ),
            _ => return Err(corrupt()),
        },
        CatalogGovernanceVersion::V5
        | CatalogGovernanceVersion::V6
        | CatalogGovernanceVersion::V7
        | CatalogGovernanceVersion::V8 => match cursor.take_u8()? {
            1 => (
                Some(ExternalTenantAlias::parse(cursor.take_text_u8(128)?).map_err(|_| corrupt())?),
                false,
            ),
            // A V1-V3 successor records that its legacy alias and data
            // credentials were absent rather than inventing replacements.
            0 => (None, true),
            _ => return Err(corrupt()),
        },
        CatalogGovernanceVersion::V1
        | CatalogGovernanceVersion::V2
        | CatalogGovernanceVersion::V3 => (None, false),
    };
    let display_name = cursor.take_text_u8(128)?;
    if display_name.is_empty() {
        return Err(corrupt());
    }
    let principal = PrincipalId::from_bytes(cursor.take_array::<16>()?).map_err(|_| corrupt())?;
    let salt = cursor.take_array::<32>()?;
    let hash = cursor.take_array::<32>()?;
    require_nonzero(salt)?;
    require_nonzero(hash)?;
    let ingest = if optional_base_credentials {
        take_optional_credential(&mut cursor)?
    } else if matches!(
        version,
        CatalogGovernanceVersion::V2
            | CatalogGovernanceVersion::V3
            | CatalogGovernanceVersion::V4
            | CatalogGovernanceVersion::V5
            | CatalogGovernanceVersion::V6
            | CatalogGovernanceVersion::V7
            | CatalogGovernanceVersion::V8
    ) {
        Some(cursor.take_credential()?)
    } else {
        None
    };
    if ingest
        .as_ref()
        .is_some_and(|credential| credential.principal == principal)
    {
        return Err(corrupt());
    }
    let query = if optional_base_credentials {
        take_optional_credential(&mut cursor)?
    } else if matches!(
        version,
        CatalogGovernanceVersion::V3
            | CatalogGovernanceVersion::V4
            | CatalogGovernanceVersion::V5
            | CatalogGovernanceVersion::V6
            | CatalogGovernanceVersion::V7
            | CatalogGovernanceVersion::V8
    ) {
        Some(cursor.take_credential()?)
    } else {
        None
    };
    if query.as_ref().is_some_and(|credential| {
        credential.principal == principal
            || ingest
                .as_ref()
                .is_some_and(|ingest| ingest.principal == credential.principal)
    }) {
        return Err(corrupt());
    }
    require_nonzero(cursor.take_array::<32>()?)?;
    require_nonzero(cursor.take_array::<32>()?)?;
    cursor.skip_u16_bytes()?;
    let tenant_key_envelope = cursor.take_u16_bytes()?.to_vec();
    let retention_offset = encoded
        .len()
        .checked_sub(cursor.remaining.len())
        .ok_or_else(corrupt)?;
    let retention_seconds = cursor.take_u64()?;
    let quota_offset = encoded
        .len()
        .checked_sub(cursor.remaining.len())
        .ok_or_else(corrupt)?;
    let quota_generation = cursor.take_u64()?;
    let quota_weight = cursor.take_u32()?;
    if retention_seconds == 0 || quota_generation == 0 || quota_weight == 0 {
        return Err(corrupt());
    }
    let mut quota_resources = [0_u64; 11];
    for resource in &mut quota_resources {
        *resource = cursor.take_u64()?;
        if *resource == 0 {
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
    #[cfg(feature = "test-support")]
    let lifecycle_end = encoded
        .len()
        .checked_sub(cursor.remaining.len())
        .ok_or_else(corrupt)?;
    let lifecycle_generation = if matches!(
        version,
        CatalogGovernanceVersion::V6 | CatalogGovernanceVersion::V7 | CatalogGovernanceVersion::V8
    ) {
        let generation = cursor.take_u64()?;
        if generation == 0 {
            return Err(corrupt());
        }
        generation
    } else {
        1
    };
    let display_generation = if matches!(
        version,
        CatalogGovernanceVersion::V7 | CatalogGovernanceVersion::V8
    ) {
        let generation = cursor.take_u64()?;
        if generation == 0 {
            return Err(corrupt());
        }
        generation
    } else {
        1
    };
    let retention_generation = if matches!(
        version,
        CatalogGovernanceVersion::V7 | CatalogGovernanceVersion::V8
    ) {
        let generation = cursor.take_u64()?;
        if generation == 0 {
            return Err(corrupt());
        }
        generation
    } else {
        1
    };
    let alias_generation = if version == CatalogGovernanceVersion::V8 {
        let generation = cursor.take_u64()?;
        if generation == 0 {
            return Err(corrupt());
        }
        generation
    } else {
        1
    };
    let credential_prefix = if matches!(
        version,
        CatalogGovernanceVersion::V5
            | CatalogGovernanceVersion::V6
            | CatalogGovernanceVersion::V7
            | CatalogGovernanceVersion::V8
    ) {
        encoded
            .get(
                ..encoded
                    .len()
                    .checked_sub(cursor.remaining.len())
                    .ok_or_else(corrupt)?,
            )
            .ok_or_else(corrupt)?
            .to_vec()
    } else {
        legacy_v5_prefix(encoded, version)?
    };
    let credential_generation = if matches!(
        version,
        CatalogGovernanceVersion::V5
            | CatalogGovernanceVersion::V6
            | CatalogGovernanceVersion::V7
            | CatalogGovernanceVersion::V8
    ) {
        let generation = cursor.take_u64()?;
        if generation == 0 {
            return Err(corrupt());
        }
        generation
    } else {
        1
    };
    let credentials = if matches!(
        version,
        CatalogGovernanceVersion::V5
            | CatalogGovernanceVersion::V6
            | CatalogGovernanceVersion::V7
            | CatalogGovernanceVersion::V8
    ) {
        let count = usize::from(cursor.take_u16()?);
        if !(1..=MAX_CREDENTIALS).contains(&count) {
            return Err(corrupt());
        }
        let mut credentials = Vec::new();
        credentials
            .try_reserve_exact(count)
            .map_err(|_| corrupt())?;
        for _ in 0..count {
            let principal =
                PrincipalId::from_bytes(cursor.take_array::<16>()?).map_err(|_| corrupt())?;
            let scope = cursor.take_u8()?;
            if !(1..=4).contains(&scope) {
                return Err(corrupt());
            }
            let active = match cursor.take_u8()? {
                0 => false,
                1 => true,
                _ => return Err(corrupt()),
            };
            let expires = match cursor.take_u64()? {
                0 => None,
                value => Some(value),
            };
            let salt = cursor.take_array::<32>()?;
            let hash = cursor.take_array::<32>()?;
            require_nonzero(salt)?;
            require_nonzero(hash)?;
            if credentials
                .iter()
                .any(|credential: &CatalogCredential| credential.principal == principal)
            {
                return Err(corrupt());
            }
            credentials.push(CatalogCredential {
                principal,
                scope,
                active,
                expires_at_unix_seconds: expires,
                salt,
                hash,
            });
        }
        if credentials
            .iter()
            .filter(|credential| credential.scope == 4)
            .count()
            != 1
        {
            return Err(corrupt());
        }
        credentials
    } else {
        legacy_credentials(principal, salt, hash, ingest.as_ref(), query.as_ref())?
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
        display_name: display_name.to_owned(),
        principal,
        salt,
        hash,
        ingest,
        query,
        retention_seconds,
        retention_offset,
        quota_generation,
        quota_weight,
        quota_resources,
        quota_offset,
        tenant_key_envelope,
        lifecycle,
        #[cfg(feature = "test-support")]
        lifecycle_end,
        lifecycle_generation,
        display_generation,
        retention_generation,
        alias_generation,
        credentials,
        credential_generation,
        credential_prefix,
    })
}

fn legacy_credentials(
    principal: PrincipalId,
    salt: [u8; 32],
    hash: [u8; 32],
    ingest: Option<&CredentialRecord>,
    query: Option<&CredentialRecord>,
) -> Result<Vec<CatalogCredential>, CatalogFailure> {
    let mut credentials = Vec::new();
    credentials.try_reserve_exact(3).map_err(|_| corrupt())?;
    credentials.push(CatalogCredential::new(
        principal, 4, true, None, salt, hash,
    )?);
    if let Some(credential) = ingest {
        credentials.push(CatalogCredential::new(
            credential.principal,
            1,
            true,
            None,
            credential.salt,
            credential.hash,
        )?);
    }
    if let Some(credential) = query {
        credentials.push(CatalogCredential::new(
            credential.principal,
            2,
            true,
            None,
            credential.salt,
            credential.hash,
        )?);
    }
    Ok(credentials)
}

fn legacy_v5_prefix(
    encoded: &[u8],
    version: CatalogGovernanceVersion,
) -> Result<Vec<u8>, CatalogFailure> {
    if version == CatalogGovernanceVersion::V4 {
        let mut upgraded = encoded.to_vec();
        let magic = upgraded.get_mut(..8).ok_or_else(corrupt)?;
        magic.copy_from_slice(&MAGIC_V5);
        return Ok(upgraded);
    }
    let slug_length = usize::from(*encoded.get(40).ok_or_else(corrupt)?);
    let common_end = 41_usize.checked_add(slug_length).ok_or_else(corrupt)?;
    let display_length = usize::from(*encoded.get(common_end).ok_or_else(corrupt)?);
    let primary_end = common_end
        .checked_add(1)
        .and_then(|offset| offset.checked_add(display_length))
        .and_then(|offset| offset.checked_add(80))
        .ok_or_else(corrupt)?;
    if primary_end > encoded.len() {
        return Err(corrupt());
    }
    let mut legacy_offset = primary_end;
    let capacity = encoded.len().checked_add(11).ok_or_else(corrupt)?;
    let mut upgraded = Vec::new();
    upgraded
        .try_reserve_exact(capacity)
        .map_err(|_| corrupt())?;
    upgraded.extend_from_slice(&MAGIC_V5);
    upgraded.extend_from_slice(encoded.get(8..common_end).ok_or_else(corrupt)?);
    upgraded.push(0);
    upgraded.extend_from_slice(encoded.get(common_end..primary_end).ok_or_else(corrupt)?);
    for present in [
        matches!(
            version,
            CatalogGovernanceVersion::V2 | CatalogGovernanceVersion::V3
        ),
        matches!(version, CatalogGovernanceVersion::V3),
    ] {
        upgraded.push(u8::from(present));
        if present {
            let credential_end = legacy_offset.checked_add(80).ok_or_else(corrupt)?;
            upgraded.extend_from_slice(
                encoded
                    .get(legacy_offset..credential_end)
                    .ok_or_else(corrupt)?,
            );
            legacy_offset = credential_end;
        }
    }
    upgraded.extend_from_slice(encoded.get(legacy_offset..).ok_or_else(corrupt)?);
    Ok(upgraded)
}

fn take_optional_credential(
    cursor: &mut Cursor<'_>,
) -> Result<Option<CredentialRecord>, CatalogFailure> {
    match cursor.take_u8()? {
        0 => Ok(None),
        1 => cursor.take_credential().map(Some),
        _ => Err(corrupt()),
    }
}

pub(super) fn encode_credentials(
    prefix: &[u8],
    generation: u64,
    credentials: &[CatalogCredential],
) -> Result<Vec<u8>, CatalogFailure> {
    let bytes = credentials
        .len()
        .checked_mul(90)
        .and_then(|size| {
            prefix
                .len()
                .checked_add(10)
                .and_then(|total| total.checked_add(size))
        })
        .ok_or_else(corrupt)?;
    let mut encoded = Vec::new();
    encoded.try_reserve_exact(bytes).map_err(|_| corrupt())?;
    encoded.extend_from_slice(prefix);
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

pub(super) fn is_governance(bytes: &[u8]) -> bool {
    bytes.starts_with(&MAGIC_V1)
        || bytes.starts_with(&MAGIC_V2)
        || bytes.starts_with(&MAGIC_V3)
        || bytes.starts_with(&MAGIC_V4)
        || bytes.starts_with(&MAGIC_V5)
        || bytes.starts_with(&MAGIC_V6)
        || bytes.starts_with(&MAGIC_V7)
        || bytes.starts_with(&MAGIC_V8)
}

pub(super) const fn lifecycle_code(lifecycle: TenantLifecycleState) -> u8 {
    match lifecycle {
        TenantLifecycleState::Active => 1,
        TenantLifecycleState::ReadOnly => 2,
        TenantLifecycleState::Suspended => 3,
        TenantLifecycleState::Purging => 4,
        TenantLifecycleState::Purged => 5,
    }
}

fn require_nonzero<const N: usize>(bytes: [u8; N]) -> Result<(), CatalogFailure> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(corrupt())
    } else {
        Ok(())
    }
}

pub(super) const fn corrupt() -> CatalogFailure {
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

    fn take_u16(&mut self) -> Result<u16, CatalogFailure> {
        self.take_array().map(u16::from_be_bytes)
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
        self.take_u16_bytes().map(|_| ())
    }

    fn take_u16_bytes(&mut self) -> Result<&'encoded [u8], CatalogFailure> {
        let length = usize::from(u16::from_be_bytes(self.take_array()?));
        if length == 0 {
            return Err(corrupt());
        }
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or_else(corrupt)?;
        self.remaining = remaining;
        Ok(value)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
