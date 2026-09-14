use positron_domain::{
    identity::{ExternalTenantAlias, TenantId},
    lifecycle::TenantLifecycleState,
};

use super::*;

pub(crate) fn is_tenant_record(bytes: &[u8]) -> bool {
    bytes.starts_with(&TENANT_RECORD_V1_MAGIC)
        || bytes.starts_with(&TENANT_RECORD_V2_MAGIC)
        || bytes.starts_with(&TENANT_RECORD_V3_MAGIC)
        || bytes.starts_with(&TENANT_RECORD_V4_MAGIC)
}

pub(super) fn record_layout(bytes: &[u8]) -> Result<RecordLayout, TenantAdministrationFailure> {
    let version_four = bytes.starts_with(&TENANT_RECORD_V4_MAGIC);
    let version_three = bytes.starts_with(&TENANT_RECORD_V3_MAGIC) || version_four;
    let version_two = bytes.starts_with(&TENANT_RECORD_V2_MAGIC) || version_three;
    if !is_tenant_record(bytes) {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let tenant = TenantId::from_bytes(array_at(bytes, 24)?)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let slug_start = 40;
    let slug_length = usize::from(byte_at(bytes, slug_start)?);
    let slug_end = slug_start
        .checked_add(1)
        .and_then(|start| start.checked_add(slug_length))
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let slug = std::str::from_utf8(
        bytes
            .get(slug_start + 1..slug_end)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    if slug.is_empty() {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let display_length = usize::from(byte_at(bytes, slug_end)?);
    let display_end = slug_end
        .checked_add(1)
        .and_then(|start| start.checked_add(display_length))
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let display = std::str::from_utf8(
        bytes
            .get(slug_end + 1..display_end)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    if display.is_empty() {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let retention_at = display_end;
    let retention_seconds = u64_at(bytes, retention_at)?;
    if retention_seconds == 0 {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let generation_at = retention_at
        .checked_add(8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let generation = ResourceGeneration::new(u64_at(bytes, generation_at)?)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let weight_at = generation_at
        .checked_add(8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let weight = u32_at(bytes, weight_at)?;
    if weight == 0 || weight > u32::from(u16::MAX) {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let resources_at = weight_at
        .checked_add(4)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let resources_end = resources_at
        .checked_add(RESOURCE_BYTES)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let mut resources = [0_u64; RESOURCE_COUNT];
    for (index, resource) in resources.iter_mut().enumerate() {
        let offset = resources_at
            .checked_add(
                index
                    .checked_mul(8)
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
            )
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        *resource = u64_at(bytes, offset)?;
    }
    if resources.contains(&0) {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let lifecycle_at = resources_end;
    let lifecycle = lifecycle_state(byte_at(bytes, lifecycle_at)?)?;
    let policy_at = lifecycle_at
        .checked_add(1)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    ResourceGeneration::new(u64_at(bytes, policy_at)?)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let after_policy = policy_at
        .checked_add(8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let (lifecycle_generation, lifecycle_generation_at, after_lifecycle) = if version_two {
        let at = after_policy;
        (
            ResourceGeneration::new(u64_at(bytes, at)?)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            Some(at),
            at.checked_add(8)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        )
    } else {
        (
            ResourceGeneration::new(1)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            None,
            after_policy,
        )
    };
    let (
        display_generation,
        display_generation_at,
        retention_generation,
        retention_generation_at,
        after_profile,
    ) = if version_three {
        let display_at = after_lifecycle;
        let retention_at = display_at
            .checked_add(8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let after_retention = retention_at
            .checked_add(8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        (
            ResourceGeneration::new(u64_at(bytes, display_at)?)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            Some(display_at),
            ResourceGeneration::new(u64_at(bytes, retention_at)?)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            Some(retention_at),
            after_retention,
        )
    } else {
        (
            ResourceGeneration::new(1)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            None,
            ResourceGeneration::new(1)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            None,
            after_lifecycle,
        )
    };
    let (alias_generation, external_alias, alias_at, envelope_length_at) = if version_four {
        let alias_generation = ResourceGeneration::new(u64_at(bytes, after_profile)?)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        let alias_length_at = after_profile
            .checked_add(8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let alias_length = usize::from(byte_at(bytes, alias_length_at)?);
        if alias_length == 0 {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        let alias_start = alias_length_at
            .checked_add(1)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let envelope_at = alias_start
            .checked_add(alias_length)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let alias = std::str::from_utf8(
            bytes
                .get(alias_start..envelope_at)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        (
            alias_generation,
            Some(
                ExternalTenantAlias::parse(alias)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            ),
            after_profile,
            envelope_at,
        )
    } else {
        (
            ResourceGeneration::new(1)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            None,
            after_profile,
            after_profile,
        )
    };
    let envelope_length = usize::from(u16_at(bytes, envelope_length_at)?);
    let envelope_start = envelope_length_at
        .checked_add(2)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let envelope_end = envelope_start
        .checked_add(envelope_length)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    if envelope_length == 0
        || bytes.get(envelope_start..envelope_end).is_none()
        || envelope_end != bytes.len()
    {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    Ok(RecordLayout {
        tenant,
        slug: slug.to_owned(),
        display_name: display.to_owned(),
        envelope: bytes
            .get(envelope_start..envelope_end)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .to_vec(),
        quota_start: generation_at,
        display_length_at: slug_end,
        display_end,
        retention_at,
        state: TenantQuotaState {
            generation,
            weight,
            resources,
        },
        lifecycle,
        lifecycle_generation,
        display_generation,
        retention_seconds,
        retention_generation,
        alias_generation,
        external_alias,
        lifecycle_at,
        lifecycle_generation_at,
        display_generation_at,
        retention_generation_at,
        alias_at,
        policy_at,
    })
}

pub(super) fn lifecycle_state(
    code: u8,
) -> Result<TenantLifecycleState, TenantAdministrationFailure> {
    match code {
        1 => Ok(TenantLifecycleState::Active),
        2 => Ok(TenantLifecycleState::ReadOnly),
        3 => Ok(TenantLifecycleState::Suspended),
        4 => Ok(TenantLifecycleState::Purging),
        5 => Ok(TenantLifecycleState::Purged),
        _ => Err(TenantAdministrationFailure::PersistenceUnavailable),
    }
}

pub(super) fn rewrite_quota(
    bytes: &[u8],
    record: RecordLayout,
    successor: TenantQuotaState,
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    if successor.weight == 0
        || successor.weight > u32::from(u16::MAX)
        || successor.resources.contains(&0)
    {
        return Err(TenantAdministrationFailure::InvalidInput);
    }
    let mut replacement = bytes.to_vec();
    replacement
        .get_mut(record.quota_start..record.quota_start + 8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .copy_from_slice(&successor.generation.get().to_be_bytes());
    replacement
        .get_mut(record.quota_start + 8..record.quota_start + 12)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .copy_from_slice(&successor.weight.to_be_bytes());
    for (index, resource) in successor.resources.into_iter().enumerate() {
        let start = record
            .quota_start
            .checked_add(12)
            .and_then(|start| start.checked_add(index.checked_mul(8)?))
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        replacement
            .get_mut(start..start + 8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .copy_from_slice(&resource.to_be_bytes());
    }
    Ok(replacement)
}

pub(super) fn rewrite_lifecycle(
    bytes: &[u8],
    record: RecordLayout,
    successor: TenantLifecycleRecord,
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    let lifecycle = lifecycle_code(successor.state)?;
    if let Some(generation_at) = record.lifecycle_generation_at {
        let mut replacement = bytes.to_vec();
        *replacement
            .get_mut(record.lifecycle_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)? = lifecycle;
        replacement
            .get_mut(generation_at..generation_at + 8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .copy_from_slice(&successor.generation.get().to_be_bytes());
        return Ok(replacement);
    }
    let mut replacement = Vec::new();
    replacement
        .try_reserve_exact(
            bytes
                .len()
                .checked_add(8)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    replacement.extend_from_slice(&TENANT_RECORD_V2_MAGIC);
    replacement.extend_from_slice(
        bytes
            .get(8..record.lifecycle_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    replacement.push(lifecycle);
    replacement.extend_from_slice(
        bytes
            .get(record.lifecycle_at + 1..record.policy_at + 8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    replacement.extend_from_slice(&successor.generation.get().to_be_bytes());
    replacement.extend_from_slice(
        bytes
            .get(record.policy_at + 8..)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    Ok(replacement)
}

pub(super) fn rewrite_profile(
    bytes: &[u8],
    record: RecordLayout,
    successor: &TenantProfileState,
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    if successor.display_name.is_empty()
        || successor.display_name.len() > 128
        || successor.retention_seconds == 0
    {
        return Err(TenantAdministrationFailure::InvalidInput);
    }
    let display_length = usize::from(
        *bytes
            .get(record.display_length_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    let profile_at = record
        .lifecycle_generation_at
        .map_or(record.policy_at + 8, |at| at + 8);
    let base_capacity = bytes
        .len()
        .checked_sub(display_length)
        .and_then(|size| size.checked_add(successor.display_name.len()))
        .and_then(|size| size.checked_add(usize::from(record.display_generation_at.is_none()) * 16))
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let mut replacement = Vec::new();
    replacement
        .try_reserve_exact(base_capacity)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    replacement.extend_from_slice(if record.external_alias.is_some() {
        &TENANT_RECORD_V4_MAGIC
    } else {
        &TENANT_RECORD_V3_MAGIC
    });
    replacement.extend_from_slice(
        bytes
            .get(8..record.display_length_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    replacement.push(
        u8::try_from(successor.display_name.len())
            .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
    );
    replacement.extend_from_slice(successor.display_name.as_bytes());
    replacement.extend_from_slice(
        bytes
            .get(record.display_end..profile_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    if record.lifecycle_generation_at.is_none() {
        replacement.extend_from_slice(&record.lifecycle_generation.get().to_be_bytes());
    }
    replacement.extend_from_slice(&successor.display_generation.get().to_be_bytes());
    replacement.extend_from_slice(&successor.retention_generation.get().to_be_bytes());
    let suffix_at = record
        .retention_generation_at
        .map_or(profile_at, |at| at + 8);
    replacement.extend_from_slice(
        bytes
            .get(suffix_at..)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    let display_delta = successor.display_name.len().abs_diff(display_length);
    let retention_at = if successor.display_name.len() >= display_length {
        record
            .retention_at
            .checked_add(display_delta)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
    } else {
        record
            .retention_at
            .checked_sub(display_delta)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
    };
    replacement
        .get_mut(retention_at..retention_at + 8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .copy_from_slice(&successor.retention_seconds.to_be_bytes());
    Ok(replacement)
}

pub(super) fn lifecycle_code(
    state: TenantLifecycleState,
) -> Result<u8, TenantAdministrationFailure> {
    match state {
        TenantLifecycleState::Active => Ok(1),
        TenantLifecycleState::ReadOnly => Ok(2),
        TenantLifecycleState::Suspended => Ok(3),
        TenantLifecycleState::Purging => Ok(4),
        TenantLifecycleState::Purged => Ok(5),
    }
}

pub(super) fn rewrite_alias(
    bytes: &[u8],
    record: RecordLayout,
    successor: TenantAliasRecord,
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    let alias = successor
        .alias
        .as_ref()
        .ok_or(TenantAdministrationFailure::InvalidInput)?;
    if record.external_alias.is_some() || successor.generation.get() != 2 {
        return Err(TenantAdministrationFailure::InvalidInput);
    }
    let alias_bytes = alias.as_str().as_bytes();
    let mut replacement = Vec::new();
    replacement
        .try_reserve_exact(
            bytes
                .len()
                .checked_add(9)
                .and_then(|size| size.checked_add(alias_bytes.len()))
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    replacement.extend_from_slice(&TENANT_RECORD_V4_MAGIC);
    replacement.extend_from_slice(
        bytes
            .get(8..record.alias_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    replacement.extend_from_slice(&successor.generation.get().to_be_bytes());
    replacement.push(
        u8::try_from(alias_bytes.len()).map_err(|_| TenantAdministrationFailure::InvalidInput)?,
    );
    replacement.extend_from_slice(alias_bytes);
    replacement.extend_from_slice(
        bytes
            .get(record.alias_at..)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    Ok(replacement)
}

#[cfg(test)]
pub(super) fn replace_record_quota(
    bytes: &[u8],
    tenant: TenantId,
    successor: TenantQuotaState,
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    let record = record_layout(bytes)?;
    if record.tenant != tenant {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    rewrite_quota(bytes, record, successor)
}

#[cfg(test)]
pub(super) fn quota_from_record(
    bytes: &[u8],
    tenant: TenantId,
) -> Result<TenantQuotaState, TenantAdministrationFailure> {
    let record = record_layout(bytes)?;
    if record.tenant != tenant {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    Ok(record.state)
}

#[cfg(test)]
pub(super) fn quota_start(bytes: &[u8]) -> Result<usize, TenantAdministrationFailure> {
    Ok(record_layout(bytes)?.quota_start)
}

#[cfg(test)]
pub(super) fn quota_end(bytes: &[u8]) -> Result<usize, TenantAdministrationFailure> {
    record_layout(bytes)?
        .quota_start
        .checked_add(8 + 4 + RESOURCE_BYTES)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)
}

pub(super) fn byte_at(bytes: &[u8], offset: usize) -> Result<u8, TenantAdministrationFailure> {
    bytes
        .get(offset)
        .copied()
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)
}

pub(super) fn array_at(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; 16], TenantAdministrationFailure> {
    bytes
        .get(offset..offset + 16)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .try_into()
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}

pub(super) fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, TenantAdministrationFailure> {
    bytes
        .get(offset..offset + 2)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}

pub(super) fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, TenantAdministrationFailure> {
    bytes
        .get(offset..offset + 4)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}

pub(super) fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, TenantAdministrationFailure> {
    bytes
        .get(offset..offset + 8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}
