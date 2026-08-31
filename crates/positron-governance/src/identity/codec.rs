use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;

use super::{Identity, IdentityFailure};

pub(super) const GOVERNANCE_OBJECT_MAGIC_V1: [u8; 8] = *b"POSGOV01";
pub(super) const GOVERNANCE_OBJECT_MAGIC_V2: [u8; 8] = *b"POSGOV02";
pub(super) const GOVERNANCE_OBJECT_MAGIC_V3: [u8; 8] = *b"POSGOV03";

pub(crate) fn decode_initial_identity(encoded: &[u8]) -> Result<Identity, IdentityFailure> {
    let mut cursor = Cursor::new(encoded);
    let magic = cursor.take_array::<8>()?;
    if magic != GOVERNANCE_OBJECT_MAGIC_V1
        && magic != GOVERNANCE_OBJECT_MAGIC_V2
        && magic != GOVERNANCE_OBJECT_MAGIC_V3
    {
        return Err(IdentityFailure);
    }
    let instance = cursor.take_array::<16>()?;
    require_nonzero(instance)?;
    let tenant = TenantId::from_bytes(cursor.take_array::<16>()?).map_err(|_| IdentityFailure)?;
    let slug = cursor.take_text_u8(63)?;
    let tenant_slug = TenantSlug::parse_canonical(slug).map_err(|_| IdentityFailure)?;
    let display_name = cursor.take_text_u8(128)?;
    if display_name.is_empty() {
        return Err(IdentityFailure);
    }
    let principal =
        PrincipalId::from_bytes(cursor.take_array::<16>()?).map_err(|_| IdentityFailure)?;
    let salt = cursor.take_array::<32>()?;
    let hash = cursor.take_array::<32>()?;
    require_nonzero(salt)?;
    require_nonzero(hash)?;
    let ingest = if magic == GOVERNANCE_OBJECT_MAGIC_V2 || magic == GOVERNANCE_OBJECT_MAGIC_V3 {
        let ingest_principal =
            PrincipalId::from_bytes(cursor.take_array::<16>()?).map_err(|_| IdentityFailure)?;
        if ingest_principal == principal {
            return Err(IdentityFailure);
        }
        let salt = cursor.take_array::<32>()?;
        let hash = cursor.take_array::<32>()?;
        require_nonzero(salt)?;
        require_nonzero(hash)?;
        Some(super::IngestIdentity {
            principal: ingest_principal,
            salt,
            hash,
        })
    } else {
        None
    };
    let query = if magic == GOVERNANCE_OBJECT_MAGIC_V3 {
        let query_principal =
            PrincipalId::from_bytes(cursor.take_array::<16>()?).map_err(|_| IdentityFailure)?;
        if query_principal == principal
            || ingest
                .as_ref()
                .is_some_and(|ingest| ingest.principal == query_principal)
        {
            return Err(IdentityFailure);
        }
        let salt = cursor.take_array::<32>()?;
        let hash = cursor.take_array::<32>()?;
        require_nonzero(salt)?;
        require_nonzero(hash)?;
        Some(super::QueryIdentity {
            principal: query_principal,
            salt,
            hash,
        })
    } else {
        None
    };
    require_nonzero(cursor.take_array::<32>()?)?;
    require_nonzero(cursor.take_array::<32>()?)?;
    cursor.skip_u16_bytes()?;
    cursor.skip_u16_bytes()?;
    let retention_seconds = cursor.take_u64()?;
    if retention_seconds == 0 || cursor.take_u64()? == 0 || cursor.take_u32()? == 0 {
        return Err(IdentityFailure);
    }
    for _ in 0..11 {
        if cursor.take_u64()? == 0 {
            return Err(IdentityFailure);
        }
    }
    let lifecycle = match cursor.take_array::<5>()? {
        [1, 4, 0, 1, 1] => TenantLifecycleState::Active,
        [2, 4, 0, 1, 1] => TenantLifecycleState::ReadOnly,
        [3, 4, 0, 1, 1] => TenantLifecycleState::Suspended,
        [4, 4, 0, 1, 1] => TenantLifecycleState::Purging,
        [5, 4, 0, 1, 1] => TenantLifecycleState::Purged,
        _ => return Err(IdentityFailure),
    };
    if !cursor.is_empty() {
        return Err(IdentityFailure);
    }
    Ok(Identity {
        instance,
        generation: 0,
        principal,
        tenant,
        tenant_slug,
        salt,
        hash,
        ingest,
        query,
        lifecycle,
        retention_seconds,
    })
}

fn require_nonzero<const N: usize>(bytes: [u8; N]) -> Result<(), IdentityFailure> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(IdentityFailure)
    } else {
        Ok(())
    }
}

struct Cursor<'encoded> {
    remaining: &'encoded [u8],
}

impl<'encoded> Cursor<'encoded> {
    const fn new(encoded: &'encoded [u8]) -> Self {
        Self { remaining: encoded }
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], IdentityFailure> {
        let (value, remaining) = self.remaining.split_at_checked(N).ok_or(IdentityFailure)?;
        self.remaining = remaining;
        value.try_into().map_err(|_| IdentityFailure)
    }

    fn take_u32(&mut self) -> Result<u32, IdentityFailure> {
        self.take_array().map(u32::from_be_bytes)
    }

    fn take_u64(&mut self) -> Result<u64, IdentityFailure> {
        self.take_array().map(u64::from_be_bytes)
    }

    fn take_text_u8(&mut self, maximum: usize) -> Result<&'encoded str, IdentityFailure> {
        let length = usize::from(self.take_array::<1>()?[0]);
        if length > maximum {
            return Err(IdentityFailure);
        }
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(IdentityFailure)?;
        self.remaining = remaining;
        std::str::from_utf8(value).map_err(|_| IdentityFailure)
    }

    fn skip_u16_bytes(&mut self) -> Result<(), IdentityFailure> {
        let length = usize::from(u16::from_be_bytes(self.take_array()?));
        if length == 0 {
            return Err(IdentityFailure);
        }
        let (_, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(IdentityFailure)?;
        self.remaining = remaining;
        Ok(())
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
