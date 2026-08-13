use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};

use super::{Identity, IdentityFailure};

pub(super) const GOVERNANCE_OBJECT_MAGIC: [u8; 8] = *b"POSGOV01";

pub(crate) fn decode_initial_identity(encoded: &[u8]) -> Result<Identity, IdentityFailure> {
    let mut cursor = Cursor::new(encoded);
    if cursor.take_array::<8>()? != GOVERNANCE_OBJECT_MAGIC {
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
    require_nonzero(cursor.take_array::<32>()?)?;
    require_nonzero(cursor.take_array::<32>()?)?;
    cursor.skip_u16_bytes()?;
    cursor.skip_u16_bytes()?;
    if cursor.take_u64()? == 0 || cursor.take_u64()? == 0 || cursor.take_u32()? == 0 {
        return Err(IdentityFailure);
    }
    for _ in 0..11 {
        if cursor.take_u64()? == 0 {
            return Err(IdentityFailure);
        }
    }
    if cursor.take_array::<5>()? != [1, 4, 0, 1, 1] || !cursor.is_empty() {
        return Err(IdentityFailure);
    }
    Ok(Identity {
        instance,
        principal,
        tenant,
        tenant_slug,
        salt,
        hash,
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
