use positron_kernel::CatalogGovernanceObject;

use super::{Identity, IdentityFailure, IngestIdentity, QueryIdentity};

#[cfg(any(test, fuzzing))]
pub(crate) fn decode_initial_identity(encoded: &[u8]) -> Result<Identity, IdentityFailure> {
    let decoded = CatalogGovernanceObject::decode(encoded).map_err(|_| IdentityFailure)?;
    identity_from_catalog(decoded)
}

pub(super) fn identity_from_catalog(
    decoded: CatalogGovernanceObject,
) -> Result<Identity, IdentityFailure> {
    let (salt, hash) = decoded.principal_secret();
    let ingest = decoded
        .ingest_credential()
        .map(|(principal, salt, hash)| IngestIdentity {
            principal,
            salt,
            hash,
        });
    let query = decoded
        .query_credential()
        .map(|(principal, salt, hash)| QueryIdentity {
            principal,
            salt,
            hash,
        });
    Ok(Identity {
        instance: decoded.instance(),
        generation: 0,
        principal: decoded.principal(),
        tenant: decoded.tenant(),
        tenant_slug: decoded.tenant_slug(),
        salt,
        hash,
        ingest,
        query,
        lifecycle: decoded.lifecycle(),
    })
}
