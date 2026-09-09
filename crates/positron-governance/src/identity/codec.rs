use positron_kernel::CatalogGovernanceObject;

use positron_domain::identity::Scope;

use super::{CredentialIdentity, Identity, IdentityFailure, IngestIdentity, QueryIdentity};

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
    let credentials = decoded
        .credentials()
        .iter()
        .map(|credential| {
            let scope = match credential.scope_code() {
                1 => Scope::Ingest,
                2 => Scope::Query,
                3 => Scope::TenantAdministration,
                4 => Scope::SystemAdministration,
                _ => return Err(IdentityFailure),
            };
            let (salt, hash) = credential.salted_hash();
            Ok(CredentialIdentity {
                principal: credential.principal(),
                scope,
                active: credential.is_active(),
                expires_at_unix_seconds: credential.expires_at_unix_seconds(),
                salt,
                hash,
            })
        })
        .collect::<Result<Vec<_>, IdentityFailure>>()?;
    Ok(Identity {
        instance: decoded.instance(),
        // Credential changes, rather than lifecycle or ordinary Catalog
        // changes, invalidate contexts and cursor authorization bindings.
        generation: decoded.credential_generation(),
        principal: decoded.principal(),
        tenant: decoded.tenant(),
        tenant_slug: decoded.tenant_slug(),
        external_alias: decoded.external_tenant_alias(),
        salt,
        hash,
        ingest,
        query,
        credentials,
        lifecycle: decoded.lifecycle(),
    })
}
