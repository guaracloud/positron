use positron_domain::identity::TenantId;
use positron_kernel::{CatalogFailureCode, CatalogSnapshot};
use positron_signals::{SchemaCatalog, SchemaFailure};

/// Typed failure at the ingest-owned Catalog representation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaCatalogLoadFailure {
    Catalog(CatalogFailureCode),
    Schema(SchemaFailure),
    DuplicateTenantObject,
}

impl SchemaCatalogLoadFailure {
    #[must_use]
    pub const fn catalog_code(self) -> Option<CatalogFailureCode> {
        match self {
            Self::Catalog(code) => Some(code),
            Self::Schema(_) | Self::DuplicateTenantObject => None,
        }
    }
}

/// Loads one tenant-bound immutable schema checkpoint without exposing Catalog authority.
pub fn load_schema_checkpoint(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<Option<Vec<u8>>, SchemaCatalogLoadFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(|failure| SchemaCatalogLoadFailure::Catalog(failure.code()))?
            .ok_or(SchemaCatalogLoadFailure::Catalog(
                CatalogFailureCode::IntegrityCorruption,
            ))?;
        let Some(schema) = SchemaCatalog::decode_catalog_object_if_recognized(bytes)
            .map_err(SchemaCatalogLoadFailure::Schema)?
        else {
            continue;
        };
        if schema.tenant() != tenant {
            continue;
        }
        if found.is_some() {
            return Err(SchemaCatalogLoadFailure::DuplicateTenantObject);
        }
        let mut checkpoint = Vec::new();
        checkpoint
            .try_reserve_exact(bytes.len())
            .map_err(|_| SchemaCatalogLoadFailure::Schema(SchemaFailure::AllocationUnavailable))?;
        checkpoint.extend_from_slice(bytes);
        found = Some(checkpoint);
    }
    Ok(found)
}

#[cfg(test)]
mod tests;
