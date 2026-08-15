use positron_domain::identity::TenantId;
use positron_kernel::{
    CatalogFailureCode, CatalogSnapshot, ResourceAmounts, ResourceDimension, ResourceGovernor,
    WorkClaim, WorkKind,
};
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
    governor: ResourceGovernor<'_>,
) -> Result<Option<Vec<u8>>, SchemaCatalogLoadFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(|failure| SchemaCatalogLoadFailure::Catalog(failure.code()))?
            .ok_or(SchemaCatalogLoadFailure::Catalog(
                CatalogFailureCode::IntegrityCorruption,
            ))?;
        if !bytes.starts_with(b"PSCHEMA1") {
            continue;
        }
        let memory_bound =
            SchemaCatalog::catalog_memory_bound(bytes).map_err(SchemaCatalogLoadFailure::Schema)?;
        let reservation_bytes =
            memory_bound
                .checked_add(bytes.len())
                .ok_or(SchemaCatalogLoadFailure::Schema(
                    SchemaFailure::LimitExceeded,
                ))?;
        let amounts = ResourceAmounts::only(
            ResourceDimension::MemoryBytes,
            u64::try_from(reservation_bytes)
                .map_err(|_| SchemaCatalogLoadFailure::Schema(SchemaFailure::LimitExceeded))?,
        )
        .map_err(|_| SchemaCatalogLoadFailure::Schema(SchemaFailure::LimitExceeded))?;
        let claim = WorkClaim::tenant(tenant, WorkKind::Ingest, amounts)
            .map_err(|_| SchemaCatalogLoadFailure::Schema(SchemaFailure::AllocationUnavailable))?;
        let mut capacity = governor
            .reserve(claim)
            .map_err(|_| SchemaCatalogLoadFailure::Schema(SchemaFailure::AllocationUnavailable))?;
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
        let actual_bytes = schema.memory_bytes().checked_add(bytes.len()).ok_or(
            SchemaCatalogLoadFailure::Schema(SchemaFailure::LimitExceeded),
        )?;
        capacity
            .try_resize(
                ResourceAmounts::only(
                    ResourceDimension::MemoryBytes,
                    u64::try_from(actual_bytes).map_err(|_| {
                        SchemaCatalogLoadFailure::Schema(SchemaFailure::LimitExceeded)
                    })?,
                )
                .map_err(|_| SchemaCatalogLoadFailure::Schema(SchemaFailure::LimitExceeded))?,
            )
            .map_err(|_| SchemaCatalogLoadFailure::Schema(SchemaFailure::AllocationUnavailable))?;
        found = Some(checkpoint);
    }
    Ok(found)
}

#[cfg(test)]
mod tests;
