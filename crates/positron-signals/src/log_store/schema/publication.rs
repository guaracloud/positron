use positron_domain::identity::TenantId;
use positron_kernel::{
    AuditIntent, Catalog, CatalogCommit, CatalogGenerationId, CatalogObject, CatalogProposal,
    FormatEpoch, TransactionId,
};

use super::codec::decode;
use super::{SchemaCatalog, SchemaFailure};

impl SchemaCatalog {
    /// Publishes one tenant schema replacement through the Storage Kernel Catalog Writer.
    pub fn commit_to_catalog(
        &self,
        catalog: &Catalog<'_>,
        expected: CatalogGenerationId,
        transaction: TransactionId,
        tenant: TenantId,
        audit: AuditIntent,
    ) -> Result<CatalogCommit, SchemaFailure> {
        let snapshot = catalog
            .pin()
            .map_err(|_| SchemaFailure::CatalogUnavailable)?;
        if snapshot.identity() != expected {
            return Err(SchemaFailure::CatalogUnavailable);
        }
        let mut objects = Vec::new();
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(|_| SchemaFailure::CatalogUnavailable)?
                .ok_or(SchemaFailure::CatalogUnavailable)?;
            if bytes.starts_with(b"PSCHEMA1") {
                let (object_tenant, _) = decode(bytes)?;
                if object_tenant == tenant {
                    continue;
                }
            }
            objects.push(
                CatalogObject::new(bytes.to_vec())
                    .map_err(|_| SchemaFailure::CatalogUnavailable)?,
            );
        }
        objects.push(self.catalog_object(tenant)?);
        let proposal = CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)
            .map_err(|_| SchemaFailure::CatalogUnavailable)?;
        catalog
            .commit(expected, proposal, Some(audit))
            .map_err(|_| SchemaFailure::CatalogUnavailable)
    }
}
