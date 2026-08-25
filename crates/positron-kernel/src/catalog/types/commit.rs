use super::{CatalogGenerationId, CatalogSnapshot, GovernanceAuditRecord};

#[derive(Clone, Debug)]
pub struct CatalogCommit {
    pub(crate) snapshot: CatalogSnapshot,
    pub(crate) audit: Option<GovernanceAuditRecord>,
}

/// The durable Catalog publications that authorize one completed root-key rotation.
#[derive(Clone, Debug)]
pub struct CatalogRotation {
    pub(crate) started: CatalogCommit,
    pub(crate) verified: CatalogCommit,
    pub(crate) completed: CatalogCommit,
}

impl CatalogRotation {
    #[must_use]
    pub fn started(&self) -> &CatalogCommit {
        &self.started
    }

    #[must_use]
    pub fn verified(&self) -> &CatalogCommit {
        &self.verified
    }

    #[must_use]
    pub fn completed(&self) -> &CatalogCommit {
        &self.completed
    }
}

impl CatalogCommit {
    #[must_use]
    pub fn identity(&self) -> CatalogGenerationId {
        self.snapshot.identity()
    }

    #[must_use]
    pub fn number(&self) -> u64 {
        self.snapshot.number()
    }

    #[must_use]
    pub fn snapshot(&self) -> &CatalogSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub fn governance_audit_record(&self) -> Option<&GovernanceAuditRecord> {
        self.audit.as_ref()
    }
}
