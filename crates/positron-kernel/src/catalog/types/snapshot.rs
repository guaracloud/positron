use std::collections::BTreeMap;
use std::fmt::{Formatter, Result as FormatResult};
use std::sync::Arc;

use super::{CatalogFailure, CatalogGenerationId, CatalogObjectId, FormatEpoch};

#[derive(Clone)]
pub struct CatalogSnapshot(pub(in crate::catalog) Arc<SnapshotData>);

pub(in crate::catalog) struct SnapshotData {
    pub(in crate::catalog) identity: CatalogGenerationId,
    pub(in crate::catalog) number: u64,
    pub(in crate::catalog) format_epoch: Option<FormatEpoch>,
    pub(in crate::catalog) objects: BTreeMap<CatalogObjectId, Arc<[u8]>>,
    pub(in crate::catalog) audit_frontier: AuditFrontier,
}

impl CatalogSnapshot {
    pub(in crate::catalog) fn origin() -> Self {
        Self(Arc::new(SnapshotData {
            identity: CatalogGenerationId::ORIGIN,
            number: 0,
            format_epoch: None,
            objects: BTreeMap::new(),
            audit_frontier: AuditFrontier::ORIGIN,
        }))
    }

    #[must_use]
    pub fn identity(&self) -> CatalogGenerationId {
        self.0.identity
    }
    #[must_use]
    pub fn number(&self) -> u64 {
        self.0.number
    }
    #[must_use]
    pub fn format_epoch(&self) -> Option<FormatEpoch> {
        self.0.format_epoch
    }
    pub fn object(&self, identity: CatalogObjectId) -> Result<Option<&[u8]>, CatalogFailure> {
        Ok(self.0.objects.get(&identity).map(AsRef::as_ref))
    }
    pub(crate) fn plaintext_objects(&self) -> impl Iterator<Item = &[u8]> {
        self.0.objects.values().map(AsRef::as_ref)
    }
    #[must_use]
    pub fn governance_audit_frontier(&self) -> u64 {
        self.0.audit_frontier.position
    }
}

impl std::fmt::Debug for CatalogSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        formatter
            .debug_struct("CatalogSnapshot")
            .field("identity", &self.0.identity)
            .field("number", &self.0.number)
            .field("format_epoch", &self.0.format_epoch)
            .field("object_count", &self.0.objects.len())
            .field("audit_frontier", &self.0.audit_frontier.position)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::catalog) struct AuditFrontier {
    pub(in crate::catalog) position: u64,
    pub(in crate::catalog) hash: [u8; 32],
}

impl AuditFrontier {
    pub(in crate::catalog) const ORIGIN: Self = Self {
        position: 0,
        hash: [0; 32],
    };
}
