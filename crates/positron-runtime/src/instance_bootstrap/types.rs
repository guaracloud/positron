use std::error::Error;
use std::fmt::{Display, Formatter};
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use positron_domain::identity::{ExternalTenantAlias, PrincipalId, Scope, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_domain::routing::SignalKind;
use positron_kernel::{
    BootstrapKeyCustody, Catalog, CatalogFailureCode, CommittedLedgerReader,
    InstanceBootstrapStorage, InstanceId, MountQualification, OwnedPrimaryDataVolume,
    ResourceAmounts, RetentionImpactPreview, RetentionReclamationEstimate, RetentionTimeAuthority,
    StorageKernelResourceAuthority,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use positron_governance::{
    AdministrativeIdempotencyKey, ApiKeyAdministrationFailure, ApiKeyCreation, AuthorizedContext,
    CatalogFormatMigration, CatalogFormatMigrationAdministration, CatalogFormatMigrationFailure,
    DurableOperation, DurableOperationAdministration, DurableOperationFailure,
    DurableOperationRequest, DurableOperationStatus, ListenerTransportAdministration,
    ListenerTransportAdministrationFailure, ResourceGeneration, RetentionImpactConfirmation,
    TenantAliasAdministration, TenantAliasAdministrationFailure, TenantAliasBindRequest,
    TenantAliasBinding, TenantDisplayGenerationConflict, TenantDisplayNameUpdate,
    TenantDisplayNameUpdateRequest, TenantLifecycleAdministration,
    TenantLifecycleAdministrationFailure, TenantLifecycleTransition,
    TenantLifecycleTransitionRequest, TenantProfileAdministration,
    TenantProfileAdministrationFailure, TenantProfileAdministrationFailureCode,
    TenantRetentionAdministration, TenantRetentionAdministrationFailure, TenantRetentionUpdate,
    TenantRetentionUpdateRequest,
};
use positron_query::QueryCancellation;

/// A bounded, authorization-filtered Governance Audit history. When an audit
/// retention anchor is present, records before that signed position are no
/// longer claimed to be available by this response.
#[derive(Debug)]
pub struct GovernanceAuditHistory {
    records: Vec<positron_governance::GovernanceAuditEntry>,
    retention_anchor_position: Option<u64>,
}

impl GovernanceAuditHistory {
    #[must_use]
    pub fn records(&self) -> &[positron_governance::GovernanceAuditEntry] {
        &self.records
    }

    /// Returns the signed boundary preceding the retained suffix, if system
    /// policy has reclaimed an older audit prefix.
    #[must_use]
    pub const fn retention_anchor_position(&self) -> Option<u64> {
        self.retention_anchor_position
    }

    /// Returns the first position that this bounded response can contain.
    #[must_use]
    pub fn earliest_visible_position(&self) -> u64 {
        self.records
            .first()
            .map(positron_governance::GovernanceAuditEntry::position)
            .or_else(|| {
                self.retention_anchor_position
                    .and_then(|position| position.checked_add(1))
            })
            .unwrap_or(1)
    }
}

/// Read-only, generation-bound retention-reduction evidence for one tenant.
pub struct TenantRetentionImpactPreview {
    tenant: TenantId,
    retention_generation: ResourceGeneration,
    proposed_retention_seconds: NonZeroU64,
    catalog_identity: positron_kernel::CatalogGenerationId,
    catalog_generation: u64,
    evaluated_at: positron_domain::time::UnixNanoseconds,
    scopes: Vec<RetentionImpactPreview>,
}

/// The two values returned by a preview that must travel together to confirm
/// a retention reduction at its original trusted evaluation instant.
#[derive(Clone, Copy)]
pub(crate) struct TenantRetentionPreviewConfirmation {
    digest: [u8; 32],
    evaluation: positron_domain::time::UnixNanoseconds,
}

impl TenantRetentionPreviewConfirmation {
    #[must_use]
    pub(crate) const fn new(
        digest: [u8; 32],
        evaluation: positron_domain::time::UnixNanoseconds,
    ) -> Self {
        Self { digest, evaluation }
    }
}

impl TenantRetentionImpactPreview {
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn retention_generation(&self) -> ResourceGeneration {
        self.retention_generation
    }
    #[must_use]
    pub const fn proposed_retention_seconds(&self) -> NonZeroU64 {
        self.proposed_retention_seconds
    }
    #[must_use]
    pub const fn catalog_identity(&self) -> positron_kernel::CatalogGenerationId {
        self.catalog_identity
    }
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }
    #[must_use]
    pub const fn evaluated_at(&self) -> positron_domain::time::UnixNanoseconds {
        self.evaluated_at
    }
    #[must_use]
    pub fn scopes(&self) -> &[RetentionImpactPreview] {
        &self.scopes
    }
    #[must_use]
    pub fn confirmation_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"positron.tenant-retention-impact.v1");
        hash.update(self.tenant.to_bytes());
        hash.update(self.retention_generation.get().to_be_bytes());
        hash.update(self.proposed_retention_seconds.get().to_be_bytes());
        hash.update(self.catalog_identity.to_bytes());
        hash.update(self.catalog_generation.to_be_bytes());
        for scope in &self.scopes {
            hash.update(scope.scope().tenant_id().to_bytes());
            hash.update([match scope.scope().signal_kind() {
                SignalKind::Logs => 1,
                SignalKind::Traces => 2,
            }]);
            hash.update(scope.scope().shard_id().value().to_be_bytes());
            hash.update(scope.catalog_identity().to_bytes());
            hash.update(scope.catalog_generation().to_be_bytes());
            hash.update(scope.evaluated_at().value().to_be_bytes());
            hash.update(scope.approximate_affected_bytes().to_be_bytes());
            hash.update(
                scope
                    .approximate_immediately_reclaimable_bytes()
                    .to_be_bytes(),
            );
            hash.update(scope.deferred_active_segment_bytes().to_be_bytes());
            hash.update(scope.deferred_mixed_sealed_segment_bytes().to_be_bytes());
            match scope.affected_time_range() {
                Some(range) => {
                    hash.update([1]);
                    hash.update(range.earliest().value().to_be_bytes());
                    hash.update(range.latest().value().to_be_bytes());
                },
                None => hash.update([0]),
            }
            match scope.earliest_reclamation() {
                RetentionReclamationEstimate::None => hash.update([0]),
                RetentionReclamationEstimate::At(time) => {
                    hash.update([1]);
                    hash.update(time.value().to_be_bytes());
                },
                RetentionReclamationEstimate::BlockedByDurableLease(time) => {
                    hash.update([2]);
                    hash.update(time.value().to_be_bytes());
                },
                RetentionReclamationEstimate::BlockedByInProcessSnapshot => hash.update([3]),
            }
        }
        hash.finalize().into()
    }

    /// A retained confirmation remains usable across ordinary clock movement
    /// only while no scope can reclaim or affect more data than it did in the
    /// preview. Catalog and generation bindings are checked separately.
    fn current_impact_does_not_exceed(&self, preview: &Self) -> bool {
        self.scopes.len() == preview.scopes.len()
            && self
                .scopes
                .iter()
                .zip(&preview.scopes)
                .all(|(current, prior)| {
                    current.scope() == prior.scope()
                        && current.catalog_identity() == prior.catalog_identity()
                        && current.catalog_generation() == prior.catalog_generation()
                        && current.approximate_affected_bytes()
                            <= prior.approximate_affected_bytes()
                        && current.approximate_immediately_reclaimable_bytes()
                            <= prior.approximate_immediately_reclaimable_bytes()
                        && current.deferred_active_segment_bytes()
                            <= prior.deferred_active_segment_bytes()
                        && current.deferred_mixed_sealed_segment_bytes()
                            <= prior.deferred_mixed_sealed_segment_bytes()
                })
    }
}

mod administration_inspection;
mod administration_keys;
mod administration_lifecycle;
mod administration_retention;
mod administration_serving;
mod administration_tenants;
mod bootstrap_claim;
mod bootstrap_models;
mod failure_mappings;
use failure_mappings::*;
mod tenant_drain_gates;
mod tenant_drain_registry;

pub use bootstrap_claim::BootstrapClaim;
pub use bootstrap_models::{
    BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState, InitializationPlan,
    InitializedInstance,
};
pub(crate) use tenant_drain_gates::{IngestDrainPermit, QueryDrainPermit};
pub(in crate::instance_bootstrap) use tenant_drain_registry::TenantDrainRegistry;
