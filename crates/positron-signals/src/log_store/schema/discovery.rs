use positron_domain::identity::TenantId;

use super::catalog::SchemaCatalog;
use super::failure::SchemaFailure;
use super::model::{MAX_DISCOVERY_NODES, SchemaEntry, SchemaPath};
use positron_domain::value::AttributeValueKind;

mod digest;
use digest::{catalog_digest, path_digest};

/// Bounded limits for one immutable schema-discovery read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaDiscoveryRequest {
    path_offset: usize,
    top_paths: usize,
    sampled_paths: usize,
}

impl SchemaDiscoveryRequest {
    /// Creates a request whose two result collections are independently bounded.
    pub fn new(top_paths: usize, sampled_paths: usize) -> Result<Self, SchemaFailure> {
        if top_paths > MAX_DISCOVERY_NODES || sampled_paths > MAX_DISCOVERY_NODES {
            return Err(SchemaFailure::LimitExceeded);
        }
        Ok(Self {
            path_offset: 0,
            top_paths,
            sampled_paths,
        })
    }

    pub fn page(
        path_offset: usize,
        page_size: usize,
        sampled_paths: usize,
    ) -> Result<Self, SchemaFailure> {
        if path_offset > MAX_DISCOVERY_NODES
            || page_size > MAX_DISCOVERY_NODES
            || sampled_paths > MAX_DISCOVERY_NODES
            || path_offset
                .checked_add(page_size)
                .is_none_or(|end| end > MAX_DISCOVERY_NODES)
        {
            return Err(SchemaFailure::LimitExceeded);
        }
        Ok(Self {
            path_offset,
            top_paths: page_size,
            sampled_paths,
        })
    }

    #[must_use]
    pub const fn path_offset(self) -> usize {
        self.path_offset
    }

    #[must_use]
    pub const fn top_paths(self) -> usize {
        self.top_paths
    }

    #[must_use]
    pub const fn sampled_paths(self) -> usize {
        self.sampled_paths
    }
}

/// A used-versus-bounded budget view exposed by schema discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaBudgetPressure {
    used: usize,
    limit: usize,
}

impl SchemaBudgetPressure {
    pub(crate) const fn new(used: usize, limit: usize) -> Self {
        Self { used, limit }
    }

    #[must_use]
    pub const fn used(self) -> usize {
        self.used
    }

    #[must_use]
    pub const fn limit(self) -> usize {
        self.limit
    }

    #[must_use]
    pub const fn exhausted(self) -> bool {
        self.used >= self.limit
    }
}

/// The reason a path is or is not represented by a scalar physical index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaPromotionReason {
    /// Repeated committed observations justify dictionary allocation.
    FrequentObservation,
    /// Governed query-use evidence justifies physical pruning state.
    QueryUse,
    /// A scalar path has not accumulated enough bounded evidence.
    InsufficientEvidence,
    /// The path has no scalar value variant to index.
    NoScalarVariant,
}

/// The immutable promotion decision for one discovered path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaPromotionDecision {
    /// The path has an allocated scalar index of the reported size.
    Promoted {
        index_bytes: usize,
        reason: SchemaPromotionReason,
    },
    /// The path remains generic because it has no scalar value variant.
    NotPromoted { reason: SchemaPromotionReason },
}

/// Bounded immutable details for one discovered path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaPathSummary {
    path: SchemaPath,
    variants: Vec<AttributeValueKind>,
    observations: u64,
    conflicts: u64,
    query_uses: u64,
    promotion: SchemaPromotionDecision,
    index_bytes: usize,
}

impl SchemaPathSummary {
    #[must_use]
    pub const fn path(&self) -> &SchemaPath {
        &self.path
    }

    #[must_use]
    pub fn variants(&self) -> &[AttributeValueKind] {
        &self.variants
    }

    #[must_use]
    pub const fn observations(&self) -> u64 {
        self.observations
    }

    #[must_use]
    pub const fn conflicts(&self) -> u64 {
        self.conflicts
    }

    #[must_use]
    pub const fn query_uses(&self) -> u64 {
        self.query_uses
    }

    #[must_use]
    pub const fn promotion(&self) -> SchemaPromotionDecision {
        self.promotion
    }

    #[must_use]
    pub const fn index_bytes(&self) -> usize {
        self.index_bytes
    }

    fn from_entry(entry: &SchemaEntry) -> Result<Self, SchemaFailure> {
        let mut variants = Vec::new();
        variants
            .try_reserve_exact(entry.variants().len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        variants.extend_from_slice(entry.variants());
        let promotion = if entry.promoted() {
            SchemaPromotionDecision::Promoted {
                index_bytes: entry.index_bytes(),
                reason: if entry.query_uses() > 0 {
                    SchemaPromotionReason::QueryUse
                } else {
                    SchemaPromotionReason::FrequentObservation
                },
            }
        } else {
            SchemaPromotionDecision::NotPromoted {
                reason: if entry.variants().iter().any(|kind| {
                    !matches!(
                        kind,
                        AttributeValueKind::Array | AttributeValueKind::KeyValueList
                    )
                }) {
                    SchemaPromotionReason::InsufficientEvidence
                } else {
                    SchemaPromotionReason::NoScalarVariant
                },
            }
        };
        Ok(Self {
            path: entry.path().try_clone()?,
            variants,
            observations: entry.observations(),
            conflicts: entry.conflicts(),
            query_uses: entry.query_uses(),
            promotion,
            index_bytes: entry.index_bytes(),
        })
    }
}

/// A stable digest of a namespace-qualified schema path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SchemaPathDigest([u8; 32]);

impl SchemaPathDigest {
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Immutable, bounded schema discovery output suitable for tenant inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaDiscovery {
    tenant: TenantId,
    catalog_memory: SchemaBudgetPressure,
    catalog_persistent: SchemaBudgetPressure,
    index: SchemaBudgetPressure,
    top_paths: Vec<SchemaPathSummary>,
    sampled_path_digests: Vec<SchemaPathDigest>,
    snapshot_digest: [u8; 32],
    path_offset: usize,
    total_paths: usize,
    overflow_records: u64,
    overflow_bytes: u64,
}

impl SchemaDiscovery {
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub const fn catalog_memory(&self) -> SchemaBudgetPressure {
        self.catalog_memory
    }

    #[must_use]
    pub const fn catalog_persistent(&self) -> SchemaBudgetPressure {
        self.catalog_persistent
    }

    #[must_use]
    pub const fn index(&self) -> SchemaBudgetPressure {
        self.index
    }

    #[must_use]
    pub fn top_paths(&self) -> &[SchemaPathSummary] {
        &self.top_paths
    }

    #[must_use]
    pub fn sampled_path_digests(&self) -> &[SchemaPathDigest] {
        &self.sampled_path_digests
    }

    #[must_use]
    pub const fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }

    #[must_use]
    pub const fn path_offset(&self) -> usize {
        self.path_offset
    }

    #[must_use]
    pub const fn total_paths(&self) -> usize {
        self.total_paths
    }

    #[must_use]
    pub const fn overflow_records(&self) -> u64 {
        self.overflow_records
    }

    #[must_use]
    pub const fn overflow_bytes(&self) -> u64 {
        self.overflow_bytes
    }
}

impl SchemaCatalog {
    /// Returns a deterministic, immutable, bounded view of schema discovery.
    pub fn discover(
        &self,
        request: SchemaDiscoveryRequest,
    ) -> Result<SchemaDiscovery, SchemaFailure> {
        let mut ranked = Vec::new();
        ranked
            .try_reserve_exact(self.entries.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        ranked.extend(self.entries.iter());
        ranked.sort_unstable_by(|left, right| {
            right
                .observations()
                .cmp(&left.observations())
                .then_with(|| left.path().cmp(right.path()))
        });

        let top_count = request
            .top_paths
            .min(ranked.len().saturating_sub(request.path_offset));
        let mut top_paths = Vec::new();
        top_paths
            .try_reserve_exact(top_count)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for entry in ranked.iter().skip(request.path_offset).take(top_count) {
            top_paths.push(SchemaPathSummary::from_entry(entry)?);
        }

        let sample_count = request.sampled_paths.min(self.entries.len());
        let mut sampled_path_digests = Vec::new();
        sampled_path_digests
            .try_reserve_exact(sample_count)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for entry in self.entries.iter().take(sample_count) {
            sampled_path_digests.push(path_digest(entry.path())?);
        }

        Ok(SchemaDiscovery {
            tenant: self.tenant,
            catalog_memory: SchemaBudgetPressure::new(
                self.memory_bytes,
                self.budget.max_memory_bytes(),
            ),
            catalog_persistent: SchemaBudgetPressure::new(
                self.persistent_bytes,
                self.budget.max_persistent_bytes(),
            ),
            index: SchemaBudgetPressure::new(self.index_bytes, self.budget.max_index_bytes()),
            top_paths,
            sampled_path_digests,
            snapshot_digest: catalog_digest(self)?,
            path_offset: request.path_offset,
            total_paths: self.entries.len(),
            overflow_records: self.overflow_records,
            overflow_bytes: self.overflow_bytes,
        })
    }
}
