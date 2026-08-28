use std::fmt::Formatter;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;

use crate::data_protection::{SecretKeyBytes, SegmentEnvelopeRoute};

use crate::IngestTime;
use crate::ResourceReservation;

mod failure;
mod prepared;
mod protection_clone;
pub use failure::{LedgerCompletionState, LedgerFailure, LedgerFailureCode};
pub use prepared::PreparedStoreBlock;

/// The immutable tenant, Signal Store, and Virtual Shard boundary of one active segment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SegmentScope {
    pub(super) tenant: TenantId,
    pub(super) signal: SignalKind,
    pub(super) shard: VirtualShardId,
}

impl SegmentScope {
    #[must_use]
    pub const fn new(tenant: TenantId, signal: SignalKind, shard: VirtualShardId) -> Self {
        Self {
            tenant,
            signal,
            shard,
        }
    }

    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub const fn signal_kind(self) -> SignalKind {
        self.signal
    }

    #[must_use]
    pub const fn shard_id(self) -> VirtualShardId {
        self.shard
    }

    pub(super) fn lease_key(self) -> [u8; 22] {
        let mut key = [0_u8; 22];
        for (destination, source) in key.iter_mut().zip(self.tenant.to_bytes()) {
            *destination = source;
        }
        if let Some(signal) = key.get_mut(16) {
            *signal = match self.signal {
                SignalKind::Logs => 1,
                SignalKind::Traces => 2,
            };
        }
        for (destination, source) in key
            .iter_mut()
            .skip(17)
            .zip(self.shard.value().to_be_bytes())
        {
            *destination = source;
        }
        if let Some(lifecycle) = key.last_mut() {
            *lifecycle = 1;
        }
        key
    }
}

/// The immutable random identity of one physical segment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SegmentId(pub(super) [u8; 16]);

impl SegmentId {
    pub(super) fn new(bytes: [u8; 16]) -> Result<Self, LedgerFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Stable caller-supplied identity of one canonical Store Block append operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StoreBlockIdentity(pub(super) [u8; 16]);

impl StoreBlockIdentity {
    pub fn new(bytes: [u8; 16]) -> Result<Self, LedgerFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

pub(super) type SegmentKeyRoute = SegmentEnvelopeRoute;

/// A one-shot secret capability and its non-secret provider recovery route.
pub struct SegmentProtectionKey {
    pub(super) key: SecretKeyBytes,
    pub(super) route: SegmentKeyRoute,
}

impl SegmentProtectionKey {
    #[must_use]
    pub fn from_owned(bytes: Box<[u8; 32]>) -> Self {
        Self {
            key: SecretKeyBytes::from_owned(bytes),
            route: SegmentKeyRoute {
                provider_family: 1,
                provider_reference: [1; 16],
                provider_key_epoch: 1,
            },
        }
    }

    pub fn from_owned_with_route(
        bytes: Box<[u8; 32]>,
        provider_reference: [u8; 16],
        provider_key_epoch: u64,
    ) -> Result<Self, LedgerFailure> {
        if provider_reference.iter().all(|byte| *byte == 0) || provider_key_epoch == 0 {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        Ok(Self {
            key: SecretKeyBytes::from_owned(bytes),
            route: SegmentKeyRoute {
                provider_family: 1,
                provider_reference,
                provider_key_epoch,
            },
        })
    }
}

impl std::fmt::Debug for SegmentProtectionKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SegmentProtectionKey { <redacted> }")
    }
}

/// Cooperative cancellation observed only before durability work is admitted.
#[derive(Clone, Debug)]
pub struct AppendCancellation(Arc<AtomicBool>);

impl AppendCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl Default for AppendCancellation {
    fn default() -> Self {
        Self::new()
    }
}

/// Proof that the exact block and authenticated frontier completed local durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    pub(super) segment: SegmentId,
    pub(super) position: CommitPosition,
    pub(super) frontier_authenticator: [u8; 32],
}

impl CommitReceipt {
    #[must_use]
    pub const fn segment_id(&self) -> SegmentId {
        self.segment
    }

    #[must_use]
    pub const fn position(&self) -> CommitPosition {
        self.position
    }

    #[must_use]
    pub const fn frontier_authenticator(&self) -> [u8; 32] {
        self.frontier_authenticator
    }
}

/// One authenticated committed Store Block visible through a stable snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedBlock {
    pub(super) identity: StoreBlockIdentity,
    pub(super) position: CommitPosition,
    pub(super) payload: Vec<u8>,
    pub(super) content_digest: [u8; 32],
    pub(super) segment: SegmentId,
    pub(super) frontier_authenticator: [u8; 32],
}

impl CommittedBlock {
    #[must_use]
    pub const fn identity(&self) -> StoreBlockIdentity {
        self.identity
    }

    #[must_use]
    pub const fn position(&self) -> CommitPosition {
        self.position
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the stable digest computed while the payload was admitted.
    pub fn content_digest(&self) -> Result<[u8; 32], LedgerFailure> {
        Ok(self.content_digest)
    }
}

/// A verified immutable view bounded by the published Durability Frontier.
pub struct LedgerSnapshot<'kernel> {
    pub(super) _capacity: ResourceReservation<'kernel>,
    pub(super) scope: SegmentScope,
    pub(super) frontier: CommitPosition,
    pub(super) catalog_generation: u64,
    pub(super) catalog_identity: crate::CatalogGenerationId,
    pub(super) blocks: Vec<CommittedBlock>,
}

impl LedgerSnapshot<'_> {
    /// Returns the authenticated physical tenant, signal, and shard scope.
    #[must_use]
    pub const fn scope(&self) -> SegmentScope {
        self.scope
    }

    /// Reconstructs Ingest Time only inside an authenticated durable snapshot.
    #[must_use]
    pub const fn reconstruct_ingest_time(&self, instant: UnixNanoseconds) -> IngestTime {
        IngestTime::from_authenticated_durable(instant)
    }

    #[must_use]
    pub const fn frontier(&self) -> CommitPosition {
        self.frontier
    }

    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    #[must_use]
    pub const fn catalog_identity(&self) -> crate::CatalogGenerationId {
        self.catalog_identity
    }

    #[must_use]
    pub fn blocks(&self) -> &[CommittedBlock] {
        &self.blocks
    }
}

/// The immutable segment publication completed by an explicit seal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedSegment {
    pub(super) segment: SegmentId,
    pub(super) frontier: CommitPosition,
}

impl SealedSegment {
    #[must_use]
    pub const fn segment_id(self) -> SegmentId {
        self.segment
    }

    #[must_use]
    pub const fn frontier(self) -> CommitPosition {
        self.frontier
    }
}
