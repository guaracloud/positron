use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};

use crate::catalog::CatalogFailure;
use crate::data_protection::{SecretKeyBytes, SegmentEnvelopeRoute};

use super::MAX_STORE_BLOCK_BYTES;
use crate::ResourceReservation;

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

/// Opaque canonical Store Block bytes and their caller-owned stable identity.
pub struct PreparedStoreBlock {
    pub(super) identity: StoreBlockIdentity,
    pub(super) payload: Vec<u8>,
}

impl PreparedStoreBlock {
    pub fn new(identity: StoreBlockIdentity, bytes: Vec<u8>) -> Result<Self, LedgerFailure> {
        if bytes.is_empty() || bytes.len() > MAX_STORE_BLOCK_BYTES {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        Ok(Self {
            identity,
            payload: bytes,
        })
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

    pub(super) fn is_cancelled(&self) -> bool {
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
}

/// A verified immutable view bounded by the published Durability Frontier.
pub struct LedgerSnapshot<'kernel> {
    pub(super) _capacity: ResourceReservation<'kernel>,
    pub(super) frontier: CommitPosition,
    pub(super) blocks: Vec<CommittedBlock>,
}

impl LedgerSnapshot<'_> {
    #[must_use]
    pub const fn frontier(&self) -> CommitPosition {
        self.frontier
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

/// The stable class of an active-segment operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerFailureCode {
    InvalidInput,
    LimitExceeded,
    ResourceAdmissionRefused,
    StorageUnavailable,
    IntegrityCorruption,
    AuthenticationFailed,
    ConcurrentWriter,
    UnsupportedFormat,
    StorageExhausted,
    IdempotencyConflict,
    StaleGeneration,
    RecoveryRequired,
    Cancelled,
}

/// Whether the failed call is safe to retry in place or requires recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerCompletionState {
    RejectedBeforeMutation,
    RecoveryRequired,
    CommitAmbiguous,
}

/// A bounded secret-free active-segment failure.
#[derive(Debug)]
pub struct LedgerFailure {
    code: LedgerFailureCode,
    completion: LedgerCompletionState,
}

impl LedgerFailure {
    pub(super) const fn new(code: LedgerFailureCode) -> Self {
        Self {
            code,
            completion: LedgerCompletionState::RejectedBeforeMutation,
        }
    }

    pub(super) const fn post_mutation(code: LedgerFailureCode) -> Self {
        Self {
            code,
            completion: LedgerCompletionState::RecoveryRequired,
        }
    }

    pub(super) const fn ambiguous(code: LedgerFailureCode) -> Self {
        Self {
            code,
            completion: LedgerCompletionState::CommitAmbiguous,
        }
    }

    #[must_use]
    pub const fn code(&self) -> LedgerFailureCode {
        self.code
    }

    #[must_use]
    pub const fn completion_state(&self) -> LedgerCompletionState {
        self.completion
    }
}

impl Display for LedgerFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("active segment ledger operation failed")
    }
}

impl Error for LedgerFailure {}

impl From<CatalogFailure> for LedgerFailure {
    fn from(failure: CatalogFailure) -> Self {
        use crate::CatalogFailureCode as Code;
        let code = match failure.code() {
            Code::InvalidInput => LedgerFailureCode::InvalidInput,
            Code::IdempotencyConflict => LedgerFailureCode::IdempotencyConflict,
            Code::StaleGeneration => LedgerFailureCode::StaleGeneration,
            Code::LimitExceeded => LedgerFailureCode::LimitExceeded,
            Code::StorageUnavailable => LedgerFailureCode::StorageUnavailable,
            Code::IntegrityCorruption => LedgerFailureCode::IntegrityCorruption,
            Code::AuthenticationFailed => LedgerFailureCode::AuthenticationFailed,
            Code::ConcurrentWriter => LedgerFailureCode::ConcurrentWriter,
            Code::ResourceAdmissionRefused => LedgerFailureCode::ResourceAdmissionRefused,
            Code::UnsupportedFormat => LedgerFailureCode::UnsupportedFormat,
        };
        Self::new(code)
    }
}
