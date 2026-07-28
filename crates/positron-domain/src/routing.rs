//! Cluster-compatible shard and committed-position values.

use std::num::NonZeroU64;

use crate::outcome::{DomainFailure, FailureSource};

/// The tenant-owned identity of one virtual shard.
///
/// Zero is rejected as a sentinel. Ingest and Storage Kernel own the eventual
/// standalone shard count and routing function; this value creates no Release
/// 1 replication, leader, migration, or other cluster runtime.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VirtualShardId(u32);

impl VirtualShardId {
    /// Builds a non-zero opaque virtual-shard identity.
    pub fn new(value: u32) -> Result<Self, DomainFailure> {
        if value == 0 {
            return Err(DomainFailure::invalid_identifier(
                FailureSource::VirtualShard,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the opaque identity number without assigning routing semantics.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// The monotonically increasing version of one virtual-shard assignment.
///
/// This is an identity-only cluster-compatible boundary: it adds no Release 1
/// replication, leader, failover, or migration runtime. Every `u64` represents
/// an exact epoch, while checked progression never wraps to stale authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssignmentEpoch(u64);

impl AssignmentEpoch {
    /// Creates the distinguished epoch before the first reassignment.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Applies an owner-selected non-zero epoch advance without wrapping.
    pub fn advance_by(self, increment: NonZeroU64) -> Result<Self, DomainFailure> {
        let Some(value) = self.0.checked_add(increment.get()) else {
            return Err(DomainFailure::arithmetic_overflow(
                FailureSource::AssignmentEpoch,
            ));
        };
        Ok(Self(value))
    }

    /// Advances to the next epoch without integer wraparound.
    pub fn next(self) -> Result<Self, DomainFailure> {
        self.advance_by(NonZeroU64::MIN)
    }

    /// Returns the exact monotonically ordered epoch.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// A monotonically ordered committed-store-block position within one shard.
///
/// Commit Position is distinct from every timestamp. Storage Kernel owns its
/// durable assignment and serialization; this type only preserves a checked
/// native order that cannot wrap back to an earlier logical position.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommitPosition(u64);

impl CommitPosition {
    /// Creates the origin position before any store block has committed.
    #[must_use]
    pub const fn origin() -> Self {
        Self(0)
    }

    /// Applies a Storage Kernel-selected non-zero committed-block advance.
    pub fn advance_by(self, increment: NonZeroU64) -> Result<Self, DomainFailure> {
        let Some(value) = self.0.checked_add(increment.get()) else {
            return Err(DomainFailure::arithmetic_overflow(
                FailureSource::CommitPosition,
            ));
        };
        Ok(Self(value))
    }

    /// Advances one position without integer wraparound.
    pub fn next(self) -> Result<Self, DomainFailure> {
        self.advance_by(NonZeroU64::MIN)
    }

    /// Returns the exact opaque logical position.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// The supported Release 1 telemetry signal stores.
///
/// This closed native taxonomy deliberately excludes Metrics and Profiles. It
/// is not a protocol enum or persistence encoding, and creates no deferred
/// signal-store implementation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SignalKind {
    /// The Release 1 Log Signal Store.
    Logs,
    /// The Release 1 Trace Signal Store.
    Traces,
}

impl SignalKind {
    /// Returns the stable lowercase native signal name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Logs => "logs",
            Self::Traces => "traces",
        }
    }
}
