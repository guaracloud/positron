use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::{FrameFailure, FrameFailureCode, MINIMUM_ENCODED_FRAME_BYTES};

/// The immutable identity of one encrypted persistent object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameObjectId(pub(super) [u8; 16]);

impl FrameObjectId {
    /// Creates a non-sentinel persistent object identity.
    pub fn new(bytes: [u8; 16]) -> Result<Self, FrameFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            Err(FrameFailure::new(FrameFailureCode::InvalidContext))
        } else {
            Ok(Self(bytes))
        }
    }
}

/// The immutable generation of key material protecting an object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyEpoch(pub(super) u64);

impl KeyEpoch {
    /// Creates an exact immutable key epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// The independently versioned persistent format generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FormatEpoch(pub(super) u32);

impl FormatEpoch {
    /// Creates a non-zero Format Epoch.
    pub const fn new(value: u32) -> Result<Self, FrameFailure> {
        if value == 0 {
            Err(FrameFailure::new(FrameFailureCode::InvalidContext))
        } else {
            Ok(Self(value))
        }
    }
}

/// The immutable sequence of one frame under its object data key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameSequence(pub(super) u64);

impl FrameSequence {
    /// Creates an exact frame sequence selected by the object's sequence owner.
    ///
    /// This constructor does not allocate or persist sequence values. The
    /// caller must never reuse a sequence under the same object data key.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// The segment payload purpose authenticated with one frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SegmentFramePurpose {
    /// A canonical Signal Store block.
    StoreBlock,
    /// A Signal Store index extent.
    Index,
    /// Signal Store statistics.
    Statistics,
    /// Segment metadata.
    SegmentMetadata,
    /// The acknowledged local durability bound of an active segment.
    DurabilityFrontier,
}

impl SegmentFramePurpose {
    const fn tag(self) -> u8 {
        match self {
            Self::StoreBlock => 1,
            Self::Index => 2,
            Self::Statistics => 3,
            Self::SegmentMetadata => 4,
            Self::DurabilityFrontier => 5,
        }
    }
}

/// The kernel-owned non-telemetry persistent object protected by one DEK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemObjectKind {
    /// An immutable Catalog Object.
    Catalog,
    /// An immutable manifest.
    Manifest,
    /// Governance Audit Store content.
    GovernanceAudit,
    /// Backup snapshot metadata.
    BackupMetadata,
}

impl SystemObjectKind {
    const fn class_tag(self) -> u8 {
        match self {
            Self::Catalog => 2,
            Self::Manifest => 3,
            Self::GovernanceAudit => 4,
            Self::BackupMetadata => 5,
        }
    }

    const fn purpose_tag(self) -> u8 {
        match self {
            Self::Catalog => 5,
            Self::Manifest => 6,
            Self::GovernanceAudit => 7,
            Self::BackupMetadata => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameScope {
    Tenant(TenantId),
    System,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameObjectClass {
    Segment {
        signal: SignalKind,
        shard: VirtualShardId,
    },
    System(SystemObjectKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FramePurpose {
    Segment(SegmentFramePurpose),
    System(SystemObjectKind),
}

impl FramePurpose {
    const fn tag(self) -> u8 {
        match self {
            Self::Segment(purpose) => purpose.tag(),
            Self::System(kind) => kind.purpose_tag(),
        }
    }
}

/// The authoritative identity and epoch binding for one encrypted object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameObjectContext {
    pub(super) scope: FrameScope,
    pub(super) class: FrameObjectClass,
    pub(super) object_id: FrameObjectId,
    pub(super) key_epoch: KeyEpoch,
    pub(super) format_epoch: FormatEpoch,
}

impl FrameObjectContext {
    /// Binds one segment object to an exact tenant, signal, and Virtual Shard.
    #[must_use]
    pub const fn tenant_segment(
        tenant: TenantId,
        signal: SignalKind,
        shard: VirtualShardId,
        object_id: FrameObjectId,
        key_epoch: KeyEpoch,
        format_epoch: FormatEpoch,
    ) -> Self {
        Self {
            scope: FrameScope::Tenant(tenant),
            class: FrameObjectClass::Segment { signal, shard },
            object_id,
            key_epoch,
            format_epoch,
        }
    }

    /// Binds one kernel-owned system object to its exact kind and epochs.
    #[must_use]
    pub const fn system(
        kind: SystemObjectKind,
        object_id: FrameObjectId,
        key_epoch: KeyEpoch,
        format_epoch: FormatEpoch,
    ) -> Self {
        Self {
            scope: FrameScope::System,
            class: FrameObjectClass::System(kind),
            object_id,
            key_epoch,
            format_epoch,
        }
    }

    /// Creates the authoritative context for one segment frame.
    pub(crate) const fn frame(
        self,
        purpose: SegmentFramePurpose,
        sequence: FrameSequence,
    ) -> Result<FrameContext, FrameFailure> {
        match self.class {
            FrameObjectClass::Segment { .. } => Ok(FrameContext {
                object: self,
                purpose: FramePurpose::Segment(purpose),
                sequence,
            }),
            FrameObjectClass::System(_) => Err(FrameFailure::new(FrameFailureCode::InvalidContext)),
        }
    }

    /// Creates the authoritative frame context for one system object extent.
    pub const fn system_frame(self, sequence: FrameSequence) -> Result<FrameContext, FrameFailure> {
        match self.class {
            FrameObjectClass::System(kind) => Ok(FrameContext {
                object: self,
                purpose: FramePurpose::System(kind),
                sequence,
            }),
            FrameObjectClass::Segment { .. } => {
                Err(FrameFailure::new(FrameFailureCode::InvalidContext))
            },
        }
    }

    pub(super) fn encode(self, purpose: FramePurpose, destination: &mut Vec<u8>) {
        match self.scope {
            FrameScope::Tenant(tenant) => {
                destination.push(1);
                destination.extend_from_slice(&tenant.to_bytes());
            },
            FrameScope::System => {
                destination.push(2);
                destination.extend_from_slice(&[0_u8; 16]);
            },
        }
        match self.class {
            FrameObjectClass::Segment { signal, shard } => {
                destination.push(1);
                destination.push(match signal {
                    SignalKind::Logs => 1,
                    SignalKind::Traces => 2,
                });
                destination.extend_from_slice(&shard.value().to_be_bytes());
            },
            FrameObjectClass::System(kind) => {
                destination.push(kind.class_tag());
                destination.push(0);
                destination.extend_from_slice(&0_u32.to_be_bytes());
            },
        }
        destination.extend_from_slice(&self.object_id.0);
        destination.extend_from_slice(&self.key_epoch.0.to_be_bytes());
        destination.extend_from_slice(&self.format_epoch.0.to_be_bytes());
        destination.push(purpose.tag());
    }
}

/// The complete authoritative context for one independently encrypted frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameContext {
    pub(super) object: FrameObjectContext,
    pub(super) purpose: FramePurpose,
    pub(super) sequence: FrameSequence,
}

/// A finite caller-owned encoded-frame policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameLimits {
    pub(super) max_encoded_bytes: u32,
}

impl FrameLimits {
    /// Creates a finite policy large enough to hold the fixed header and tag.
    pub const fn new(max_encoded_bytes: u32) -> Result<Self, FrameFailure> {
        if max_encoded_bytes < MINIMUM_ENCODED_FRAME_BYTES {
            Err(FrameFailure::new(FrameFailureCode::InvalidLimit))
        } else {
            Ok(Self { max_encoded_bytes })
        }
    }
}
