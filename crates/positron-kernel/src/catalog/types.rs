use std::fmt::Formatter;
use std::sync::Arc;

use crate::data_protection::{DataProtection, SecretKeyBytes};
#[cfg(feature = "test-support")]
use positron_domain::lifecycle::TenantLifecycleState;

mod commit;
mod failure;
mod snapshot;

pub use commit::{CatalogCommit, CatalogRotation};
pub use failure::{CatalogFailure, CatalogFailureCode};
pub use snapshot::CatalogSnapshot;
pub(super) use snapshot::{AuditFrontier, SnapshotData};

pub(super) const MAX_CATALOG_OBJECTS: usize = 1_024;
pub(super) const MAX_CATALOG_OBJECT_BYTES: usize = 1_048_576;
pub(super) const MAX_CATALOG_TOTAL_BYTES: usize = 16_777_216;
pub(super) const MAX_AUDIT_INTENT_BYTES: usize = 65_536;

macro_rules! nonzero_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub(super) [u8; 16]);

        impl $name {
            pub fn new(bytes: [u8; 16]) -> Result<Self, CatalogFailure> {
                if bytes.iter().all(|byte| *byte == 0) {
                    Err(CatalogFailure::new(CatalogFailureCode::InvalidInput))
                } else {
                    Ok(Self(bytes))
                }
            }

            #[must_use]
            pub const fn to_bytes(self) -> [u8; 16] {
                self.0
            }
        }
    };
}

nonzero_id!(InstanceId);
nonzero_id!(TransactionId);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CatalogObjectId(pub(super) [u8; 32]);

impl CatalogObjectId {
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CatalogGenerationId(pub(super) [u8; 32]);

impl CatalogGenerationId {
    pub(super) const ORIGIN: Self = Self([0_u8; 32]);

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) const fn from_authenticated_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatEpoch(pub(super) u32);

impl FormatEpoch {
    pub const CATALOG_V1: Self = Self(1);

    pub const fn new(value: u32) -> Result<Self, CatalogFailure> {
        if value == 0 {
            Err(CatalogFailure::new(CatalogFailureCode::InvalidInput))
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    pub(super) const fn is_catalog_readable(self) -> bool {
        self.0 == Self::CATALOG_V1.0
    }

    pub(super) const fn is_catalog_writable(self) -> bool {
        self.is_catalog_readable()
    }
}

pub struct CatalogWrappingKey {
    pub(crate) key: SecretKeyBytes,
    pub(super) provider_key_reference: [u8; 16],
    pub(crate) key_epoch: u64,
}

impl CatalogWrappingKey {
    pub fn from_owned_at_epoch(
        bytes: Box<[u8; 32]>,
        provider_key_reference: [u8; 16],
        key_epoch: u64,
    ) -> Result<Self, CatalogFailure> {
        if provider_key_reference.iter().all(|byte| *byte == 0) || key_epoch == 0 {
            return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
        }
        Ok(Self {
            key: SecretKeyBytes::from_owned(bytes),
            provider_key_reference,
            key_epoch,
        })
    }

    pub(super) fn same_route(&self, other: &Self) -> bool {
        self.provider_key_reference == other.provider_key_reference
            && self.key_epoch == other.key_epoch
    }
}

impl std::fmt::Debug for CatalogWrappingKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CatalogWrappingKey { <redacted> }")
    }
}

pub struct CatalogSecret {
    pub(crate) marker_key: SecretKeyBytes,
    pub(crate) wrapping: CatalogWrappingKey,
    pub(super) predecessor: Option<CatalogWrappingKey>,
}

impl CatalogSecret {
    #[must_use]
    pub fn from_owned(marker_authentication: Box<[u8; 32]>, wrapping_key: Box<[u8; 32]>) -> Self {
        Self {
            marker_key: SecretKeyBytes::from_owned(marker_authentication),
            wrapping: CatalogWrappingKey {
                key: SecretKeyBytes::from_owned(wrapping_key),
                provider_key_reference: [1; 16],
                key_epoch: 1,
            },
            predecessor: None,
        }
    }

    pub fn from_owned_at_epoch(
        marker_authentication: Box<[u8; 32]>,
        wrapping_key: Box<[u8; 32]>,
        provider_key_reference: [u8; 16],
        key_epoch: u64,
    ) -> Result<Self, CatalogFailure> {
        Ok(Self {
            marker_key: SecretKeyBytes::from_owned(marker_authentication),
            wrapping: CatalogWrappingKey::from_owned_at_epoch(
                wrapping_key,
                provider_key_reference,
                key_epoch,
            )?,
            predecessor: None,
        })
    }

    pub fn with_predecessor(
        mut self,
        predecessor: CatalogWrappingKey,
    ) -> Result<Self, CatalogFailure> {
        if predecessor.key_epoch >= self.wrapping.key_epoch
            || predecessor.same_route(&self.wrapping)
        {
            return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
        }
        self.predecessor = Some(predecessor);
        Ok(self)
    }
}

impl std::fmt::Debug for CatalogSecret {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CatalogSecret { <redacted> }")
    }
}

pub struct CatalogObject {
    pub(super) identity: CatalogObjectId,
    pub(super) plaintext: Vec<u8>,
}

impl CatalogObject {
    pub fn new(plaintext: Vec<u8>) -> Result<Self, CatalogFailure> {
        if plaintext.is_empty() || plaintext.len() > MAX_CATALOG_OBJECT_BYTES {
            return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
        }
        let identity = CatalogObjectId(
            DataProtection::hash(&plaintext)
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?,
        );
        Ok(Self {
            identity,
            plaintext,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> CatalogObjectId {
        self.identity
    }
}

impl std::fmt::Debug for CatalogObject {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CatalogObject")
            .field("identity", &self.identity)
            .field("plaintext_bytes", &self.plaintext.len())
            .finish()
    }
}

/// Opaque governance object capability used only by integration-test fixtures.
#[cfg(feature = "test-support")]
#[derive(Clone)]
pub struct GovernanceFixtureObject {
    pub(super) plaintext: Vec<u8>,
}

#[cfg(feature = "test-support")]
impl GovernanceFixtureObject {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CatalogFailure> {
        if bytes.is_empty() || bytes.len() > MAX_CATALOG_OBJECT_BYTES {
            return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
        }
        let mut plaintext = Vec::new();
        plaintext
            .try_reserve_exact(bytes.len())
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        plaintext.extend_from_slice(bytes);
        Ok(Self { plaintext })
    }

    /// Returns the same opaque fixture with its typed tenant lifecycle changed.
    #[doc(hidden)]
    pub fn with_lifecycle(&self, lifecycle: TenantLifecycleState) -> Result<Self, CatalogFailure> {
        let mut plaintext = self.plaintext.clone();
        let start = plaintext
            .len()
            .checked_sub(5)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        let suffix = plaintext
            .get_mut(start..)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        suffix.copy_from_slice(match lifecycle {
            TenantLifecycleState::Active => &[1, 4, 0, 1, 1],
            TenantLifecycleState::ReadOnly => &[2, 4, 0, 1, 1],
            TenantLifecycleState::Suspended => &[3, 4, 0, 1, 1],
            TenantLifecycleState::Purging => &[4, 4, 0, 1, 1],
            TenantLifecycleState::Purged => &[5, 4, 0, 1, 1],
        });
        Self::from_bytes(&plaintext)
    }
}

#[derive(Clone)]
pub struct AuditIntent(pub(super) Vec<u8>);

impl AuditIntent {
    pub fn new(redacted_encoding: Vec<u8>) -> Result<Self, CatalogFailure> {
        if redacted_encoding.is_empty() || redacted_encoding.len() > MAX_AUDIT_INTENT_BYTES {
            Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded))
        } else {
            Ok(Self(redacted_encoding))
        }
    }
}

impl std::fmt::Debug for AuditIntent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditIntent")
            .field("encoded_bytes", &self.0.len())
            .finish()
    }
}

pub struct CatalogProposal {
    pub(super) transaction: TransactionId,
    pub(super) format_epoch: FormatEpoch,
    pub(super) objects: Vec<CatalogObject>,
}

impl CatalogProposal {
    pub fn new(
        transaction: TransactionId,
        format_epoch: FormatEpoch,
        mut objects: Vec<CatalogObject>,
    ) -> Result<Self, CatalogFailure> {
        if objects.is_empty() || objects.len() > MAX_CATALOG_OBJECTS {
            return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
        }
        // The count and per-object bounds above cap this sum below `usize::MAX`
        // on every supported target.
        let total: usize = objects.iter().map(|object| object.plaintext.len()).sum();
        if total > MAX_CATALOG_TOTAL_BYTES {
            return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
        }
        objects.sort_by_key(CatalogObject::identity);
        if objects.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(left, right)| left.identity == right.identity)
        }) {
            return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
        }
        Ok(Self {
            transaction,
            format_epoch,
            objects,
        })
    }
}

impl std::fmt::Debug for CatalogProposal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CatalogProposal")
            .field("transaction", &self.transaction)
            .field("format_epoch", &self.format_epoch)
            .field("object_count", &self.objects.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceAuditRecord {
    pub(super) position: u64,
    pub(super) predecessor_hash: [u8; 32],
    pub(super) hash: [u8; 32],
    pub(super) transaction: TransactionId,
    pub(super) intent: Arc<[u8]>,
}

impl GovernanceAuditRecord {
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    #[must_use]
    pub const fn predecessor_hash(&self) -> [u8; 32] {
        self.predecessor_hash
    }

    #[must_use]
    pub const fn record_hash(&self) -> [u8; 32] {
        self.hash
    }

    #[must_use]
    pub const fn transaction(&self) -> TransactionId {
        self.transaction
    }

    #[must_use]
    pub fn intent(&self) -> &[u8] {
        &self.intent
    }
}
