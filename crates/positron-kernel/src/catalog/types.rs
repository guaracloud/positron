use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use crate::data_protection::{DataProtection, SecretKeyBytes};

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatEpoch(pub(super) u32);

impl FormatEpoch {
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
}

pub struct CatalogWrappingKey {
    pub(super) key: SecretKeyBytes,
    pub(super) provider_key_reference: [u8; 16],
    pub(super) key_epoch: u64,
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
    pub(super) marker_key: SecretKeyBytes,
    pub(super) wrapping: CatalogWrappingKey,
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
            let [left, right] = pair else {
                return false;
            };
            left.identity == right.identity
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

#[derive(Clone)]
pub struct CatalogSnapshot(pub(super) Arc<SnapshotData>);

pub(super) struct SnapshotData {
    pub(super) identity: CatalogGenerationId,
    pub(super) number: u64,
    pub(super) format_epoch: Option<FormatEpoch>,
    pub(super) objects: BTreeMap<CatalogObjectId, Arc<[u8]>>,
    pub(super) audit_frontier: AuditFrontier,
}

impl CatalogSnapshot {
    pub(super) fn origin() -> Self {
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

    #[must_use]
    pub fn governance_audit_frontier(&self) -> u64 {
        self.0.audit_frontier.position
    }
}

impl std::fmt::Debug for CatalogSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
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
pub(super) struct AuditFrontier {
    pub(super) position: u64,
    pub(super) hash: [u8; 32],
}

impl AuditFrontier {
    pub(super) const ORIGIN: Self = Self {
        position: 0,
        hash: [0_u8; 32],
    };
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

#[derive(Clone, Debug)]
pub struct CatalogCommit {
    pub(super) snapshot: CatalogSnapshot,
    pub(super) audit: Option<GovernanceAuditRecord>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogFailureCode {
    InvalidInput,
    LimitExceeded,
    StaleGeneration,
    IdempotencyConflict,
    StorageUnavailable,
    IntegrityCorruption,
    AuthenticationFailed,
    ConcurrentWriter,
    ResourceAdmissionRefused,
    UnsupportedFormat,
}

#[derive(Debug)]
pub struct CatalogFailure {
    pub(super) code: CatalogFailureCode,
    pub(super) current: Option<CatalogGenerationId>,
    pub(super) admission: Option<crate::AdmissionFailure>,
}

impl CatalogFailure {
    pub(super) const fn new(code: CatalogFailureCode) -> Self {
        Self {
            code,
            current: None,
            admission: None,
        }
    }

    pub(super) const fn stale(current: CatalogGenerationId) -> Self {
        Self {
            code: CatalogFailureCode::StaleGeneration,
            current: Some(current),
            admission: None,
        }
    }

    pub(super) const fn admission(admission: crate::AdmissionFailure) -> Self {
        Self {
            code: CatalogFailureCode::ResourceAdmissionRefused,
            current: None,
            admission: Some(admission),
        }
    }

    #[must_use]
    pub const fn code(&self) -> CatalogFailureCode {
        self.code
    }

    #[must_use]
    pub const fn current_generation(&self) -> Option<CatalogGenerationId> {
        self.current
    }

    #[must_use]
    pub const fn admission_failure(&self) -> Option<crate::AdmissionFailure> {
        self.admission
    }
}

impl Display for CatalogFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("catalog operation failed")
    }
}

impl Error for CatalogFailure {}
