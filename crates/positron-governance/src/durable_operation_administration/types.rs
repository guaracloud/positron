//! Durable-operation public state, request binding, and typed failures.

use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::PrincipalId;
use sha2::{Digest, Sha256};

use crate::AdministrativeIdempotencyKey;

const REQUEST_DOMAIN: &[u8] = b"positron.durable-operation.request.v1\0";
const COMPLETED_LOOKUP_RETENTION_SECONDS: u64 = 2_592_000;

/// Closed taxonomy of long-running Release 1 administration work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationKind {
    /// The existing V1-to-V2 Catalog migration handler.
    CatalogFormatMigration,
}

impl DurableOperationKind {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::CatalogFormatMigration => 1,
        }
    }

    pub(super) fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::CatalogFormatMigration),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }

    pub(crate) fn from_audit_code(code: u8) -> Result<Self, crate::identity::IdentityFailure> {
        Self::from_code(code).map_err(|_| crate::identity::IdentityFailure)
    }
}

/// Stable opaque identity of one accepted administrative operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OperationId([u8; 16]);

impl OperationId {
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, DurableOperationFailure> {
        (!bytes.iter().all(|byte| *byte == 0))
            .then_some(Self(bytes))
            .ok_or(DurableOperationFailure::InvalidInput)
    }

    /// Derives the stable identity only after the complete canonical request is bound.
    #[must_use]
    pub fn from_request(request: &DurableOperationRequest) -> Self {
        let digest = request.digest;
        let mut bytes = [0_u8; 16];
        let (chunks, remainder) = digest.as_chunks::<16>();
        let [prefix, _] = chunks else {
            return Self(bytes);
        };
        if !remainder.is_empty() {
            return Self(bytes);
        }
        bytes.copy_from_slice(prefix);
        Self(bytes)
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Exact, authenticated input required to accept a durable operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableOperationRequest {
    pub(super) principal: PrincipalId,
    pub(super) idempotency: AdministrativeIdempotencyKey,
    pub(super) kind: DurableOperationKind,
    pub(super) target_identity: Option<[u8; 16]>,
    pub(super) accepted_generation: u64,
    pub(super) accepted_at_unix_seconds: u64,
    pub(super) digest: [u8; 32],
}

impl DurableOperationRequest {
    pub(crate) fn operation_id_for_audit(
        principal: PrincipalId,
        idempotency: AdministrativeIdempotencyKey,
        target_identity: Option<[u8; 16]>,
        accepted_generation: u64,
    ) -> Result<OperationId, DurableOperationFailure> {
        if accepted_generation == 0 {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let kind = DurableOperationKind::CatalogFormatMigration;
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DOMAIN);
        hasher.update(principal.to_bytes());
        hasher.update(idempotency.to_bytes());
        hasher.update([kind.code()]);
        if let Some(target_identity) = target_identity {
            hasher.update(target_identity);
        }
        hasher.update(accepted_generation.to_be_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(OperationId::from_request(&Self {
            principal,
            idempotency,
            kind,
            target_identity,
            accepted_generation,
            accepted_at_unix_seconds: 1,
            digest,
        }))
    }
    /// Constructs the only currently registered operation request.
    pub fn catalog_format_migration(
        principal: PrincipalId,
        idempotency: AdministrativeIdempotencyKey,
        target_identity: [u8; 16],
        accepted_generation: u64,
        accepted_at_unix_seconds: u64,
    ) -> Result<Self, DurableOperationFailure> {
        if accepted_generation == 0
            || accepted_at_unix_seconds == 0
            || target_identity.iter().all(|byte| *byte == 0)
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let kind = DurableOperationKind::CatalogFormatMigration;
        let operation_id = Self::operation_id_for_audit(
            principal,
            idempotency,
            Some(target_identity),
            accepted_generation,
        )?;
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DOMAIN);
        hasher.update(principal.to_bytes());
        hasher.update(idempotency.to_bytes());
        hasher.update([kind.code()]);
        hasher.update(target_identity);
        hasher.update(accepted_generation.to_be_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let request = Self {
            principal,
            idempotency,
            kind,
            target_identity: Some(target_identity),
            accepted_generation,
            accepted_at_unix_seconds,
            digest,
        };
        if request.operation_id() != operation_id {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        Ok(request)
    }

    #[must_use]
    pub fn operation_id(&self) -> OperationId {
        OperationId::from_request(self)
    }

    #[must_use]
    pub const fn kind(&self) -> DurableOperationKind {
        self.kind
    }

    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> AdministrativeIdempotencyKey {
        self.idempotency
    }

    #[must_use]
    pub const fn accepted_generation(&self) -> u64 {
        self.accepted_generation
    }
    #[must_use]
    pub const fn target_identity(&self) -> Option<[u8; 16]> {
        self.target_identity
    }

    #[must_use]
    pub const fn accepted_at_unix_seconds(&self) -> u64 {
        self.accepted_at_unix_seconds
    }

    #[must_use]
    pub const fn canonical_digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(super) fn has_same_semantics(self, other: Self) -> bool {
        self.principal == other.principal
            && self.idempotency == other.idempotency
            && self.kind == other.kind
            && self.target_identity == other.target_identity
            && self.accepted_generation == other.accepted_generation
            && self.digest == other.digest
    }
}

/// Persisted terminal and non-terminal state of one durable operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl DurableOperationStatus {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Pending => 1,
            Self::Running => 2,
            Self::Succeeded => 3,
            Self::Failed => 4,
            Self::Cancelled => 5,
        }
    }

    pub(super) fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Running),
            3 => Ok(Self::Succeeded),
            4 => Ok(Self::Failed),
            5 => Ok(Self::Cancelled),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }

    pub(crate) fn from_audit_code(code: u8) -> Result<Self, crate::identity::IdentityFailure> {
        Self::from_code(code).map_err(|_| crate::identity::IdentityFailure)
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

/// Checked phase taxonomy for the concrete catalog-format migration handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationPhase {
    Accepted,
    Preflight,
    Draining,
    CatalogPublication,
    Published,
    Cancelled,
}

impl DurableOperationPhase {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Accepted => 1,
            Self::Preflight => 2,
            Self::Draining => 3,
            Self::CatalogPublication => 4,
            Self::Published => 5,
            Self::Cancelled => 6,
        }
    }

    pub(super) fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Preflight),
            3 => Ok(Self::Draining),
            4 => Ok(Self::CatalogPublication),
            5 => Ok(Self::Published),
            6 => Ok(Self::Cancelled),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }

    pub(crate) fn from_audit_code(code: u8) -> Result<Self, crate::identity::IdentityFailure> {
        Self::from_code(code).map_err(|_| crate::identity::IdentityFailure)
    }
}

/// Bounded caller-visible retry guidance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationRetry {
    InspectByOperationId,
    RetryAfterRecoveryCapacity,
    Never,
}

impl DurableOperationRetry {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::InspectByOperationId => 1,
            Self::RetryAfterRecoveryCapacity => 2,
            Self::Never => 3,
        }
    }

    pub(super) fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::InspectByOperationId),
            2 => Ok(Self::RetryAfterRecoveryCapacity),
            3 => Ok(Self::Never),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }
}

/// Explicit cancellation point; cancellation never promises rollback past publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationCancellation {
    AllowedBeforeDrain,
    NotAllowedAfterDrain,
    Cancelled,
}

impl DurableOperationCancellation {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::AllowedBeforeDrain => 1,
            Self::NotAllowedAfterDrain => 2,
            Self::Cancelled => 3,
        }
    }

    pub(super) fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::AllowedBeforeDrain),
            2 => Ok(Self::NotAllowedAfterDrain),
            3 => Ok(Self::Cancelled),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }
}

/// The only irreversible boundary for the currently registered handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationBoundary {
    NotCrossed,
    CatalogGenerationPublished,
}

impl DurableOperationBoundary {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::NotCrossed => 1,
            Self::CatalogGenerationPublished => 2,
        }
    }

    pub(super) fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::NotCrossed),
            2 => Ok(Self::CatalogGenerationPublished),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }
}

/// Lookup retention is system-governed. Active operation records never expire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationLookupRetention {
    Indefinite,
    UntilUnixSeconds(u64),
}

/// A stable, non-secret reason for a genuinely terminal handler failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationTerminalError {
    HandlerRejected,
    LegacyUnknown,
}

impl DurableOperationTerminalError {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::HandlerRejected => 1,
            Self::LegacyUnknown => 2,
        }
    }

    pub(super) fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::HandlerRejected),
            2 => Ok(Self::LegacyUnknown),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }
}

/// Durable public inspection state. Active records never expire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableOperation {
    pub(super) request: DurableOperationRequest,
    pub(super) status: DurableOperationStatus,
    pub(super) phase: DurableOperationPhase,
    pub(super) progress_percent: u8,
    pub(super) retry: DurableOperationRetry,
    pub(super) cancellation: DurableOperationCancellation,
    pub(super) boundary: DurableOperationBoundary,
    pub(super) terminal_error: Option<DurableOperationTerminalError>,
    pub(super) cancellation_idempotency: Option<AdministrativeIdempotencyKey>,
    pub(super) updated_at_unix_seconds: u64,
    pub(super) completed_at_unix_seconds: Option<u64>,
    pub(super) revision: u64,
}

impl DurableOperation {
    #[must_use]
    pub fn operation_id(self) -> OperationId {
        self.request.operation_id()
    }
    #[must_use]
    pub const fn status(self) -> DurableOperationStatus {
        self.status
    }
    #[must_use]
    pub const fn phase(self) -> DurableOperationPhase {
        self.phase
    }
    #[must_use]
    pub const fn progress_percent(self) -> u8 {
        self.progress_percent
    }
    #[must_use]
    pub const fn retry_guidance(self) -> DurableOperationRetry {
        self.retry
    }
    #[must_use]
    pub const fn cancellation(self) -> DurableOperationCancellation {
        self.cancellation
    }
    #[must_use]
    pub const fn irreversible_boundary(self) -> DurableOperationBoundary {
        self.boundary
    }
    #[must_use]
    pub const fn terminal_error(self) -> Option<DurableOperationTerminalError> {
        self.terminal_error
    }
    #[must_use]
    pub const fn accepted_at_unix_seconds(self) -> u64 {
        self.request.accepted_at_unix_seconds
    }
    #[must_use]
    pub const fn updated_at_unix_seconds(self) -> u64 {
        self.updated_at_unix_seconds
    }
    #[must_use]
    pub const fn completed_at_unix_seconds(self) -> Option<u64> {
        self.completed_at_unix_seconds
    }
    #[must_use]
    pub const fn lookup_retention(self) -> DurableOperationLookupRetention {
        match self.completed_at_unix_seconds {
            Some(completed) => DurableOperationLookupRetention::UntilUnixSeconds(
                completed.saturating_add(COMPLETED_LOOKUP_RETENTION_SECONDS),
            ),
            None => DurableOperationLookupRetention::Indefinite,
        }
    }
    #[must_use]
    pub const fn earliest_lookup_expiry_unix_seconds(self) -> Option<u64> {
        match self.lookup_retention() {
            DurableOperationLookupRetention::Indefinite => None,
            DurableOperationLookupRetention::UntilUnixSeconds(expiry) => Some(expiry),
        }
    }
    #[must_use]
    pub const fn request(self) -> DurableOperationRequest {
        self.request
    }
    #[must_use]
    pub const fn target_identity(self) -> Option<[u8; 16]> {
        self.request.target_identity()
    }
    #[must_use]
    pub const fn cancellation_idempotency_key(self) -> Option<AdministrativeIdempotencyKey> {
        self.cancellation_idempotency
    }

    pub(super) fn accepted(request: DurableOperationRequest) -> Self {
        Self {
            request,
            status: DurableOperationStatus::Pending,
            phase: DurableOperationPhase::Accepted,
            progress_percent: 0,
            retry: DurableOperationRetry::InspectByOperationId,
            cancellation: DurableOperationCancellation::AllowedBeforeDrain,
            boundary: DurableOperationBoundary::NotCrossed,
            terminal_error: None,
            cancellation_idempotency: None,
            updated_at_unix_seconds: request.accepted_at_unix_seconds,
            completed_at_unix_seconds: None,
            revision: 1,
        }
    }

    pub(super) fn begin(mut self, now: u64) -> Result<Self, DurableOperationFailure> {
        if self.status != DurableOperationStatus::Pending || now < self.updated_at_unix_seconds {
            return Err(DurableOperationFailure::InvalidState);
        }
        self.status = DurableOperationStatus::Running;
        self.phase = DurableOperationPhase::Preflight;
        self.progress_percent = 10;
        self.retry = DurableOperationRetry::InspectByOperationId;
        self.cancellation = DurableOperationCancellation::AllowedBeforeDrain;
        self.updated_at_unix_seconds = now;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        Ok(self)
    }

    pub(super) fn drained(mut self, now: u64) -> Result<Self, DurableOperationFailure> {
        if self.status != DurableOperationStatus::Running || now < self.updated_at_unix_seconds {
            return Err(DurableOperationFailure::InvalidState);
        }
        self.phase = DurableOperationPhase::CatalogPublication;
        self.progress_percent = 50;
        self.cancellation = DurableOperationCancellation::NotAllowedAfterDrain;
        self.updated_at_unix_seconds = now;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        Ok(self)
    }

    pub(super) fn succeeded(mut self, now: u64) -> Result<Self, DurableOperationFailure> {
        if self.status != DurableOperationStatus::Running || now < self.updated_at_unix_seconds {
            return Err(DurableOperationFailure::InvalidState);
        }
        self.status = DurableOperationStatus::Succeeded;
        self.phase = DurableOperationPhase::Published;
        self.progress_percent = 100;
        self.retry = DurableOperationRetry::Never;
        self.cancellation = DurableOperationCancellation::NotAllowedAfterDrain;
        self.boundary = DurableOperationBoundary::CatalogGenerationPublished;
        self.terminal_error = None;
        self.updated_at_unix_seconds = now;
        self.completed_at_unix_seconds = Some(now);
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        Ok(self)
    }

    pub(super) fn cancelled(
        mut self,
        now: u64,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<Self, DurableOperationFailure> {
        if self.status == DurableOperationStatus::Cancelled {
            return (self.cancellation_idempotency == Some(idempotency))
                .then_some(self)
                .ok_or(DurableOperationFailure::IdempotencyConflict);
        }
        if self.status != DurableOperationStatus::Pending
            || self.boundary != DurableOperationBoundary::NotCrossed
            || now < self.updated_at_unix_seconds
        {
            return Err(DurableOperationFailure::CancellationUnavailable);
        }
        self.status = DurableOperationStatus::Cancelled;
        self.phase = DurableOperationPhase::Cancelled;
        self.retry = DurableOperationRetry::Never;
        self.cancellation = DurableOperationCancellation::Cancelled;
        self.cancellation_idempotency = Some(idempotency);
        self.updated_at_unix_seconds = now;
        self.completed_at_unix_seconds = Some(now);
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        Ok(self)
    }

    pub(super) fn failed(
        mut self,
        now: u64,
        error: DurableOperationTerminalError,
    ) -> Result<Self, DurableOperationFailure> {
        if self.status != DurableOperationStatus::Running || now < self.updated_at_unix_seconds {
            return Err(DurableOperationFailure::InvalidState);
        }
        self.status = DurableOperationStatus::Failed;
        self.retry = DurableOperationRetry::Never;
        self.terminal_error = Some(error);
        self.updated_at_unix_seconds = now;
        self.completed_at_unix_seconds = Some(now);
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        Ok(self)
    }
}

/// Closed public failures from durable-operation request validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationFailure {
    InvalidInput,
    Unauthorized,
    IdempotencyConflict,
    StaleGeneration,
    UnknownOperation,
    CompletedLookupExpired,
    InvalidState,
    CancellationUnavailable,
    CapacityExceeded,
    PersistenceUnavailable,
}

impl Display for DurableOperationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("durable operation failed")
    }
}

impl Error for DurableOperationFailure {}
