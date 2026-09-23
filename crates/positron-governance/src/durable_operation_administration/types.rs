//! Durable-operation public state, request binding, and typed failures.

use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, TenantId};
use sha2::{Digest, Sha256};

use crate::AdministrativeIdempotencyKey;

const REQUEST_DOMAIN: &[u8] = b"positron.durable-operation.request.v1\0";
const COMPLETED_LOOKUP_RETENTION_SECONDS: u64 = 2_592_000;

/// Closed taxonomy of long-running Release 1 administration work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationKind {
    /// The existing V1-to-V2 Catalog migration handler.
    CatalogFormatMigration,
    /// A tenant-scoped Query export whose output manifest is the irreversible receipt.
    QueryExport,
}

impl DurableOperationKind {
    /// Names this handler's applicable irreversible boundary before execution.
    #[must_use]
    pub const fn declared_irreversible_boundary(self) -> DurableOperationBoundary {
        match self {
            Self::CatalogFormatMigration => DurableOperationBoundary::CatalogGenerationPublished,
            Self::QueryExport => DurableOperationBoundary::ExportManifestPublished,
        }
    }

    pub(super) const fn code(self) -> u8 {
        match self {
            Self::CatalogFormatMigration => 1,
            Self::QueryExport => 2,
        }
    }

    pub(super) fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::CatalogFormatMigration),
            2 => Ok(Self::QueryExport),
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
    pub(super) applicable_tenant: Option<TenantId>,
    pub(super) accepted_generation: u64,
    pub(super) accepted_at_unix_seconds: u64,
    /// Full Query-owned request binding for a Query export. The generic
    /// administrative idempotency key is only 128 bits, so it is not enough
    /// to stand in for this authenticated 256-bit request commitment.
    pub(super) query_export_request_digest: Option<[u8; 32]>,
    pub(super) digest: [u8; 32],
}

impl DurableOperationRequest {
    pub(crate) fn operation_id_for_audit(
        principal: PrincipalId,
        idempotency: AdministrativeIdempotencyKey,
        kind: DurableOperationKind,
        target_identity: Option<[u8; 16]>,
        accepted_generation: u64,
        applicable_tenant: Option<TenantId>,
        query_export_request_digest: Option<[u8; 32]>,
    ) -> Result<OperationId, DurableOperationFailure> {
        if accepted_generation == 0 {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DOMAIN);
        hasher.update(principal.to_bytes());
        hasher.update(idempotency.to_bytes());
        hasher.update([kind.code()]);
        match kind {
            DurableOperationKind::CatalogFormatMigration => {
                if applicable_tenant.is_some() || query_export_request_digest.is_some() {
                    return Err(DurableOperationFailure::InvalidInput);
                }
                if let Some(target_identity) = target_identity {
                    hasher.update(target_identity);
                }
                hasher.update(accepted_generation.to_be_bytes());
            },
            DurableOperationKind::QueryExport => {
                hasher.update(
                    applicable_tenant
                        .ok_or(DurableOperationFailure::InvalidInput)?
                        .to_bytes(),
                );
                hasher.update(target_identity.ok_or(DurableOperationFailure::InvalidInput)?);
                hasher.update(
                    query_export_request_digest.ok_or(DurableOperationFailure::InvalidInput)?,
                );
            },
        }
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(OperationId::from_request(&Self {
            principal,
            idempotency,
            kind,
            target_identity,
            applicable_tenant,
            accepted_generation,
            accepted_at_unix_seconds: 1,
            query_export_request_digest,
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
            kind,
            Some(target_identity),
            accepted_generation,
            None,
            None,
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
            applicable_tenant: None,
            accepted_generation,
            accepted_at_unix_seconds,
            query_export_request_digest: None,
            digest,
        };
        if request.operation_id() != operation_id {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        Ok(request)
    }

    /// Constructs a tenant-query export operation. `target_identity` is the
    /// immutable protected output identity, never a path or credential.
    pub fn query_export(
        principal: PrincipalId,
        tenant: TenantId,
        idempotency: AdministrativeIdempotencyKey,
        target_identity: [u8; 16],
        accepted_generation: u64,
        accepted_at_unix_seconds: u64,
        query_export_request_digest: [u8; 32],
    ) -> Result<Self, DurableOperationFailure> {
        if accepted_generation == 0
            || accepted_at_unix_seconds == 0
            || target_identity.iter().all(|byte| *byte == 0)
            || query_export_request_digest.iter().all(|byte| *byte == 0)
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let kind = DurableOperationKind::QueryExport;
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DOMAIN);
        hasher.update(principal.to_bytes());
        hasher.update(idempotency.to_bytes());
        hasher.update([kind.code()]);
        hasher.update(tenant.to_bytes());
        hasher.update(target_identity);
        // Query catalog generation is a fresh-request precondition. It is not
        // part of the durable idempotency intent: an exact caller retry must
        // retain the originally accepted snapshot after catalog advances.
        hasher.update(query_export_request_digest);
        let digest: [u8; 32] = hasher.finalize().into();
        let request = Self {
            principal,
            idempotency,
            kind,
            target_identity: Some(target_identity),
            applicable_tenant: Some(tenant),
            accepted_generation,
            accepted_at_unix_seconds,
            query_export_request_digest: Some(query_export_request_digest),
            digest,
        };
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

    /// Returns the full Query request commitment retained for durable resume.
    #[must_use]
    pub const fn query_export_request_digest(self) -> Option<[u8; 32]> {
        self.query_export_request_digest
    }

    /// Returns the tenant explicitly bound to a tenant-scoped operation.
    #[must_use]
    pub const fn applicable_tenant(self) -> Option<TenantId> {
        self.applicable_tenant
    }

    pub(super) fn has_same_semantics(self, other: Self) -> bool {
        self.principal == other.principal
            && self.idempotency == other.idempotency
            && self.kind == other.kind
            && self.target_identity == other.target_identity
            && self.applicable_tenant == other.applicable_tenant
            && (self.kind == DurableOperationKind::QueryExport
                || self.accepted_generation == other.accepted_generation)
            && self.query_export_request_digest == other.query_export_request_digest
            && self.digest == other.digest
    }

    pub(super) fn is_valid_persisted_request(self) -> bool {
        match self.kind {
            DurableOperationKind::CatalogFormatMigration => self
                .target_identity
                .and_then(|target_identity| {
                    Self::catalog_format_migration(
                        self.principal,
                        self.idempotency,
                        target_identity,
                        self.accepted_generation,
                        self.accepted_at_unix_seconds,
                    )
                    .ok()
                })
                .is_some_and(|canonical| canonical == self),
            DurableOperationKind::QueryExport => self
                .target_identity
                .and_then(|target_identity| {
                    Self::query_export(
                        self.principal,
                        self.applicable_tenant?,
                        self.idempotency,
                        target_identity,
                        self.accepted_generation,
                        self.accepted_at_unix_seconds,
                        self.query_export_request_digest?,
                    )
                    .ok()
                })
                .is_some_and(|canonical| canonical == self),
        }
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
    ExportManifestPublished,
}

impl DurableOperationBoundary {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::NotCrossed => 1,
            Self::CatalogGenerationPublished => 2,
            Self::ExportManifestPublished => 3,
        }
    }

    pub(super) fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::NotCrossed),
            2 => Ok(Self::CatalogGenerationPublished),
            3 => Ok(Self::ExportManifestPublished),
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
    QueryFailure(DurableQueryExportFailure),
}

impl DurableOperationTerminalError {
    pub(super) const fn encoded(self) -> (u8, u8) {
        match self {
            Self::HandlerRejected => (1, 0),
            Self::LegacyUnknown => (2, 0),
            Self::QueryFailure(failure) => {
                (failure.code.code() + 2, failure.limiting_budget.code())
            },
        }
    }

    pub(super) fn from_encoded(code: u8, detail: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 if detail == 0 => Ok(Self::HandlerRejected),
            2 if detail == 0 => Ok(Self::LegacyUnknown),
            3..=16 => Ok(Self::QueryFailure(DurableQueryExportFailure::from_encoded(
                code - 2,
                detail,
            )?)),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }

    #[must_use]
    pub const fn query_failure(self) -> Option<DurableQueryExportFailure> {
        match self {
            Self::QueryFailure(failure) => Some(failure),
            Self::HandlerRejected | Self::LegacyUnknown => None,
        }
    }

    fn is_valid_for(self, kind: DurableOperationKind) -> bool {
        match self {
            Self::HandlerRejected | Self::LegacyUnknown => true,
            Self::QueryFailure(failure) => {
                kind == DurableOperationKind::QueryExport && failure.is_valid()
            },
        }
    }
}

/// The durable, bounded public Query failure outcome retained for an exact
/// Query-export retry that terminated before a signed manifest exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableQueryExportFailure {
    code: DurableQueryExportFailureCode,
    limiting_budget: DurableQueryBudgetDimension,
}

impl DurableQueryExportFailure {
    #[must_use]
    pub const fn new(
        code: DurableQueryExportFailureCode,
        limiting_budget: Option<DurableQueryBudgetDimension>,
    ) -> Self {
        Self {
            code,
            limiting_budget: DurableQueryBudgetDimension::from_option(limiting_budget),
        }
    }

    fn from_encoded(code: u8, dimension: u8) -> Result<Self, DurableOperationFailure> {
        let code = DurableQueryExportFailureCode::from_code(code)?;
        let limiting_budget = DurableQueryBudgetDimension::from_code(dimension)?;
        if !limiting_budget.is_allowed_for(code) {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        Ok(Self {
            code,
            limiting_budget,
        })
    }

    #[must_use]
    pub const fn code(self) -> DurableQueryExportFailureCode {
        self.code
    }

    #[must_use]
    pub const fn limiting_budget(self) -> Option<DurableQueryBudgetDimension> {
        self.limiting_budget.into_option()
    }

    const fn is_valid(self) -> bool {
        self.limiting_budget.is_allowed_for(self.code)
    }
}

/// Stable codes for terminal Query-export outcomes held by a Durable Operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableQueryExportFailureCode {
    Unauthorized,
    IdempotencyConflict,
    InvalidBudget,
    BudgetExhausted,
    InvalidCursor,
    SnapshotExpired,
    AuthorizationChanged,
    Cancelled,
    ResourceAdmissionRefused,
    ResourceExhausted,
    UnsupportedQuery,
    StoreUnavailable,
    MalformedPersistentData,
    Internal,
}

impl DurableQueryExportFailureCode {
    const fn code(self) -> u8 {
        match self {
            Self::Unauthorized => 1,
            Self::IdempotencyConflict => 2,
            Self::InvalidBudget => 3,
            Self::BudgetExhausted => 4,
            Self::InvalidCursor => 5,
            Self::SnapshotExpired => 6,
            Self::AuthorizationChanged => 7,
            Self::Cancelled => 8,
            Self::ResourceAdmissionRefused => 9,
            Self::ResourceExhausted => 10,
            Self::UnsupportedQuery => 11,
            Self::StoreUnavailable => 12,
            Self::MalformedPersistentData => 13,
            Self::Internal => 14,
        }
    }

    fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::Unauthorized),
            2 => Ok(Self::IdempotencyConflict),
            3 => Ok(Self::InvalidBudget),
            4 => Ok(Self::BudgetExhausted),
            5 => Ok(Self::InvalidCursor),
            6 => Ok(Self::SnapshotExpired),
            7 => Ok(Self::AuthorizationChanged),
            8 => Ok(Self::Cancelled),
            9 => Ok(Self::ResourceAdmissionRefused),
            10 => Ok(Self::ResourceExhausted),
            11 => Ok(Self::UnsupportedQuery),
            12 => Ok(Self::StoreUnavailable),
            13 => Ok(Self::MalformedPersistentData),
            14 => Ok(Self::Internal),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }
}

/// A bounded query budget dimension retained only when it qualified the
/// original terminal Query failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableQueryBudgetDimension {
    None,
    ScannedBytes,
    DecodedRecords,
    OutputRows,
    OutputBytes,
    MemoryBytes,
    CpuWorkUnits,
    WallSeconds,
    MaximumTimeRangeNanoseconds,
}

impl DurableQueryBudgetDimension {
    const fn from_option(value: Option<Self>) -> Self {
        match value {
            Some(value) => value,
            None => Self::None,
        }
    }

    const fn into_option(self) -> Option<Self> {
        match self {
            Self::None => None,
            value => Some(value),
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::ScannedBytes => 1,
            Self::DecodedRecords => 2,
            Self::OutputRows => 3,
            Self::OutputBytes => 4,
            Self::MemoryBytes => 5,
            Self::CpuWorkUnits => 6,
            Self::WallSeconds => 7,
            Self::MaximumTimeRangeNanoseconds => 8,
        }
    }

    fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            0 => Ok(Self::None),
            1 => Ok(Self::ScannedBytes),
            2 => Ok(Self::DecodedRecords),
            3 => Ok(Self::OutputRows),
            4 => Ok(Self::OutputBytes),
            5 => Ok(Self::MemoryBytes),
            6 => Ok(Self::CpuWorkUnits),
            7 => Ok(Self::WallSeconds),
            8 => Ok(Self::MaximumTimeRangeNanoseconds),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }

    const fn is_allowed_for(self, code: DurableQueryExportFailureCode) -> bool {
        matches!(self, Self::None)
            || matches!(
                code,
                DurableQueryExportFailureCode::InvalidBudget
                    | DurableQueryExportFailureCode::BudgetExhausted
            )
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
    pub const fn kind(self) -> DurableOperationKind {
        self.request.kind()
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
    /// Returns the boundary declared by this operation's handler.
    #[must_use]
    pub const fn declared_irreversible_boundary(self) -> DurableOperationBoundary {
        self.request.kind().declared_irreversible_boundary()
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
        if self.status != DurableOperationStatus::Running
            || self.phase != DurableOperationPhase::Draining
            || now < self.updated_at_unix_seconds
        {
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

    pub(super) fn draining(mut self, now: u64) -> Result<Self, DurableOperationFailure> {
        if self.status != DurableOperationStatus::Running
            || self.phase != DurableOperationPhase::Preflight
            || now < self.updated_at_unix_seconds
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        self.phase = DurableOperationPhase::Draining;
        self.progress_percent = 25;
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
        self.boundary = self.request.kind.declared_irreversible_boundary();
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
        let cancellable = matches!(
            (self.status, self.phase, self.cancellation, self.boundary,),
            (
                DurableOperationStatus::Pending,
                DurableOperationPhase::Accepted,
                DurableOperationCancellation::AllowedBeforeDrain,
                DurableOperationBoundary::NotCrossed,
            ) | (
                DurableOperationStatus::Running,
                DurableOperationPhase::Preflight,
                DurableOperationCancellation::AllowedBeforeDrain,
                DurableOperationBoundary::NotCrossed,
            )
        );
        if !cancellable || now < self.updated_at_unix_seconds {
            return Err(DurableOperationFailure::CancellationUnavailable);
        }
        self.status = DurableOperationStatus::Cancelled;
        self.phase = DurableOperationPhase::Cancelled;
        self.progress_percent = 0;
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
        if self.status != DurableOperationStatus::Running
            || now < self.updated_at_unix_seconds
            || !error.is_valid_for(self.request.kind)
        {
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

    /// Records a Query-export failure whose signed terminal manifest has
    /// already become durable. The manifest is the operation's irreversible
    /// boundary even when its Query terminal is incomplete.
    pub(super) fn failed_after_manifest_publication(
        mut self,
        now: u64,
        error: DurableOperationTerminalError,
    ) -> Result<Self, DurableOperationFailure> {
        if self.status != DurableOperationStatus::Running
            || self.request.kind != DurableOperationKind::QueryExport
            || now < self.updated_at_unix_seconds
            || !error.is_valid_for(self.request.kind)
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        self.status = DurableOperationStatus::Failed;
        self.phase = DurableOperationPhase::Published;
        self.progress_percent = 100;
        self.retry = DurableOperationRetry::Never;
        self.cancellation = DurableOperationCancellation::NotAllowedAfterDrain;
        self.boundary = DurableOperationBoundary::ExportManifestPublished;
        self.terminal_error = Some(error);
        self.updated_at_unix_seconds = now;
        self.completed_at_unix_seconds = Some(now);
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        Ok(self)
    }

    pub(super) fn is_legal_persisted_state(self) -> bool {
        if !self.request.is_valid_persisted_request()
            || self.updated_at_unix_seconds < self.request.accepted_at_unix_seconds
            || self.revision == 0
        {
            return false;
        }
        if self
            .terminal_error
            .is_some_and(|error| !error.is_valid_for(self.request.kind))
        {
            return false;
        }

        let active_checkpoint = match self.phase {
            DurableOperationPhase::Preflight => {
                Some((10, DurableOperationCancellation::AllowedBeforeDrain))
            },
            DurableOperationPhase::Draining => {
                Some((25, DurableOperationCancellation::NotAllowedAfterDrain))
            },
            DurableOperationPhase::CatalogPublication => {
                Some((50, DurableOperationCancellation::NotAllowedAfterDrain))
            },
            _ => None,
        };
        match self.status {
            DurableOperationStatus::Pending => {
                self.phase == DurableOperationPhase::Accepted
                    && self.progress_percent == 0
                    && self.retry == DurableOperationRetry::InspectByOperationId
                    && self.cancellation == DurableOperationCancellation::AllowedBeforeDrain
                    && self.boundary == DurableOperationBoundary::NotCrossed
                    && self.terminal_error.is_none()
                    && self.cancellation_idempotency.is_none()
                    && self.completed_at_unix_seconds.is_none()
            },
            DurableOperationStatus::Running => {
                active_checkpoint.is_some_and(|(progress, cancellation)| {
                    self.progress_percent == progress
                        && self.retry == DurableOperationRetry::InspectByOperationId
                        && self.cancellation == cancellation
                        && self.boundary == DurableOperationBoundary::NotCrossed
                        && self.terminal_error.is_none()
                        && self.cancellation_idempotency.is_none()
                        && self.completed_at_unix_seconds.is_none()
                })
            },
            DurableOperationStatus::Succeeded => {
                self.phase == DurableOperationPhase::Published
                    && self.progress_percent == 100
                    && self.retry == DurableOperationRetry::Never
                    && self.cancellation == DurableOperationCancellation::NotAllowedAfterDrain
                    && self.boundary == self.request.kind.declared_irreversible_boundary()
                    && self.terminal_error.is_none()
                    && self.cancellation_idempotency.is_none()
                    && self.completed_at_unix_seconds == Some(self.updated_at_unix_seconds)
            },
            DurableOperationStatus::Failed => {
                let failed_before_boundary =
                    active_checkpoint.is_some_and(|(progress, cancellation)| {
                        self.progress_percent == progress
                            && self.retry == DurableOperationRetry::Never
                            && self.cancellation == cancellation
                            && self.boundary == DurableOperationBoundary::NotCrossed
                    });
                let failed_after_query_manifest = self.request.kind
                    == DurableOperationKind::QueryExport
                    && self.phase == DurableOperationPhase::Published
                    && self.progress_percent == 100
                    && self.retry == DurableOperationRetry::Never
                    && self.cancellation == DurableOperationCancellation::NotAllowedAfterDrain
                    && self.boundary == DurableOperationBoundary::ExportManifestPublished;
                (failed_before_boundary || failed_after_query_manifest)
                    && self.terminal_error.is_some()
                    && self.cancellation_idempotency.is_none()
                    && self.completed_at_unix_seconds == Some(self.updated_at_unix_seconds)
            },
            DurableOperationStatus::Cancelled => {
                self.phase == DurableOperationPhase::Cancelled
                    && self.progress_percent == 0
                    && self.retry == DurableOperationRetry::Never
                    && self.cancellation == DurableOperationCancellation::Cancelled
                    && self.boundary == DurableOperationBoundary::NotCrossed
                    && self.terminal_error.is_none()
                    && self.cancellation_idempotency.is_some()
                    && self.completed_at_unix_seconds == Some(self.updated_at_unix_seconds)
            },
        }
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
