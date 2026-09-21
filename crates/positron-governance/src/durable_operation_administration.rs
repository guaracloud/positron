//! Administration-owned durable operation identities and request binding.
//!
//! The public seam is the checked request and operation identity. Persistence,
//! phase transitions, and handler reattachment remain in this module so callers
//! cannot manufacture a later operation state.

use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope};
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSnapshot,
    FormatEpoch, TransactionId,
};
use sha2::{Digest, Sha256};

use crate::AdministrativeIdempotencyKey;

const REQUEST_DOMAIN: &[u8] = b"positron.durable-operation.request.v1\0";
const OPERATION_MAGIC: [u8; 8] = *b"POSOPR01";
const OPERATION_AUDIT_MAGIC: [u8; 8] = *b"POSOPA01";
const MAX_OPERATION_RECORDS: usize = 1_024;

/// Closed taxonomy of long-running Release 1 administration work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationKind {
    /// The existing V1-to-V2 Catalog migration handler.
    CatalogFormatMigration,
}

impl DurableOperationKind {
    const fn code(self) -> u8 {
        match self {
            Self::CatalogFormatMigration => 1,
        }
    }

    fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
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
    principal: PrincipalId,
    idempotency: AdministrativeIdempotencyKey,
    kind: DurableOperationKind,
    accepted_generation: u64,
    accepted_at_unix_seconds: u64,
    digest: [u8; 32],
}

impl DurableOperationRequest {
    /// Constructs the only currently registered operation request.
    pub fn catalog_format_migration(
        principal: PrincipalId,
        idempotency: AdministrativeIdempotencyKey,
        accepted_generation: u64,
        accepted_at_unix_seconds: u64,
    ) -> Result<Self, DurableOperationFailure> {
        if accepted_generation == 0 || accepted_at_unix_seconds == 0 {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let kind = DurableOperationKind::CatalogFormatMigration;
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DOMAIN);
        hasher.update(principal.to_bytes());
        hasher.update(idempotency.to_bytes());
        hasher.update([kind.code()]);
        hasher.update(accepted_generation.to_be_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(Self {
            principal,
            idempotency,
            kind,
            accepted_generation,
            accepted_at_unix_seconds,
            digest,
        })
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
    pub const fn accepted_at_unix_seconds(&self) -> u64 {
        self.accepted_at_unix_seconds
    }

    #[must_use]
    pub const fn canonical_digest(&self) -> [u8; 32] {
        self.digest
    }

    fn has_same_semantics(self, other: Self) -> bool {
        self.principal == other.principal
            && self.idempotency == other.idempotency
            && self.kind == other.kind
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
    const fn code(self) -> u8 {
        match self {
            Self::Pending => 1,
            Self::Running => 2,
            Self::Succeeded => 3,
            Self::Failed => 4,
            Self::Cancelled => 5,
        }
    }

    fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
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
    const fn code(self) -> u8 {
        match self {
            Self::Accepted => 1,
            Self::Preflight => 2,
            Self::Draining => 3,
            Self::CatalogPublication => 4,
            Self::Published => 5,
            Self::Cancelled => 6,
        }
    }

    fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
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
    const fn code(self) -> u8 {
        match self {
            Self::InspectByOperationId => 1,
            Self::RetryAfterRecoveryCapacity => 2,
            Self::Never => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
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
    const fn code(self) -> u8 {
        match self {
            Self::AllowedBeforeDrain => 1,
            Self::NotAllowedAfterDrain => 2,
            Self::Cancelled => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
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
    const fn code(self) -> u8 {
        match self {
            Self::NotCrossed => 1,
            Self::CatalogGenerationPublished => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::NotCrossed),
            2 => Ok(Self::CatalogGenerationPublished),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }
}

/// Reservation state describes the actual kernel catalog-commit reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationReservation {
    Released,
    ReacquireForCatalogCommit,
}

impl DurableOperationReservation {
    const fn code(self) -> u8 {
        match self {
            Self::Released => 1,
            Self::ReacquireForCatalogCommit => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::Released),
            2 => Ok(Self::ReacquireForCatalogCommit),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }
}

/// Completed records have no expiry in Release 1; this is disclosed at inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationLookupRetention {
    Indefinite,
}

/// Durable public inspection state. Active records never expire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableOperation {
    request: DurableOperationRequest,
    status: DurableOperationStatus,
    phase: DurableOperationPhase,
    progress_percent: u8,
    retry: DurableOperationRetry,
    cancellation: DurableOperationCancellation,
    boundary: DurableOperationBoundary,
    reservation: DurableOperationReservation,
    updated_at_unix_seconds: u64,
    completed_at_unix_seconds: Option<u64>,
    revision: u64,
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
    pub const fn reservation(self) -> DurableOperationReservation {
        self.reservation
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
        DurableOperationLookupRetention::Indefinite
    }
    #[must_use]
    pub const fn request(self) -> DurableOperationRequest {
        self.request
    }

    fn accepted(request: DurableOperationRequest) -> Self {
        Self {
            request,
            status: DurableOperationStatus::Pending,
            phase: DurableOperationPhase::Accepted,
            progress_percent: 0,
            retry: DurableOperationRetry::InspectByOperationId,
            cancellation: DurableOperationCancellation::AllowedBeforeDrain,
            boundary: DurableOperationBoundary::NotCrossed,
            reservation: DurableOperationReservation::Released,
            updated_at_unix_seconds: request.accepted_at_unix_seconds,
            completed_at_unix_seconds: None,
            revision: 1,
        }
    }

    fn begin(mut self, now: u64) -> Result<Self, DurableOperationFailure> {
        if self.status != DurableOperationStatus::Pending || now < self.updated_at_unix_seconds {
            return Err(DurableOperationFailure::InvalidState);
        }
        self.status = DurableOperationStatus::Running;
        self.phase = DurableOperationPhase::Preflight;
        self.progress_percent = 10;
        self.retry = DurableOperationRetry::InspectByOperationId;
        self.cancellation = DurableOperationCancellation::AllowedBeforeDrain;
        self.reservation = DurableOperationReservation::ReacquireForCatalogCommit;
        self.updated_at_unix_seconds = now;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        Ok(self)
    }

    fn drained(mut self, now: u64) -> Result<Self, DurableOperationFailure> {
        if self.status != DurableOperationStatus::Running || now < self.updated_at_unix_seconds {
            return Err(DurableOperationFailure::InvalidState);
        }
        self.phase = DurableOperationPhase::Draining;
        self.progress_percent = 35;
        self.cancellation = DurableOperationCancellation::NotAllowedAfterDrain;
        self.updated_at_unix_seconds = now;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        Ok(self)
    }

    fn succeeded(mut self, now: u64) -> Result<Self, DurableOperationFailure> {
        if self.status != DurableOperationStatus::Running || now < self.updated_at_unix_seconds {
            return Err(DurableOperationFailure::InvalidState);
        }
        self.status = DurableOperationStatus::Succeeded;
        self.phase = DurableOperationPhase::Published;
        self.progress_percent = 100;
        self.retry = DurableOperationRetry::Never;
        self.cancellation = DurableOperationCancellation::NotAllowedAfterDrain;
        self.boundary = DurableOperationBoundary::CatalogGenerationPublished;
        self.reservation = DurableOperationReservation::Released;
        self.updated_at_unix_seconds = now;
        self.completed_at_unix_seconds = Some(now);
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        Ok(self)
    }

    fn cancelled(mut self, now: u64) -> Result<Self, DurableOperationFailure> {
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
        self.updated_at_unix_seconds = now;
        self.completed_at_unix_seconds = Some(now);
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        Ok(self)
    }
}

/// Administration owns durable records; Catalog owns their sole publication point.
pub struct DurableOperationAdministration;

impl DurableOperationAdministration {
    /// Accepts or exactly replays a catalog-format operation before draining work.
    pub fn accept_catalog_format_migration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if let Some(existing) = find_by_key(&snapshot, request.idempotency)? {
            return exact_replay(existing, request);
        }
        if snapshot.format_epoch() != Some(FormatEpoch::CATALOG_V1) {
            return Err(DurableOperationFailure::InvalidState);
        }
        let operation = DurableOperation::accepted(request);
        publish(catalog, &snapshot, operation)
    }

    /// Reattaches after restart without inferring a failed caller outcome.
    pub fn inspect(
        catalog: &Catalog<'_>,
        operation_id: OperationId,
    ) -> Result<Option<DurableOperation>, DurableOperationFailure> {
        find_by_id(&catalog.pin().map_err(map_catalog)?, operation_id)
    }

    /// Resolves a stable accepted operation before callers construct a retry.
    pub fn inspect_by_idempotency(
        catalog: &Catalog<'_>,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<Option<DurableOperation>, DurableOperationFailure> {
        find_by_key(&catalog.pin().map_err(map_catalog)?, idempotency)
    }

    /// Persists preflight and the actual upcoming Catalog reservation requirement.
    pub fn begin(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        publish(catalog, &snapshot, operation.begin(now)?)
    }

    /// Records the point after which cancellation cannot claim to reverse a migration.
    pub fn mark_drained(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        publish(catalog, &snapshot, operation.drained(now)?)
    }

    /// Records the existing handler's published V2 Catalog generation as the irreversible boundary.
    pub fn succeed_catalog_format_migration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if snapshot.format_epoch() != Some(FormatEpoch::CATALOG_V2) {
            return Err(DurableOperationFailure::InvalidState);
        }
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        publish(catalog, &snapshot, operation.succeeded(now)?)
    }

    /// Cancels only at the documented pre-drain cancellation point.
    pub fn cancel(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        publish(catalog, &snapshot, operation.cancelled(now)?)
    }
}

fn validate_system_actor(
    actor: crate::AuthorizedContext,
    principal: PrincipalId,
) -> Result<(), DurableOperationFailure> {
    if actor.principal_id() != principal
        || actor.scope() != Scope::SystemAdministration
        || actor.tenant_attribution().is_some()
    {
        return Err(DurableOperationFailure::Unauthorized);
    }
    Ok(())
}

fn exact_replay(
    existing: DurableOperation,
    request: DurableOperationRequest,
) -> Result<DurableOperation, DurableOperationFailure> {
    existing
        .request
        .has_same_semantics(request)
        .then_some(existing)
        .ok_or(DurableOperationFailure::IdempotencyConflict)
}

fn map_catalog(failure: positron_kernel::CatalogFailure) -> DurableOperationFailure {
    match failure.code() {
        CatalogFailureCode::IdempotencyConflict => DurableOperationFailure::IdempotencyConflict,
        CatalogFailureCode::LimitExceeded => DurableOperationFailure::CapacityExceeded,
        _ => DurableOperationFailure::PersistenceUnavailable,
    }
}

fn publish(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    operation: DurableOperation,
) -> Result<DurableOperation, DurableOperationFailure> {
    let mut objects = retained_objects(snapshot, operation.operation_id())?;
    objects
        .try_reserve(1)
        .map_err(|_| DurableOperationFailure::CapacityExceeded)?;
    objects.push(CatalogObject::new(encode_operation(operation)).map_err(map_catalog)?);
    let audit = AuditIntent::new(encode_audit(operation)).map_err(map_catalog)?;
    let transaction = transition_transaction(operation)?;
    catalog
        .commit(
            snapshot.identity(),
            CatalogProposal::new(
                transaction,
                snapshot
                    .format_epoch()
                    .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
                objects,
            )
            .map_err(map_catalog)?,
            Some(audit),
        )
        .map_err(map_catalog)?;
    Ok(operation)
}

fn retained_objects(
    snapshot: &CatalogSnapshot,
    replace: OperationId,
) -> Result<Vec<CatalogObject>, DurableOperationFailure> {
    let mut objects = Vec::new();
    objects
        .try_reserve(snapshot.object_count())
        .map_err(|_| DurableOperationFailure::CapacityExceeded)?;
    let mut operation_count = 0_usize;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        if let Some(operation) = decode_operation(bytes)? {
            operation_count = operation_count
                .checked_add(1)
                .ok_or(DurableOperationFailure::CapacityExceeded)?;
            if operation_count > MAX_OPERATION_RECORDS {
                return Err(DurableOperationFailure::CapacityExceeded);
            }
            if operation.operation_id() == replace {
                continue;
            }
        }
        objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
    }
    Ok(objects)
}

fn find_by_id(
    snapshot: &CatalogSnapshot,
    operation_id: OperationId,
) -> Result<Option<DurableOperation>, DurableOperationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let Some(operation) = decode_operation(bytes)? else {
            continue;
        };
        if operation.operation_id() == operation_id && found.replace(operation).is_some() {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
    }
    Ok(found)
}

fn find_by_key(
    snapshot: &CatalogSnapshot,
    key: AdministrativeIdempotencyKey,
) -> Result<Option<DurableOperation>, DurableOperationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let Some(operation) = decode_operation(bytes)? else {
            continue;
        };
        if operation.request.idempotency == key && found.replace(operation).is_some() {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
    }
    Ok(found)
}

fn transition_transaction(
    operation: DurableOperation,
) -> Result<TransactionId, DurableOperationFailure> {
    let mut hasher = Sha256::new();
    hasher.update(b"positron.durable-operation.transition.v1\0");
    hasher.update(operation.operation_id().to_bytes());
    hasher.update(operation.revision.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let Some(bytes) = digest.first_chunk::<16>() else {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    };
    TransactionId::new(*bytes).map_err(map_catalog)
}

fn encode_operation(operation: DurableOperation) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(136);
    encoded.extend_from_slice(&OPERATION_MAGIC);
    encoded.extend_from_slice(&operation.operation_id().to_bytes());
    encoded.extend_from_slice(&operation.request.principal.to_bytes());
    encoded.extend_from_slice(&operation.request.idempotency.to_bytes());
    encoded.push(operation.request.kind.code());
    encoded.extend_from_slice(&operation.request.accepted_generation.to_be_bytes());
    encoded.extend_from_slice(&operation.request.accepted_at_unix_seconds.to_be_bytes());
    encoded.extend_from_slice(&operation.request.digest);
    encoded.push(operation.status.code());
    encoded.push(operation.phase.code());
    encoded.push(operation.progress_percent);
    encoded.push(operation.retry.code());
    encoded.push(operation.cancellation.code());
    encoded.push(operation.boundary.code());
    encoded.push(operation.reservation.code());
    encoded.extend_from_slice(&operation.updated_at_unix_seconds.to_be_bytes());
    encoded.extend_from_slice(
        &operation
            .completed_at_unix_seconds
            .unwrap_or(0)
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&operation.revision.to_be_bytes());
    encoded
}

fn decode_operation(encoded: &[u8]) -> Result<Option<DurableOperation>, DurableOperationFailure> {
    if !encoded.starts_with(&OPERATION_MAGIC) {
        return Ok(None);
    }
    if encoded.len() != 136 {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let mut offset = 8_usize;
    let operation_id = take_array::<16>(encoded, &mut offset)?;
    let principal = PrincipalId::from_bytes(take_array(encoded, &mut offset)?)
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let idempotency = AdministrativeIdempotencyKey::new(take_array(encoded, &mut offset)?)
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let kind = DurableOperationKind::from_code(take_byte(encoded, &mut offset)?)?;
    let accepted_generation = take_u64(encoded, &mut offset)?;
    let accepted_at_unix_seconds = take_u64(encoded, &mut offset)?;
    let digest = take_array(encoded, &mut offset)?;
    let request = DurableOperationRequest {
        principal,
        idempotency,
        kind,
        accepted_generation,
        accepted_at_unix_seconds,
        digest,
    };
    if request.operation_id().to_bytes() != operation_id
        || accepted_generation == 0
        || accepted_at_unix_seconds == 0
    {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let status = DurableOperationStatus::from_code(take_byte(encoded, &mut offset)?)?;
    let phase = DurableOperationPhase::from_code(take_byte(encoded, &mut offset)?)?;
    let progress_percent = take_byte(encoded, &mut offset)?;
    if progress_percent > 100 {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let retry = DurableOperationRetry::from_code(take_byte(encoded, &mut offset)?)?;
    let cancellation = DurableOperationCancellation::from_code(take_byte(encoded, &mut offset)?)?;
    let boundary = DurableOperationBoundary::from_code(take_byte(encoded, &mut offset)?)?;
    let reservation = DurableOperationReservation::from_code(take_byte(encoded, &mut offset)?)?;
    let updated_at_unix_seconds = take_u64(encoded, &mut offset)?;
    let completed = take_u64(encoded, &mut offset)?;
    let revision = take_u64(encoded, &mut offset)?;
    if updated_at_unix_seconds < accepted_at_unix_seconds
        || revision == 0
        || offset != encoded.len()
    {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let completed_at_unix_seconds = if completed == 0 {
        None
    } else {
        Some(completed)
    };
    if status.is_terminal() != completed_at_unix_seconds.is_some() {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    Ok(Some(DurableOperation {
        request,
        status,
        phase,
        progress_percent,
        retry,
        cancellation,
        boundary,
        reservation,
        updated_at_unix_seconds,
        completed_at_unix_seconds,
        revision,
    }))
}

fn take_array<const N: usize>(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], DurableOperationFailure> {
    let end = offset
        .checked_add(N)
        .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
    let bytes = encoded
        .get(*offset..end)
        .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
    *offset = end;
    bytes
        .try_into()
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)
}

fn take_byte(encoded: &[u8], offset: &mut usize) -> Result<u8, DurableOperationFailure> {
    take_array::<1>(encoded, offset).map(|[value]| value)
}
fn take_u64(encoded: &[u8], offset: &mut usize) -> Result<u64, DurableOperationFailure> {
    Ok(u64::from_be_bytes(take_array(encoded, offset)?))
}

fn encode_audit(operation: DurableOperation) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(8 + 16 + 1 + 1 + 1 + 8);
    encoded.extend_from_slice(&OPERATION_AUDIT_MAGIC);
    encoded.extend_from_slice(&operation.operation_id().to_bytes());
    encoded.push(operation.request.kind.code());
    encoded.push(operation.status.code());
    encoded.push(operation.phase.code());
    encoded.extend_from_slice(&operation.revision.to_be_bytes());
    encoded
}

/// Exercises the bounded persisted-record decoder with hostile bytes.
#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_durable_operation_record(data: &[u8]) {
    let _ = decode_operation(data);
}

/// Closed public failures from durable-operation request validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOperationFailure {
    InvalidInput,
    Unauthorized,
    IdempotencyConflict,
    UnknownOperation,
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
