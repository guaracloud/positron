use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_ingest::{AdmissionGroupPlanFailure, ReceiveFailure};
use positron_kernel::{CatalogFailureCode, LedgerFailureCode};
use positron_query::{QueryEvent, QueryFailure, QueryFailureCode, QueryTerminal};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceFailure {
    Unauthorized,
    CapacityUnavailable,
    RequestTooLarge,
    InvalidRequest,
    KeyUnavailable,
    CatalogUnavailable,
    LedgerUnavailable,
    StorageUnavailable,
    CorruptState,
    Internal,
    Cancelled,
}

pub(super) fn map_admission_group_plan_failure(
    failure: AdmissionGroupPlanFailure,
) -> ServiceFailure {
    match failure {
        AdmissionGroupPlanFailure::UnsupportedSignal => ServiceFailure::InvalidRequest,
        AdmissionGroupPlanFailure::AssignmentUnavailable => ServiceFailure::CapacityUnavailable,
        AdmissionGroupPlanFailure::RecordCountExceeded => ServiceFailure::Internal,
    }
}

pub(super) fn map_receive_failure(failure: ReceiveFailure) -> ServiceFailure {
    match failure {
        ReceiveFailure::AuthenticationRejected => ServiceFailure::Unauthorized,
        ReceiveFailure::CapacityUnavailable => ServiceFailure::CapacityUnavailable,
        ReceiveFailure::TransportLimitExceeded => ServiceFailure::RequestTooLarge,
        _ => ServiceFailure::InvalidRequest,
    }
}

pub(super) fn map_query_failure(failure: &QueryFailure) -> ServiceFailure {
    map_query_failure_code(failure.code())
}

pub(super) const fn classify_catalog_failure_code(code: CatalogFailureCode) -> ServiceFailure {
    match code {
        CatalogFailureCode::ResourceAdmissionRefused | CatalogFailureCode::LimitExceeded => {
            ServiceFailure::CapacityUnavailable
        },
        CatalogFailureCode::StorageUnavailable => ServiceFailure::StorageUnavailable,
        CatalogFailureCode::IntegrityCorruption
        | CatalogFailureCode::AuthenticationFailed
        | CatalogFailureCode::UnsupportedFormat
        | CatalogFailureCode::InvalidInput => ServiceFailure::CorruptState,
        CatalogFailureCode::StaleGeneration
        | CatalogFailureCode::ConcurrentWriter
        | CatalogFailureCode::IdempotencyConflict => ServiceFailure::CatalogUnavailable,
    }
}

pub(super) const fn classify_bootstrap_failure_code(
    code: crate::BootstrapFailureCode,
) -> ServiceFailure {
    match code {
        crate::BootstrapFailureCode::KeyCustodyUnavailable => ServiceFailure::KeyUnavailable,
        crate::BootstrapFailureCode::ResourceUnavailable => ServiceFailure::CapacityUnavailable,
        crate::BootstrapFailureCode::CorruptState
        | crate::BootstrapFailureCode::IdentityMismatch => ServiceFailure::CorruptState,
        crate::BootstrapFailureCode::StorageUnavailable
        | crate::BootstrapFailureCode::CatalogUnavailable => ServiceFailure::StorageUnavailable,
        crate::BootstrapFailureCode::InvalidRoots
        | crate::BootstrapFailureCode::InconsistentRoots
        | crate::BootstrapFailureCode::AlreadyInitialized
        | crate::BootstrapFailureCode::LedgerUnavailable
        | crate::BootstrapFailureCode::ClaimUnavailable
        | crate::BootstrapFailureCode::ClaimDestructionFailed
        | crate::BootstrapFailureCode::EntropyUnavailable => ServiceFailure::Internal,
    }
}

pub(super) const fn classify_ledger_failure_code(code: LedgerFailureCode) -> ServiceFailure {
    match code {
        LedgerFailureCode::ResourceAdmissionRefused
        | LedgerFailureCode::LimitExceeded
        | LedgerFailureCode::StorageExhausted => ServiceFailure::CapacityUnavailable,
        LedgerFailureCode::StorageUnavailable => ServiceFailure::StorageUnavailable,
        LedgerFailureCode::IntegrityCorruption
        | LedgerFailureCode::AuthenticationFailed
        | LedgerFailureCode::UnsupportedFormat
        | LedgerFailureCode::InvalidInput
        | LedgerFailureCode::PhysicalScopeMismatch
        | LedgerFailureCode::RecoveryRequired => ServiceFailure::CorruptState,
        LedgerFailureCode::StaleGeneration
        | LedgerFailureCode::ConcurrentWriter
        | LedgerFailureCode::IdempotencyConflict
        | LedgerFailureCode::SnapshotExpired => ServiceFailure::CatalogUnavailable,
        LedgerFailureCode::StaleResumeMarker => ServiceFailure::InvalidRequest,
        LedgerFailureCode::Cancelled => ServiceFailure::Cancelled,
    }
}

pub(super) const fn map_query_failure_code(code: QueryFailureCode) -> ServiceFailure {
    match code {
        QueryFailureCode::Unauthorized | QueryFailureCode::AuthorizationChanged => {
            ServiceFailure::Unauthorized
        },
        QueryFailureCode::InvalidBudget
        | QueryFailureCode::InvalidCursor
        | QueryFailureCode::SnapshotExpired
        | QueryFailureCode::UnsupportedQuery => ServiceFailure::InvalidRequest,
        QueryFailureCode::BudgetExhausted
        | QueryFailureCode::ResourceAdmissionRefused
        | QueryFailureCode::ResourceExhausted => ServiceFailure::CapacityUnavailable,
        QueryFailureCode::Cancelled => ServiceFailure::Cancelled,
        QueryFailureCode::MalformedPersistentData => ServiceFailure::CorruptState,
        QueryFailureCode::StoreUnavailable => ServiceFailure::StorageUnavailable,
        QueryFailureCode::Internal => ServiceFailure::Internal,
    }
}

pub(super) fn collect_query_bodies(
    events: impl IntoIterator<Item = QueryEvent>,
) -> Result<Vec<String>, ServiceFailure> {
    let mut bodies = Vec::new();
    let mut header_seen = false;
    let mut terminal: Option<Result<(), ServiceFailure>> = None;
    for event in events {
        if terminal.is_some() {
            return Err(ServiceFailure::Internal);
        }
        match event {
            QueryEvent::Header(_) if !header_seen => {
                header_seen = true;
            },
            QueryEvent::Header(_) => return Err(ServiceFailure::Internal),
            QueryEvent::Batch(batch) if header_seen => {
                bodies
                    .try_reserve(batch.records().len())
                    .map_err(|_| ServiceFailure::CapacityUnavailable)?;
                for record in batch.records() {
                    if let Some(body) = record.body_text() {
                        let mut owned = String::new();
                        owned
                            .try_reserve_exact(body.len())
                            .map_err(|_| ServiceFailure::CapacityUnavailable)?;
                        owned.push_str(body);
                        bodies.push(owned);
                    }
                }
            },
            QueryEvent::Batch(_) => return Err(ServiceFailure::Internal),
            QueryEvent::Terminal(QueryTerminal::Complete(_)) if !header_seen => {
                return Err(ServiceFailure::Internal);
            },
            QueryEvent::Terminal(QueryTerminal::Incomplete(_)) if !header_seen => {
                return Err(ServiceFailure::Internal);
            },
            QueryEvent::Terminal(QueryTerminal::Continued(_)) if !header_seen => {
                return Err(ServiceFailure::Internal);
            },
            QueryEvent::Terminal(QueryTerminal::Complete(_)) => terminal = Some(Ok(())),
            QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)) => {
                terminal = Some(Err(map_query_failure_code(incomplete.code())));
            },
            QueryEvent::Terminal(QueryTerminal::Continued(_)) => {
                terminal = Some(Err(ServiceFailure::Internal));
            },
        }
    }
    if !header_seen {
        return Err(ServiceFailure::Internal);
    }
    match terminal {
        Some(Ok(())) => Ok(bodies),
        Some(Err(failure)) => Err(failure),
        None => Err(ServiceFailure::Internal),
    }
}

impl Display for ServiceFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("runtime service request failed")
    }
}

impl Error for ServiceFailure {}

impl ServiceFailure {
    pub(crate) const fn bootstrap_code(self) -> crate::BootstrapFailureCode {
        match self {
            Self::CorruptState => crate::BootstrapFailureCode::CorruptState,
            Self::KeyUnavailable => crate::BootstrapFailureCode::KeyCustodyUnavailable,
            Self::CatalogUnavailable | Self::StorageUnavailable => {
                crate::BootstrapFailureCode::CatalogUnavailable
            },
            Self::LedgerUnavailable => crate::BootstrapFailureCode::LedgerUnavailable,
            Self::Cancelled => crate::BootstrapFailureCode::ResourceUnavailable,
            Self::CapacityUnavailable => crate::BootstrapFailureCode::ResourceUnavailable,
            Self::Unauthorized | Self::RequestTooLarge | Self::InvalidRequest | Self::Internal => {
                crate::BootstrapFailureCode::ResourceUnavailable
            },
        }
    }
}
