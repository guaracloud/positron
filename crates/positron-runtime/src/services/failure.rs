use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_ingest::{AdmissionGroupPlanFailure, ReceiveFailure};
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
    let mut complete = false;
    let mut terminal_seen = false;
    for event in events {
        match event {
            QueryEvent::Header(_) if !terminal_seen => {},
            QueryEvent::Header(_) => return Err(ServiceFailure::Internal),
            QueryEvent::Batch(batch) if !terminal_seen => {
                bodies
                    .try_reserve(batch.records().len())
                    .map_err(|_| ServiceFailure::CapacityUnavailable)?;
                for record in batch.records() {
                    if let Some(body) = record.body_text() {
                        bodies.push(body.to_owned());
                    }
                }
            },
            QueryEvent::Batch(_) => return Err(ServiceFailure::Internal),
            QueryEvent::Terminal(QueryTerminal::Complete(_)) if !terminal_seen => {
                terminal_seen = true;
                complete = true;
            },
            QueryEvent::Terminal(QueryTerminal::Complete(_)) => {
                return Err(ServiceFailure::Internal);
            },
            QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)) => {
                return Err(map_query_failure_code(incomplete.code()));
            },
            QueryEvent::Terminal(QueryTerminal::Continued(_)) => {
                return Err(ServiceFailure::InvalidRequest);
            },
        }
    }
    if complete {
        Ok(bodies)
    } else {
        Err(ServiceFailure::Internal)
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
