use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_ingest::{AdmissionGroupPlanFailure, ReceiveFailure};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceFailure {
    Unauthorized,
    CapacityUnavailable,
    RequestTooLarge,
    InvalidRequest,
    KeyUnavailable,
    StorageUnavailable,
    Internal,
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

impl Display for ServiceFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("runtime service request failed")
    }
}

impl Error for ServiceFailure {}
