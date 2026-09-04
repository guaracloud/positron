use positron_ingest::{IngestFailureCode, IngestOutcome};

use crate::ServiceFailure;

/// Signal-neutral classification shared by the OTLP protocol adapters.
///
/// The HTTP and gRPC adapters still own their response constructors, but the
/// status and message mapping must remain identical for the same signal and
/// outcome. Keeping that mapping here prevents the two protocol surfaces from
/// drifting while retaining their distinct wire representations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OtlpSignal {
    Logs,
    Traces,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OtlpFailure {
    pub(super) http_status: u16,
    pub(super) grpc_code: i32,
    pub(super) message: &'static str,
    pub(super) retry_after: bool,
}

impl OtlpSignal {
    pub(super) const fn authentication_rejected(self) -> OtlpFailure {
        OtlpFailure {
            http_status: 401,
            grpc_code: 16,
            message: match self {
                Self::Logs => "OTLP Logs request authentication was rejected",
                Self::Traces => "OTLP Traces request authentication was rejected",
            },
            retry_after: false,
        }
    }

    pub(super) const fn outcome_failure(self, outcome: IngestOutcome) -> OtlpFailure {
        match outcome {
            IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable) => OtlpFailure {
                http_status: 429,
                grpc_code: 8,
                message: match self {
                    Self::Logs => "OTLP Logs ingest capacity is unavailable",
                    Self::Traces => "OTLP Traces ingest capacity is unavailable",
                },
                retry_after: true,
            },
            IngestOutcome::Retryable(_) => OtlpFailure {
                http_status: 503,
                grpc_code: 14,
                message: match self {
                    Self::Logs => "OTLP Logs ingest is temporarily unavailable",
                    Self::Traces => "OTLP Traces ingest is temporarily unavailable",
                },
                retry_after: false,
            },
            IngestOutcome::Permanent(_) => OtlpFailure {
                http_status: 400,
                grpc_code: 3,
                message: match self {
                    Self::Logs => "OTLP Logs request was rejected",
                    Self::Traces => "OTLP Traces request was rejected",
                },
                retry_after: false,
            },
            IngestOutcome::Ambiguous(_) => OtlpFailure {
                http_status: 503,
                grpc_code: 14,
                message: match self {
                    Self::Logs => {
                        "OTLP Logs commit outcome is ambiguous; retry may duplicate records"
                    },
                    Self::Traces => {
                        "OTLP Traces commit outcome is ambiguous; retry may duplicate spans"
                    },
                },
                retry_after: false,
            },
            IngestOutcome::Full(_) | IngestOutcome::Partial(_) => OtlpFailure {
                http_status: 500,
                grpc_code: 13,
                message: match self {
                    Self::Logs => "OTLP Logs outcome aggregation failed",
                    Self::Traces => "OTLP Traces outcome aggregation failed",
                },
                retry_after: false,
            },
        }
    }

    pub(super) const fn service_failure(self, service_failure: ServiceFailure) -> OtlpFailure {
        match service_failure {
            ServiceFailure::Unauthorized => self.authentication_rejected(),
            ServiceFailure::CapacityUnavailable => OtlpFailure {
                http_status: 429,
                grpc_code: 8,
                message: match self {
                    Self::Logs => "OTLP Logs ingest capacity is unavailable",
                    Self::Traces => "OTLP Traces ingest capacity is unavailable",
                },
                retry_after: true,
            },
            ServiceFailure::RequestTooLarge => OtlpFailure {
                http_status: 413,
                grpc_code: 8,
                message: match self {
                    Self::Logs => "OTLP Logs request exceeds the receiver limit",
                    Self::Traces => "OTLP Traces request exceeds the receiver limit",
                },
                retry_after: false,
            },
            ServiceFailure::InvalidRequest => OtlpFailure {
                http_status: 400,
                grpc_code: 3,
                message: match self {
                    Self::Logs => "OTLP Logs request was rejected",
                    Self::Traces => "OTLP Traces request was rejected",
                },
                retry_after: false,
            },
            ServiceFailure::KeyUnavailable
            | ServiceFailure::CatalogUnavailable
            | ServiceFailure::LedgerUnavailable
            | ServiceFailure::StorageUnavailable => OtlpFailure {
                http_status: 503,
                grpc_code: 14,
                message: match self {
                    Self::Logs => "OTLP Logs ingest is temporarily unavailable",
                    Self::Traces => "OTLP Traces ingest is temporarily unavailable",
                },
                retry_after: false,
            },
            ServiceFailure::CorruptState | ServiceFailure::Internal | ServiceFailure::Cancelled => {
                OtlpFailure {
                    http_status: 500,
                    grpc_code: 13,
                    message: match self {
                        Self::Logs => "OTLP Logs ingest failed",
                        Self::Traces => "OTLP Traces ingest failed",
                    },
                    retry_after: false,
                }
            },
        }
    }
}
