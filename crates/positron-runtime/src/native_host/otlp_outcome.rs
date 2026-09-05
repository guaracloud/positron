use positron_ingest::{
    IngestFailureCode, IngestOutcome, TraceLimitRejectionSummary, TraceLimitViolation,
    TraceReceiveFailure,
};
use std::fmt::Write as _;

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
    pub(super) limit: Option<TraceLimitViolation>,
    pub(super) retry_after: bool,
}

impl OtlpFailure {
    pub(super) fn rendered_message(self) -> String {
        match self.limit {
            Some(limit) => format!(
                "{} ({}: actual {}, allowed {})",
                self.message,
                limit.class().label(),
                limit.actual(),
                limit.allowed(),
            ),
            None => self.message.to_owned(),
        }
    }
}

impl OtlpSignal {
    pub(super) fn trace_partial_message(summary: TraceLimitRejectionSummary) -> Result<String, ()> {
        const PREFIX: &str = "some spans were permanently rejected";
        if summary.is_empty() {
            return Ok(PREFIX.to_owned());
        }
        let details_capacity = summary.iter().try_fold(0_usize, |capacity, violation| {
            capacity
                .checked_add(violation.class().label().len())
                .and_then(|capacity| capacity.checked_add(2 + 20 + 10 + 20 + 2))
        });
        let details_capacity = details_capacity.ok_or(())?;
        let capacity = PREFIX
            .len()
            .checked_add(2)
            .and_then(|capacity| capacity.checked_add(details_capacity))
            .ok_or(())?;
        let mut message = String::new();
        message.try_reserve(capacity).map_err(|_| ())?;
        message.write_str(PREFIX).map_err(|_| ())?;
        message.write_str(" (").map_err(|_| ())?;
        for (index, violation) in summary.iter().enumerate() {
            if index > 0 {
                message.write_str("; ").map_err(|_| ())?;
            }
            write!(
                message,
                "{}: actual {}, allowed {}",
                violation.class().label(),
                violation.actual(),
                violation.allowed(),
            )
            .map_err(|_| ())?;
        }
        message.write_char(')').map_err(|_| ())?;
        Ok(message)
    }

    pub(super) const fn receive_failure(self, failure: TraceReceiveFailure) -> OtlpFailure {
        match failure {
            TraceReceiveFailure::AuthenticationRejected => self.authentication_rejected(),
            TraceReceiveFailure::CapacityUnavailable => {
                self.service_failure(ServiceFailure::CapacityUnavailable)
            },
            TraceReceiveFailure::TransportLimitExceeded => {
                self.service_failure(ServiceFailure::RequestTooLarge)
            },
            TraceReceiveFailure::MalformedCompression | TraceReceiveFailure::MalformedPayload => {
                OtlpFailure {
                    http_status: 400,
                    grpc_code: 3,
                    message: match self {
                        Self::Logs => "OTLP Logs request was malformed",
                        Self::Traces => "OTLP Traces request was malformed",
                    },
                    limit: None,
                    retry_after: false,
                }
            },
            TraceReceiveFailure::ValueLimitExceededWithDetail(detail) => {
                self.limit_exceeded(detail)
            },
            TraceReceiveFailure::PolicyEvaluationFailed
            | TraceReceiveFailure::ValueLimitExceeded
            | TraceReceiveFailure::TimestampOutOfRange
            | TraceReceiveFailure::UnsupportedValue => {
                self.service_failure(ServiceFailure::InvalidRequest)
            },
        }
    }

    const fn limit_exceeded(self, detail: TraceLimitViolation) -> OtlpFailure {
        OtlpFailure {
            http_status: 400,
            grpc_code: 3,
            message: match self {
                Self::Logs => "OTLP Logs request exceeded a value limit",
                Self::Traces => "OTLP Traces request exceeded a value limit",
            },
            limit: Some(detail),
            retry_after: false,
        }
    }

    pub(super) const fn authentication_rejected(self) -> OtlpFailure {
        OtlpFailure {
            http_status: 401,
            grpc_code: 16,
            message: match self {
                Self::Logs => "OTLP Logs request authentication was rejected",
                Self::Traces => "OTLP Traces request authentication was rejected",
            },
            limit: None,
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
                limit: None,
                retry_after: true,
            },
            IngestOutcome::Retryable(_) => OtlpFailure {
                http_status: 503,
                grpc_code: 14,
                message: match self {
                    Self::Logs => "OTLP Logs ingest is temporarily unavailable",
                    Self::Traces => "OTLP Traces ingest is temporarily unavailable",
                },
                limit: None,
                retry_after: false,
            },
            IngestOutcome::Permanent(_) => OtlpFailure {
                http_status: 400,
                grpc_code: 3,
                message: match self {
                    Self::Logs => "OTLP Logs request was rejected",
                    Self::Traces => "OTLP Traces request was rejected",
                },
                limit: None,
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
                limit: None,
                retry_after: false,
            },
            IngestOutcome::Full(_) | IngestOutcome::Partial(_) => OtlpFailure {
                http_status: 500,
                grpc_code: 13,
                message: match self {
                    Self::Logs => "OTLP Logs outcome aggregation failed",
                    Self::Traces => "OTLP Traces outcome aggregation failed",
                },
                limit: None,
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
                limit: None,
                retry_after: true,
            },
            ServiceFailure::RequestTooLarge => OtlpFailure {
                http_status: 413,
                grpc_code: 8,
                message: match self {
                    Self::Logs => "OTLP Logs request exceeds the receiver limit",
                    Self::Traces => "OTLP Traces request exceeds the receiver limit",
                },
                limit: None,
                retry_after: false,
            },
            ServiceFailure::InvalidRequest => OtlpFailure {
                http_status: 400,
                grpc_code: 3,
                message: match self {
                    Self::Logs => "OTLP Logs request was rejected",
                    Self::Traces => "OTLP Traces request was rejected",
                },
                limit: None,
                retry_after: false,
            },
            ServiceFailure::InvalidRequestWithLimit(detail) => self.limit_exceeded(detail),
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
                limit: None,
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
                    limit: None,
                    retry_after: false,
                }
            },
        }
    }
}
