use positron_domain::identity::{Scope, TenantId};
use positron_domain::routing::VirtualShardId;
use positron_kernel::{
    ActiveSegmentLedger, AppendCancellation, CommitReceipt, LedgerCompletionState, LedgerFailure,
    LedgerFailureCode, LifecycleClock, LifecycleClockSource, ResourceAmounts,
    StorageKernelResourceAuthority, StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_signals::{LogStore, LogStoreFailure, LogStoreFailureCode};

use crate::policy::PolicyDecision;
use crate::{IngestPolicy, NativeLogBatch};

/// One independently committed Admission Group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedAdmission {
    receipt: CommitReceipt,
    records: usize,
}

/// A durable accepted subset plus explicit permanent rejections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartialAdmission {
    committed: CommittedAdmission,
    rejections: [RejectionDetail; 3],
    rejection_class_count: u8,
}

/// One deterministic permanent-rejection class and its bounded record count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RejectionDetail {
    code: IngestFailureCode,
    records: usize,
}

impl RejectionDetail {
    const EMPTY: Self = Self {
        code: IngestFailureCode::PolicyRejected,
        records: 0,
    };

    #[must_use]
    pub const fn code(self) -> IngestFailureCode {
        self.code
    }

    #[must_use]
    pub const fn records(self) -> usize {
        self.records
    }
}

impl PartialAdmission {
    #[must_use]
    pub const fn committed(self) -> CommittedAdmission {
        self.committed
    }

    #[must_use]
    pub fn permanently_rejected(self) -> usize {
        self.rejections().iter().map(|detail| detail.records).sum()
    }

    #[must_use]
    pub fn rejections(&self) -> &[RejectionDetail] {
        self.rejections
            .get(..usize::from(self.rejection_class_count))
            .unwrap_or_default()
    }
}

impl CommittedAdmission {
    #[must_use]
    pub const fn receipt(self) -> CommitReceipt {
        self.receipt
    }

    #[must_use]
    pub const fn records(self) -> usize {
        self.records
    }
}

/// Stable secret-free failure classes at the native ingest seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestFailureCode {
    TenantConflict,
    PolicyRejected,
    InvalidRecord,
    ValueLimitExceeded,
    CapacityUnavailable,
    StorageUnavailable,
    Cancelled,
    IdempotencyConflict,
}

/// Complete outcome for one independently admitted group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestOutcome {
    Full(CommittedAdmission),
    Partial(PartialAdmission),
    Retryable(IngestFailureCode),
    Permanent(IngestFailureCode),
    Ambiguous(IngestFailureCode),
}

impl IngestOutcome {
    /// Converts only a known post-commit producer disconnect into explicit
    /// ambiguity. Pre-commit failures retain their original classification.
    #[must_use]
    pub const fn producer_disconnected_after_commit(self) -> Self {
        match self {
            Self::Full(_) | Self::Partial(_) => {
                Self::Ambiguous(IngestFailureCode::StorageUnavailable)
            },
            other => other,
        }
    }
}

/// Concrete receiver-independent Log ingestion path.
pub struct LogIngest<'service, 'kernel, 'catalog, S> {
    authority: &'kernel StorageKernelResourceAuthority,
    ledger: &'service ActiveSegmentLedger<'kernel, 'catalog>,
    clock: &'service LifecycleClock<S>,
    policy: &'service IngestPolicy,
    tenant: TenantId,
    shard: VirtualShardId,
}

impl<'service, 'kernel, 'catalog, S: LifecycleClockSource>
    LogIngest<'service, 'kernel, 'catalog, S>
{
    #[must_use]
    pub const fn new(
        authority: &'kernel StorageKernelResourceAuthority,
        ledger: &'service ActiveSegmentLedger<'kernel, 'catalog>,
        clock: &'service LifecycleClock<S>,
        policy: &'service IngestPolicy,
        tenant: TenantId,
        shard: VirtualShardId,
    ) -> Self {
        Self {
            authority,
            ledger,
            clock,
            policy,
            tenant,
            shard,
        }
    }

    /// Validates, reserves, prepares, and durably commits one Admission Group.
    #[must_use]
    pub fn accept(&self, batch: NativeLogBatch, identity: StoreBlockIdentity) -> IngestOutcome {
        self.accept_inner(batch, identity, None)
    }

    /// Observes cancellation before durability admission without fabricating a
    /// failed outcome after a commit boundary.
    #[must_use]
    pub fn accept_cancellable(
        &self,
        batch: NativeLogBatch,
        identity: StoreBlockIdentity,
        cancellation: &AppendCancellation,
    ) -> IngestOutcome {
        self.accept_inner(batch, identity, Some(cancellation))
    }

    fn accept_inner(
        &self,
        batch: NativeLogBatch,
        identity: StoreBlockIdentity,
        cancellation: Option<&AppendCancellation>,
    ) -> IngestOutcome {
        let attribution = batch.attribution();
        if attribution.scope() != Scope::Ingest || attribution.tenant_id() != self.tenant {
            return IngestOutcome::Permanent(IngestFailureCode::TenantConflict);
        }
        if batch.records().is_empty() {
            return IngestOutcome::Permanent(IngestFailureCode::InvalidRecord);
        }
        let mut accepted = Vec::new();
        let mut rejection_counts = [0_usize; 3];
        let mut rejection_code = IngestFailureCode::InvalidRecord;
        for candidate in batch.into_records() {
            let policy = match self.policy.evaluate(&candidate) {
                Ok(PolicyDecision::Accept(policy)) => policy,
                Ok(PolicyDecision::Reject) => {
                    increment_rejection(&mut rejection_counts, IngestFailureCode::PolicyRejected);
                    rejection_code = IngestFailureCode::PolicyRejected;
                    continue;
                },
                Err(failure) => return map_store_failure(&failure),
            };
            let (event_time, observed_time, body, attributes) = candidate.into_parts();
            let attributes = attributes
                .into_iter()
                .map(|attribute| {
                    positron_domain::value::AttributeOccurrenceSetCandidate::new(
                        attribute.namespace(),
                        attribute.key().to_owned(),
                        attribute.occurrences().to_vec(),
                    )
                })
                .collect();
            match positron_signals::LogRecord::checked_receiver_candidate(
                event_time,
                observed_time,
                body,
                attributes,
                policy,
            ) {
                Ok(record) => accepted.push(record),
                Err(failure) => {
                    rejection_code = match failure.code() {
                        LogStoreFailureCode::LimitExceeded => IngestFailureCode::ValueLimitExceeded,
                        _ => IngestFailureCode::InvalidRecord,
                    };
                    increment_rejection(&mut rejection_counts, rejection_code);
                },
            }
        }
        if accepted.is_empty() {
            return IngestOutcome::Permanent(rejection_code);
        }
        let records = accepted.len();
        let record_count = match u64::try_from(records) {
            Ok(count) => count,
            Err(_) => return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
        };
        let amounts = ResourceAmounts::new([
            1_048_576,
            1,
            1,
            1_048_576,
            record_count,
            0,
            1,
            1,
            1,
            4,
            1_048_576,
        ]);
        let claim = match WorkClaim::tenant(self.tenant, WorkKind::Ingest, amounts) {
            Ok(claim) => claim,
            Err(_) => return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
        };
        let capacity = match self.authority.governor().reserve(claim) {
            Ok(capacity) => capacity,
            Err(_) => return IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable),
        };
        let prepared = match LogStore::new().prepare(
            capacity,
            self.clock,
            self.tenant,
            self.shard,
            identity,
            accepted,
        ) {
            Ok(prepared) => prepared,
            Err(failure) => return map_store_failure(&failure),
        };
        let block = prepared.into_store_block();
        let result = match cancellation {
            Some(cancellation) => self.ledger.append_cancellable(block, cancellation),
            None => self.ledger.append(block),
        };
        match result {
            Ok(receipt) if rejection_counts.iter().all(|count| *count == 0) => {
                IngestOutcome::Full(CommittedAdmission { receipt, records })
            },
            Ok(receipt) => IngestOutcome::Partial(partial_admission(
                CommittedAdmission { receipt, records },
                rejection_counts,
            )),
            Err(failure) => map_ledger_failure(&failure),
        }
    }
}

fn increment_rejection(counts: &mut [usize; 3], code: IngestFailureCode) {
    let index = match code {
        IngestFailureCode::PolicyRejected => 0,
        IngestFailureCode::InvalidRecord => 1,
        IngestFailureCode::ValueLimitExceeded => 2,
        _ => return,
    };
    if let Some(count) = counts.get_mut(index) {
        *count = count.saturating_add(1);
    }
}

fn partial_admission(committed: CommittedAdmission, counts: [usize; 3]) -> PartialAdmission {
    let codes = [
        IngestFailureCode::PolicyRejected,
        IngestFailureCode::InvalidRecord,
        IngestFailureCode::ValueLimitExceeded,
    ];
    let mut rejections = [RejectionDetail::EMPTY; 3];
    let mut used = 0_u8;
    for (code, records) in codes.into_iter().zip(counts) {
        if records > 0
            && let Some(detail) = rejections.get_mut(usize::from(used))
        {
            *detail = RejectionDetail { code, records };
            used = used.saturating_add(1);
        }
    }
    PartialAdmission {
        committed,
        rejections,
        rejection_class_count: used,
    }
}

fn map_store_failure(failure: &LogStoreFailure) -> IngestOutcome {
    match failure.code() {
        LogStoreFailureCode::InvalidInput
        | LogStoreFailureCode::MalformedBlock
        | LogStoreFailureCode::PhysicalScopeMismatch => {
            IngestOutcome::Permanent(IngestFailureCode::InvalidRecord)
        },
        LogStoreFailureCode::LimitExceeded => {
            IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded)
        },
        LogStoreFailureCode::ResourceExhausted
        | LogStoreFailureCode::ClockUnavailable
        | LogStoreFailureCode::ResourceAdmissionRefused => {
            IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
        },
        LogStoreFailureCode::Kernel => {
            IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable)
        },
    }
}

fn map_ledger_failure(failure: &LedgerFailure) -> IngestOutcome {
    let code = match failure.code() {
        LedgerFailureCode::Cancelled => IngestFailureCode::Cancelled,
        LedgerFailureCode::IdempotencyConflict => IngestFailureCode::IdempotencyConflict,
        LedgerFailureCode::LimitExceeded => IngestFailureCode::ValueLimitExceeded,
        LedgerFailureCode::InvalidInput | LedgerFailureCode::PhysicalScopeMismatch => {
            IngestFailureCode::InvalidRecord
        },
        LedgerFailureCode::ResourceAdmissionRefused => IngestFailureCode::CapacityUnavailable,
        LedgerFailureCode::StorageUnavailable
        | LedgerFailureCode::StorageExhausted
        | LedgerFailureCode::IntegrityCorruption
        | LedgerFailureCode::AuthenticationFailed
        | LedgerFailureCode::ConcurrentWriter
        | LedgerFailureCode::UnsupportedFormat
        | LedgerFailureCode::StaleGeneration
        | LedgerFailureCode::RecoveryRequired => IngestFailureCode::StorageUnavailable,
    };
    match failure.completion_state() {
        LedgerCompletionState::CommitAmbiguous => IngestOutcome::Ambiguous(code),
        LedgerCompletionState::RecoveryRequired => IngestOutcome::Retryable(code),
        LedgerCompletionState::RejectedBeforeMutation => match failure.code() {
            LedgerFailureCode::InvalidInput
            | LedgerFailureCode::PhysicalScopeMismatch
            | LedgerFailureCode::LimitExceeded
            | LedgerFailureCode::IdempotencyConflict => IngestOutcome::Permanent(code),
            _ => IngestOutcome::Retryable(code),
        },
    }
}
