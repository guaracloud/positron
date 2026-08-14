use positron_domain::identity::{Scope, TenantId};
use positron_domain::routing::VirtualShardId;
use positron_kernel::{
    ActiveSegmentLedger, AppendCancellation, CommitReceipt, LifecycleClock, LifecycleClockSource,
    ResourceAmounts, StorageKernelResourceAuthority, StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_signals::LogStore;

use crate::policy::PolicyDecision;
use crate::{IngestPolicy, NativeLogBatch};

mod failure;

pub(crate) use failure::classify_log_store_failure_code;
use failure::map_ledger_failure;

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
    pub fn accept(
        &self,
        batch: NativeLogBatch<'kernel>,
        identity: StoreBlockIdentity,
    ) -> IngestOutcome {
        self.accept_inner(batch, identity, None)
    }

    /// Observes cancellation before durability admission without fabricating a
    /// failed outcome after a commit boundary.
    #[must_use]
    pub fn accept_cancellable(
        &self,
        batch: NativeLogBatch<'kernel>,
        identity: StoreBlockIdentity,
        cancellation: &AppendCancellation,
    ) -> IngestOutcome {
        self.accept_inner(batch, identity, Some(cancellation))
    }

    fn accept_inner(
        &self,
        batch: NativeLogBatch<'kernel>,
        identity: StoreBlockIdentity,
        cancellation: Option<&AppendCancellation>,
    ) -> IngestOutcome {
        let (attribution, records, value_profile, capacity) = batch.into_parts();
        if attribution.scope() != Scope::Ingest || attribution.tenant_id() != self.tenant {
            return IngestOutcome::Permanent(IngestFailureCode::TenantConflict);
        }
        if records.is_empty() {
            return IngestOutcome::Permanent(IngestFailureCode::InvalidRecord);
        }
        let mut accepted = Vec::new();
        let mut accepted_attributes = 0_usize;
        let mut rejection_counts = [0_usize; 3];
        let mut rejection_code = IngestFailureCode::InvalidRecord;
        for candidate in records {
            let policy = match self.policy.evaluate(&candidate) {
                Ok(PolicyDecision::Accept(policy)) => policy,
                Ok(PolicyDecision::Reject) => {
                    increment_rejection(&mut rejection_counts, IngestFailureCode::PolicyRejected);
                    rejection_code = IngestFailureCode::PolicyRejected;
                    continue;
                },
                Err(failure) => return classify_log_store_failure_code(failure.code()),
            };
            let candidate_attributes = match candidate
                .attributes()
                .iter()
                .try_fold(0_usize, |total, attribute| {
                    total.checked_add(attribute.occurrences().len())
                }) {
                Some(count) => count,
                None => {
                    return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded);
                },
            };
            let (event_time, observed_time, body, attributes, metadata) = candidate.into_parts();
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
            match positron_signals::LogRecord::checked_receiver_candidate_with_metadata(
                value_profile,
                event_time,
                observed_time,
                body,
                attributes,
                metadata,
                policy,
            ) {
                Ok(record) => {
                    accepted_attributes = match accepted_attributes
                        .checked_add(candidate_attributes)
                    {
                        Some(count) => count,
                        None => {
                            return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded);
                        },
                    };
                    accepted.push(record);
                },
                Err(failure) => match classify_log_store_failure_code(failure.code()) {
                    IngestOutcome::Permanent(code) => {
                        rejection_code = code;
                        increment_rejection(&mut rejection_counts, rejection_code);
                    },
                    other => return other,
                },
            }
        }
        let maximum_records =
            match usize::try_from(value_profile.effective_limits().request().records().value()) {
                Ok(limit) => limit,
                Err(_) => {
                    return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded);
                },
            };
        if accepted.len() > maximum_records {
            return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded);
        }
        let maximum_attributes = match usize::try_from(
            value_profile
                .effective_limits()
                .request()
                .aggregate_attributes()
                .value(),
        ) {
            Ok(limit) => limit,
            Err(_) => {
                return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded);
            },
        };
        if accepted_attributes > maximum_attributes {
            return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded);
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
        let capacity = match capacity {
            Some(mut capacity) => {
                if capacity.try_resize(amounts).is_err() {
                    return IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable);
                }
                capacity
            },
            None => {
                let claim = match WorkClaim::tenant(self.tenant, WorkKind::Ingest, amounts) {
                    Ok(claim) => claim,
                    Err(_) => {
                        return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded);
                    },
                };
                match self.authority.governor().reserve(claim) {
                    Ok(capacity) => capacity,
                    Err(_) => {
                        return IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable);
                    },
                }
            },
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
            Err(failure) => return classify_log_store_failure_code(failure.code()),
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
