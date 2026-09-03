use positron_domain::identity::{Scope, TenantId};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, AppendCancellation, LedgerCompletionState, ResourceAmounts,
    StorageKernelResourceAuthority, StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_signals::{TraceStore, TraceStoreFailureCode};

use crate::ingest::partial_admission;
use crate::{IngestFailureCode, IngestOutcome, NativeSpanBatch};

/// Receiver-independent Trace ingestion.  The Storage Kernel remains the only
/// authority for commit positions and durable visibility.
pub struct TraceIngest<'service, 'kernel, 'catalog> {
    authority: &'kernel StorageKernelResourceAuthority,
    ledger: &'service ActiveSegmentLedger<'kernel, 'catalog>,
    tenant: TenantId,
    shard: VirtualShardId,
}

impl<'service, 'kernel, 'catalog> TraceIngest<'service, 'kernel, 'catalog> {
    #[must_use]
    pub const fn new(
        authority: &'kernel StorageKernelResourceAuthority,
        ledger: &'service ActiveSegmentLedger<'kernel, 'catalog>,
        tenant: TenantId,
        shard: VirtualShardId,
    ) -> Self {
        Self {
            authority,
            ledger,
            tenant,
            shard,
        }
    }

    pub fn accept(
        &self,
        batch: NativeSpanBatch<'kernel>,
        identity: StoreBlockIdentity,
    ) -> IngestOutcome {
        self.accept_inner(batch, identity, None)
    }

    pub fn accept_cancellable(
        &self,
        batch: NativeSpanBatch<'kernel>,
        identity: StoreBlockIdentity,
        cancellation: &AppendCancellation,
    ) -> IngestOutcome {
        self.accept_inner(batch, identity, Some(cancellation))
    }

    fn accept_inner(
        &self,
        batch: NativeSpanBatch<'kernel>,
        identity: StoreBlockIdentity,
        cancellation: Option<&AppendCancellation>,
    ) -> IngestOutcome {
        let rejections = batch.rejections();
        let (attribution, records, profile, incoming_capacity, _receiver) = batch.into_parts();
        if attribution.scope() != Scope::Ingest || attribution.tenant_id() != self.tenant {
            return IngestOutcome::Permanent(IngestFailureCode::TenantConflict);
        }
        if self.ledger.scope()
            != positron_kernel::SegmentScope::new(self.tenant, SignalKind::Traces, self.shard)
        {
            return IngestOutcome::Permanent(IngestFailureCode::InvalidRecord);
        }
        if records.is_empty() {
            return IngestOutcome::Permanent(IngestFailureCode::InvalidRecord);
        }
        if cancellation.is_some_and(AppendCancellation::is_cancelled) {
            return IngestOutcome::Retryable(IngestFailureCode::Cancelled);
        }
        let record_count = match u64::try_from(records.len()) {
            Ok(value) => value,
            Err(_) => return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
        };
        let memory = match records.iter().try_fold(0_u64, |total, record| {
            let native = u64::try_from(std::mem::size_of::<positron_signals::SpanObservation>())
                .map_err(|_| ())?;
            let heap = record.retained_heap_bytes().map_err(|_| ())?;
            let heap = u64::try_from(heap).map_err(|_| ())?;
            total
                .checked_add(native)
                .and_then(|size| size.checked_add(heap))
                .ok_or(())
        }) {
            // The kernel's Store Block preparation contract has a fixed
            // 1 MiB floor. Retain the exact native/detail charge above that
            // floor so admission remains conservative without weakening the
            // kernel authorization check.
            Ok(value) => value.max(1_048_576),
            Err(()) => return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
        };
        let amounts = ResourceAmounts::new([
            memory,
            0,
            0,
            0,
            record_count,
            0,
            0,
            0,
            record_count,
            0,
            1_048_576,
        ]);
        let capacity = match incoming_capacity {
            Some(mut reservation) => {
                if reservation.try_resize(amounts).is_err() {
                    return IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable);
                }
                reservation
            },
            None => {
                let claim = match WorkClaim::tenant(self.tenant, WorkKind::Ingest, amounts) {
                    Ok(claim) => claim,
                    Err(_) => {
                        return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded);
                    },
                };
                match self.authority.governor().reserve(claim) {
                    Ok(reservation) => reservation,
                    Err(_) => {
                        return IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable);
                    },
                }
            },
        };
        let prepared = match self.ledger.begin_store_block(capacity, identity) {
            Ok(preparation) => {
                match TraceStore::new().prepare_with_profile(&profile, preparation, records) {
                    Ok(prepared) => prepared,
                    Err(failure) => {
                        return classify_store_failure(failure.code());
                    },
                }
            },
            Err(failure) => {
                return classify_ledger_failure(&failure);
            },
        };
        let append = match cancellation {
            Some(cancellation) => self
                .ledger
                .append_cancellable(prepared.into_store_block(), cancellation),
            None => self.ledger.append(prepared.into_store_block()),
        };
        match append {
            Ok(receipt) => match usize::try_from(record_count) {
                Ok(records) => {
                    let committed = crate::CommittedAdmission::new(receipt, records);
                    if rejections.into_iter().any(|count| count > 0) {
                        IngestOutcome::Partial(partial_admission(committed, rejections))
                    } else {
                        IngestOutcome::Full(committed)
                    }
                },
                Err(_) => IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable),
            },
            Err(failure) => classify_ledger_failure(&failure),
        }
    }
}

fn classify_store_failure(code: TraceStoreFailureCode) -> IngestOutcome {
    match code {
        TraceStoreFailureCode::InvalidInput
        | TraceStoreFailureCode::MalformedBlock
        | TraceStoreFailureCode::PhysicalScopeMismatch => {
            IngestOutcome::Permanent(IngestFailureCode::InvalidRecord)
        },
        TraceStoreFailureCode::LimitExceeded => {
            IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded)
        },
        TraceStoreFailureCode::Cancelled => IngestOutcome::Retryable(IngestFailureCode::Cancelled),
        _ => IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
    }
}

fn classify_ledger_failure(failure: &positron_kernel::LedgerFailure) -> IngestOutcome {
    let code = match failure.code() {
        positron_kernel::LedgerFailureCode::InvalidInput
        | positron_kernel::LedgerFailureCode::PhysicalScopeMismatch => {
            IngestFailureCode::InvalidRecord
        },
        positron_kernel::LedgerFailureCode::LimitExceeded => IngestFailureCode::ValueLimitExceeded,
        positron_kernel::LedgerFailureCode::IdempotencyConflict => {
            IngestFailureCode::IdempotencyConflict
        },
        positron_kernel::LedgerFailureCode::Cancelled => IngestFailureCode::Cancelled,
        _ => IngestFailureCode::StorageUnavailable,
    };
    match failure.completion_state() {
        LedgerCompletionState::CommitAmbiguous => IngestOutcome::Ambiguous(code),
        LedgerCompletionState::RejectedBeforeMutation => {
            if matches!(
                code,
                IngestFailureCode::InvalidRecord
                    | IngestFailureCode::ValueLimitExceeded
                    | IngestFailureCode::IdempotencyConflict
            ) {
                IngestOutcome::Permanent(code)
            } else {
                IngestOutcome::Retryable(code)
            }
        },
        LedgerCompletionState::RecoveryRequired => IngestOutcome::Retryable(code),
    }
}
