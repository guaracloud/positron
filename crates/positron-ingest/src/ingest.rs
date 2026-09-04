use crate::schema_session::SchemaBuildObserver;
use crate::schema_session::{DurableSchemaOutcome, DurableSchemaResolution};
use crate::{IngestPolicy, NativeLogBatch, PolicyEvaluation, TenantSchemaSession};
use positron_domain::identity::{Scope, TenantId};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, AppendCancellation, LedgerCompletionState, ResourceAmounts,
    ResourceDimension, StorageKernelResourceAuthority, StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_signals::LogStore;

mod capacity;
mod entry;
mod failure;
mod outcome;
mod schema_resolution;

use capacity::{group_work_amounts, schema_admission_estimate};
pub(crate) use failure::classify_log_store_failure_code;
use failure::map_ledger_failure;
use outcome::increment_rejection;
pub(crate) use outcome::partial_admission;
pub use outcome::{
    CommittedAdmission, IngestFailureCode, IngestOutcome, PartialAdmission, RejectionDetail,
};
use schema_resolution::{
    RetentionResolution, SchemaCapacityRetention, map_schema_session_failure,
    resolve_after_retention_failure, retain_schema_capacity, rollback_schema,
};

/// Concrete receiver-independent Log ingestion path.
pub struct LogIngest<'service, 'kernel, 'catalog> {
    authority: &'kernel StorageKernelResourceAuthority,
    ledger: &'service ActiveSegmentLedger<'kernel, 'catalog>,
    policy: &'service IngestPolicy,
    tenant: TenantId,
    shard: VirtualShardId,
    schema: TenantSchemaSession,
}

impl<'service, 'kernel, 'catalog> LogIngest<'service, 'kernel, 'catalog> {
    fn accept_inner(
        &self,
        batch: NativeLogBatch<'kernel>,
        identity: StoreBlockIdentity,
        cancellation: Option<&AppendCancellation>,
    ) -> IngestOutcome {
        let (attribution, records, value_profile, capacity, receiver) = batch.into_parts();
        if attribution.scope() != Scope::Ingest || attribution.tenant_id() != self.tenant {
            return IngestOutcome::Permanent(IngestFailureCode::TenantConflict);
        }
        if self.ledger.scope()
            != positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.shard)
        {
            return IngestOutcome::Permanent(IngestFailureCode::InvalidRecord);
        }
        if records.is_empty() {
            return IngestOutcome::Permanent(IngestFailureCode::InvalidRecord);
        }
        if cancellation.is_some_and(AppendCancellation::is_cancelled) {
            return IngestOutcome::Retryable(IngestFailureCode::Cancelled);
        }
        let input_record_count = match u64::try_from(records.len()) {
            Ok(count) => count,
            Err(_) => return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
        };
        let Some(schema_estimate) = schema_admission_estimate(&records) else {
            return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded);
        };
        let Some(group_amounts) =
            group_work_amounts(input_record_count, self.policy.budget(), schema_estimate)
        else {
            return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded);
        };
        let mut capacity = match capacity {
            Some(mut capacity) => {
                if capacity.try_resize(group_amounts).is_err() {
                    return IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable);
                }
                capacity
            },
            None => {
                let claim = match WorkClaim::tenant(self.tenant, WorkKind::Ingest, group_amounts) {
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
        let schema_claim = match ResourceAmounts::only(
            ResourceDimension::MemoryBytes,
            schema_estimate.retained_memory_bytes(),
        )
        .ok()
        .and_then(|amounts| WorkClaim::tenant(self.tenant, WorkKind::Ingest, amounts).ok())
        {
            Some(claim) => claim,
            None => return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
        };
        let schema_capacity = match self.authority.governor().reserve(schema_claim) {
            Ok(capacity) => capacity,
            Err(_) => {
                return IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable);
            },
        };
        let mut accepted = Vec::new();
        let mut accepted_attributes = 0_usize;
        let mut rejection_counts = [0_usize; 3];
        let mut rejection_code = IngestFailureCode::InvalidRecord;
        for candidate in records {
            let evaluated = match self.policy.evaluate(candidate, receiver) {
                Ok(PolicyEvaluation::Accepted(record)) => *record,
                Ok(PolicyEvaluation::Rejected) => {
                    increment_rejection(&mut rejection_counts, IngestFailureCode::PolicyRejected);
                    rejection_code = IngestFailureCode::PolicyRejected;
                    continue;
                },
                Err(_) => return IngestOutcome::Permanent(IngestFailureCode::InvalidRecord),
            };
            let candidate_attributes = match evaluated
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
            match positron_signals::LogRecord::checked_evaluated(value_profile, evaluated) {
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
        let Some(accepted_amounts) =
            group_work_amounts(record_count, self.policy.budget(), schema_estimate)
        else {
            return IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded);
        };
        if capacity.try_resize(accepted_amounts).is_err() {
            return IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable);
        }
        // `capacity` is the admitted ingest-group CPU/task reservation that
        // covers this snapshot's bounded construction work.
        let snapshot = match self.ledger.snapshot() {
            Ok(snapshot) => snapshot,
            Err(failure) => return map_ledger_failure(&failure),
        };
        let schema_observer =
            SchemaBuildObserver::new(schema_estimate.schema_work_units(), cancellation);
        let staged_schema = match self.schema.stage_group_observed(
            self.tenant,
            self.shard,
            identity,
            &snapshot,
            &mut accepted,
            self.authority.governor(),
            &schema_observer,
        ) {
            Ok(staged) => staged,
            Err(failure) => {
                return map_schema_session_failure(failure);
            },
        };
        let staged_bytes = match u64::try_from(staged_schema.staged_memory_bytes()) {
            Ok(bytes) if bytes <= schema_estimate.staging_memory_bytes() => bytes,
            _ => {
                return rollback_schema(
                    &self.schema,
                    identity,
                    self.shard,
                    staged_schema,
                    IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
                    self.authority.governor(),
                );
            },
        };
        let retained_bytes = match u64::try_from(staged_schema.retained_memory_bytes()) {
            Ok(bytes) if bytes <= schema_estimate.retained_memory_bytes() => bytes,
            _ => {
                return rollback_schema(
                    &self.schema,
                    identity,
                    self.shard,
                    staged_schema,
                    IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
                    self.authority.governor(),
                );
            },
        };
        drop(snapshot);
        let preparation = match self.ledger.begin_store_block(capacity, identity) {
            Ok(preparation) => preparation,
            Err(failure) => {
                return rollback_schema(
                    &self.schema,
                    identity,
                    self.shard,
                    staged_schema,
                    map_ledger_failure(&failure),
                    self.authority.governor(),
                );
            },
        };
        let prepared = match LogStore::new().prepare(preparation, accepted) {
            Ok(prepared) => prepared,
            Err(failure) => {
                return rollback_schema(
                    &self.schema,
                    identity,
                    self.shard,
                    staged_schema,
                    classify_log_store_failure_code(failure.code()),
                    self.authority.governor(),
                );
            },
        };
        let block = prepared.into_store_block();
        let block_digest = match block.content_digest() {
            Ok(digest) => digest,
            Err(_) => {
                return rollback_schema(
                    &self.schema,
                    identity,
                    self.shard,
                    staged_schema,
                    IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
                    self.authority.governor(),
                );
            },
        };
        let result = match cancellation {
            Some(cancellation) => self.ledger.append_cancellable(block, cancellation),
            None => self.ledger.append(block),
        };
        match result {
            Ok(receipt) => {
                let retained_capacity =
                    match retain_schema_capacity(schema_capacity, retained_bytes) {
                        SchemaCapacityRetention::Retained(capacity) => capacity,
                        SchemaCapacityRetention::Failed(failure) => {
                            return resolve_after_retention_failure(
                                &self.schema,
                                RetentionResolution {
                                    identity,
                                    shard: self.shard,
                                    staged: staged_schema,
                                    capacity_bytes: retained_bytes,
                                    digest: block_digest,
                                },
                                failure,
                                self.authority.governor(),
                            );
                        },
                    };
                if self
                    .schema
                    .resolve_durable_outcome(
                        DurableSchemaResolution {
                            identity,
                            shard: self.shard,
                            staged: staged_schema,
                            capacity: retained_capacity,
                            capacity_bytes: retained_bytes,
                            outcome: DurableSchemaOutcome::Committed {
                                position: receipt.position(),
                                digest: block_digest,
                            },
                        },
                        self.authority.governor(),
                    )
                    .is_err()
                {
                    return IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable);
                }
                if rejection_counts.iter().all(|count| *count == 0) {
                    IngestOutcome::Full(CommittedAdmission { receipt, records })
                } else {
                    IngestOutcome::Partial(partial_admission(
                        CommittedAdmission { receipt, records },
                        rejection_counts,
                    ))
                }
            },
            Err(failure) => {
                let schema_outcome =
                    if failure.completion_state() == LedgerCompletionState::CommitAmbiguous {
                        DurableSchemaOutcome::Ambiguous {
                            digest: block_digest,
                        }
                    } else {
                        DurableSchemaOutcome::DefiniteFailure
                    };
                let pending_capacity =
                    if matches!(schema_outcome, DurableSchemaOutcome::Ambiguous { .. }) {
                        match retain_schema_capacity(schema_capacity, staged_bytes) {
                            SchemaCapacityRetention::Retained(capacity) => capacity,
                            SchemaCapacityRetention::Failed(failure) => {
                                return resolve_after_retention_failure(
                                    &self.schema,
                                    RetentionResolution {
                                        identity,
                                        shard: self.shard,
                                        staged: staged_schema,
                                        capacity_bytes: staged_bytes,
                                        digest: block_digest,
                                    },
                                    failure,
                                    self.authority.governor(),
                                );
                            },
                        }
                    } else {
                        drop(schema_capacity);
                        None
                    };
                if self
                    .schema
                    .resolve_durable_outcome(
                        DurableSchemaResolution {
                            identity,
                            shard: self.shard,
                            staged: staged_schema,
                            capacity: pending_capacity,
                            capacity_bytes: staged_bytes,
                            outcome: schema_outcome,
                        },
                        self.authority.governor(),
                    )
                    .is_err()
                {
                    return IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable);
                }
                map_ledger_failure(&failure)
            },
        }
    }
}
