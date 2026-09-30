//! Immutable Compaction task authority and its bounded PMTC footprint.

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::{MaintenanceCheckpoint, MaintenanceFailure, MaintenanceScope};
use crate::CatalogLogRetentionPolicy;

const COMPACTION_BINDING_MAGIC: &[u8; 8] = b"CMPBND01";
const COMPACTION_BINDING_BYTES: usize = 8 + 16 + 1 + 4 + 32 + 8 + 8 + 8 + 32;

/// Returns the exact Catalog payload footprint of the initial durable
/// Compaction record. The ledger reserves this before it submits the task, so
/// the task's own queued-to-running PMTC replacement cannot invalidate its
/// otherwise unchanged resource claim.
pub(crate) fn compaction_task_record_bytes(
    inputs: usize,
    binding: CompactionBinding,
) -> Result<usize, MaintenanceFailure> {
    if inputs == 0 || inputs > super::MAX_TASK_OBJECTS {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let checkpoint = binding.checkpoint()?;
    let scope_bytes = match binding.scope() {
        MaintenanceScope::System => 1_usize,
        MaintenanceScope::Tenant(_) | MaintenanceScope::Segment { .. } => 22,
    };
    // This is the serialized payload length, not Vec's conservative reserve
    // capacity. The ledger charges Catalog payload ownership precisely.
    8_usize
        .checked_add(16 + 1 + scope_bytes + 1 + 1 + 1 + 8 + 8 + 8 + 1 + 1)
        .and_then(|bytes| bytes.checked_add(inputs.checked_mul(32)?))
        .and_then(|bytes| bytes.checked_add(11 * 8 + 1 + 8 + 1 + 8 + 1 + 8 + 1))
        .and_then(|bytes| bytes.checked_add(8 + 4 + 4 + checkpoint.opaque_progress.len()))
        .ok_or(MaintenanceFailure::CapacityExceeded)
}

/// The conservative allocation held while the handler encodes the terminal
/// PMTC replacement. This is distinct from the serialized Catalog payload:
/// the `Vec` reserve capacity remains live until publication completes.
pub(crate) fn compaction_task_record_working_bytes(
    inputs: usize,
    binding: CompactionBinding,
) -> Result<usize, MaintenanceFailure> {
    if inputs == 0 || inputs > super::MAX_TASK_OBJECTS {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let checkpoint = binding.checkpoint()?;
    super::record::encoded_record_capacity(inputs, 0, checkpoint.opaque_progress.len())
}

/// Immutable source authority for one Compaction task. It is persisted before
/// dispatch rather than inferred from a later Catalog generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionBinding {
    scope: MaintenanceScope,
    policy_object: [u8; 32],
    retention_seconds: u64,
    bucket_start: i64,
    bucket_end_exclusive: i64,
    source_digest: [u8; 32],
}

impl CompactionBinding {
    pub fn new(
        scope: MaintenanceScope,
        policy: CatalogLogRetentionPolicy,
        bucket: crate::RetentionBucket,
        source_digest: [u8; 32],
    ) -> Result<Self, MaintenanceFailure> {
        let MaintenanceScope::Segment { tenant, signal, .. } = scope else {
            return Err(MaintenanceFailure::InvalidInput);
        };
        if policy.tenant() != tenant
            || policy.signal_kind() != signal
            || bucket.tenant() != tenant
            || bucket.signal_kind() != signal
            || source_digest.iter().all(|byte| *byte == 0)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self {
            scope,
            policy_object: policy.object_id().to_bytes(),
            retention_seconds: policy.retention_seconds().get(),
            bucket_start: bucket.start().value(),
            bucket_end_exclusive: bucket.end_exclusive().value(),
            source_digest,
        })
    }

    #[must_use]
    pub const fn scope(self) -> MaintenanceScope {
        self.scope
    }
    #[must_use]
    pub const fn source_digest(self) -> [u8; 32] {
        self.source_digest
    }

    pub fn matches_policy(self, policy: CatalogLogRetentionPolicy) -> bool {
        self.policy_object == policy.object_id().to_bytes()
            && self.retention_seconds == policy.retention_seconds().get()
    }

    pub fn contains(self, ingest_time: crate::IngestTime) -> bool {
        ingest_time.retention_authenticated()
            && ingest_time.instant().value() >= self.bucket_start
            && ingest_time.instant().value() < self.bucket_end_exclusive
    }

    pub fn checkpoint(self) -> Result<MaintenanceCheckpoint, MaintenanceFailure> {
        let MaintenanceScope::Segment {
            tenant,
            signal,
            shard,
        } = self.scope
        else {
            return Err(MaintenanceFailure::InvalidInput);
        };
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(COMPACTION_BINDING_BYTES)
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        bytes.extend_from_slice(COMPACTION_BINDING_MAGIC);
        bytes.extend_from_slice(&tenant.to_bytes());
        bytes.push(match signal {
            SignalKind::Logs => 1,
            SignalKind::Traces => 2,
        });
        bytes.extend_from_slice(&shard.value().to_be_bytes());
        bytes.extend_from_slice(&self.policy_object);
        bytes.extend_from_slice(&self.retention_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.bucket_start.to_be_bytes());
        bytes.extend_from_slice(&self.bucket_end_exclusive.to_be_bytes());
        bytes.extend_from_slice(&self.source_digest);
        MaintenanceCheckpoint::new(1, 0, bytes)
    }

    pub fn from_checkpoint(
        checkpoint: Option<&MaintenanceCheckpoint>,
    ) -> Result<Self, MaintenanceFailure> {
        let checkpoint = checkpoint.ok_or(MaintenanceFailure::InvalidInput)?;
        let bytes = checkpoint.opaque_progress();
        if checkpoint.sequence() != 1
            || checkpoint.completed_inputs() != 0
            || bytes.len() != COMPACTION_BINDING_BYTES
            || !bytes.starts_with(COMPACTION_BINDING_MAGIC)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let tenant = TenantId::from_bytes(
            bytes
                .get(8..24)
                .ok_or(MaintenanceFailure::InvalidInput)?
                .try_into()
                .map_err(|_| MaintenanceFailure::InvalidInput)?,
        )
        .map_err(|_| MaintenanceFailure::InvalidInput)?;
        let signal = match bytes.get(24).copied() {
            Some(1) => SignalKind::Logs,
            Some(2) => SignalKind::Traces,
            _ => return Err(MaintenanceFailure::InvalidInput),
        };
        let shard = VirtualShardId::new(u32::from_be_bytes(
            bytes
                .get(25..29)
                .ok_or(MaintenanceFailure::InvalidInput)?
                .try_into()
                .map_err(|_| MaintenanceFailure::InvalidInput)?,
        ))
        .map_err(|_| MaintenanceFailure::InvalidInput)?;
        let policy_object = bytes
            .get(29..61)
            .ok_or(MaintenanceFailure::InvalidInput)?
            .try_into()
            .map_err(|_| MaintenanceFailure::InvalidInput)?;
        let retention_seconds = u64::from_be_bytes(
            bytes
                .get(61..69)
                .ok_or(MaintenanceFailure::InvalidInput)?
                .try_into()
                .map_err(|_| MaintenanceFailure::InvalidInput)?,
        );
        let bucket_start = i64::from_be_bytes(
            bytes
                .get(69..77)
                .ok_or(MaintenanceFailure::InvalidInput)?
                .try_into()
                .map_err(|_| MaintenanceFailure::InvalidInput)?,
        );
        let bucket_end_exclusive = i64::from_be_bytes(
            bytes
                .get(77..85)
                .ok_or(MaintenanceFailure::InvalidInput)?
                .try_into()
                .map_err(|_| MaintenanceFailure::InvalidInput)?,
        );
        let source_digest: [u8; 32] = bytes
            .get(85..117)
            .ok_or(MaintenanceFailure::InvalidInput)?
            .try_into()
            .map_err(|_| MaintenanceFailure::InvalidInput)?;
        if retention_seconds == 0
            || bucket_start >= bucket_end_exclusive
            || source_digest.iter().all(|byte| *byte == 0)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self {
            scope: MaintenanceScope::segment(tenant, signal, shard),
            policy_object,
            retention_seconds,
            bucket_start,
            bucket_end_exclusive,
            source_digest,
        })
    }
}
