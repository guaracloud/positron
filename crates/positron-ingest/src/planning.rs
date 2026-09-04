use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use crate::NativeLogCandidate;
use positron_signals::SpanObservation;

/// Typed refusal from a trusted Admission Group assignment authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionGroupPlanFailure {
    UnsupportedSignal,
    AssignmentUnavailable,
    RecordCountExceeded,
}

impl Display for AdmissionGroupPlanFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("admission group assignment failed")
    }
}

impl Error for AdmissionGroupPlanFailure {}

/// Constructor-injected authority that assigns native records to configured shards.
pub trait AdmissionGroupPlanner: Send + Sync {
    fn assigned_shard(
        &self,
        tenant: TenantId,
        signal: SignalKind,
        record_ordinal: u32,
        record: &NativeLogCandidate,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure>;

    fn assigned_trace_shard(
        &self,
        _tenant: TenantId,
        _signal: SignalKind,
        _record_ordinal: u32,
        _record: &SpanObservation,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        Err(AdmissionGroupPlanFailure::UnsupportedSignal)
    }
}

/// The accepted standalone plan that assigns all records to one configured shard.
#[derive(Clone, Copy, Debug)]
pub struct FixedAdmissionGroupPlanner {
    shard: VirtualShardId,
}

impl FixedAdmissionGroupPlanner {
    #[must_use]
    pub const fn new(shard: VirtualShardId) -> Self {
        Self { shard }
    }
}

impl AdmissionGroupPlanner for FixedAdmissionGroupPlanner {
    fn assigned_shard(
        &self,
        _tenant: TenantId,
        signal: SignalKind,
        _record_ordinal: u32,
        _record: &NativeLogCandidate,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        if signal != SignalKind::Logs {
            return Err(AdmissionGroupPlanFailure::UnsupportedSignal);
        }
        Ok(self.shard)
    }

    fn assigned_trace_shard(
        &self,
        _tenant: TenantId,
        signal: SignalKind,
        _record_ordinal: u32,
        _record: &SpanObservation,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        if signal != SignalKind::Traces {
            return Err(AdmissionGroupPlanFailure::UnsupportedSignal);
        }
        Ok(self.shard)
    }
}
