use std::collections::BTreeMap;

use positron_domain::routing::{SignalKind, VirtualShardId};

use crate::{AdmissionGroupPlanFailure, AdmissionGroupPlanner};

use super::{NativeLogBatch, NativeLogCandidate};

/// One planned native batch sharing tenant, Logs store, and virtual shard.
#[derive(Debug)]
pub struct NativeLogAdmissionGroup<'authority> {
    shard: VirtualShardId,
    batch: NativeLogBatch<'authority>,
}

impl<'authority> NativeLogAdmissionGroup<'authority> {
    #[must_use]
    pub const fn shard(&self) -> VirtualShardId {
        self.shard
    }

    #[must_use]
    pub fn records(&self) -> usize {
        self.batch.records.len()
    }

    #[must_use]
    pub fn into_batch(self) -> NativeLogBatch<'authority> {
        self.batch
    }
}

impl<'authority> NativeLogBatch<'authority> {
    pub fn into_admission_groups(
        self,
        planner: &dyn AdmissionGroupPlanner,
    ) -> Result<Vec<NativeLogAdmissionGroup<'authority>>, AdmissionGroupPlanFailure> {
        let mut planned = BTreeMap::<VirtualShardId, Vec<NativeLogCandidate>>::new();
        for (ordinal, record) in self.records.into_iter().enumerate() {
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| AdmissionGroupPlanFailure::RecordCountExceeded)?;
            let shard = planner.assigned_shard(
                self.attribution.tenant_id(),
                SignalKind::Logs,
                ordinal,
                &record,
            )?;
            planned.entry(shard).or_default().push(record);
        }
        let mut capacity = self.capacity;
        Ok(planned
            .into_iter()
            .map(|(shard, records)| NativeLogAdmissionGroup {
                shard,
                batch: NativeLogBatch {
                    attribution: self.attribution,
                    records,
                    value_limit_profile: self.value_limit_profile,
                    decoded_bytes: self.decoded_bytes,
                    capacity: capacity.take(),
                },
            })
            .collect())
    }
}
