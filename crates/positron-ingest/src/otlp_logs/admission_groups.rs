use std::collections::BTreeMap;
use std::vec::IntoIter;

use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{ResourceAmounts, ResourceReservation};

use crate::{AdmissionGroupPlanFailure, AdmissionGroupPlanner};

use super::bounds::grouped_retained_bytes;
use super::{NativeLogBatch, NativeLogCandidate};

/// One planned native batch sharing tenant, Logs store, and virtual shard.
#[derive(Debug)]
pub struct NativeLogAdmissionGroup<'authority> {
    shard: VirtualShardId,
    batch: NativeLogBatch<'authority>,
}

/// Bounded planned groups that retain the decoded request allocation until all
/// groups have reached an independent terminal outcome.
#[derive(Debug)]
pub struct NativeLogAdmissionGroups<'authority> {
    groups: IntoIter<NativeLogAdmissionGroup<'authority>>,
    _retained_capacity: Option<ResourceReservation<'authority>>,
}

impl NativeLogAdmissionGroups<'_> {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.as_slice().is_empty()
    }
}

impl<'authority> Iterator for NativeLogAdmissionGroups<'authority> {
    type Item = NativeLogAdmissionGroup<'authority>;

    fn next(&mut self) -> Option<Self::Item> {
        self.groups.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.groups.size_hint()
    }
}

impl ExactSizeIterator for NativeLogAdmissionGroups<'_> {}

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
    ) -> Result<NativeLogAdmissionGroups<'authority>, AdmissionGroupPlanFailure> {
        let NativeLogBatch {
            attribution,
            records,
            value_limit_profile,
            decoded_bytes,
            mut capacity,
        } = self;
        let record_count = records.len();
        let grouped_bytes = grouped_retained_bytes(decoded_bytes, record_count)
            .map_err(|_| AdmissionGroupPlanFailure::RecordCountExceeded)?;
        if let Some(retained) = capacity.as_mut() {
            retained
                .try_resize(ResourceAmounts::new([
                    grouped_bytes,
                    0,
                    0,
                    0,
                    u64::try_from(record_count)
                        .map_err(|_| AdmissionGroupPlanFailure::RecordCountExceeded)?,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]))
                .map_err(|_| AdmissionGroupPlanFailure::AssignmentUnavailable)?;
        }
        let mut planned = BTreeMap::<VirtualShardId, Vec<NativeLogCandidate>>::new();
        for (ordinal, record) in records.into_iter().enumerate() {
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| AdmissionGroupPlanFailure::RecordCountExceeded)?;
            let shard = planner.assigned_shard(
                attribution.tenant_id(),
                SignalKind::Logs,
                ordinal,
                &record,
            )?;
            planned.entry(shard).or_default().push(record);
        }
        let groups = planned
            .into_iter()
            .map(|(shard, records)| NativeLogAdmissionGroup {
                shard,
                batch: NativeLogBatch {
                    attribution,
                    records,
                    value_limit_profile,
                    decoded_bytes: 0,
                    capacity: None,
                },
            })
            .collect::<Vec<_>>()
            .into_iter();
        Ok(NativeLogAdmissionGroups {
            groups,
            _retained_capacity: capacity,
        })
    }
}
