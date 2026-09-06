use std::vec::IntoIter;

use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{ResourceAmounts, ResourceReservation};

use crate::{AdmissionGroupPlanFailure, AdmissionGroupPlanner};

use super::bounds::grouped_retained_native_batch_bytes;
use super::{NativeSpanBatch, TraceLimitRejectionSummary};

/// One planned native batch sharing tenant, Trace Store, and virtual shard.
#[derive(Debug)]
pub struct NativeSpanAdmissionGroup<'authority> {
    shard: VirtualShardId,
    batch: NativeSpanBatch<'authority>,
}

/// Bounded planned groups retaining the decoded request allocation until all
/// groups reach independent terminal outcomes.
#[derive(Debug)]
pub struct NativeSpanAdmissionGroups<'authority> {
    groups: IntoIter<NativeSpanAdmissionGroup<'authority>>,
    rejections: [usize; 3],
    limit_rejections: TraceLimitRejectionSummary,
    _retained_capacity: Option<ResourceReservation<'authority>>,
}

impl NativeSpanAdmissionGroups<'_> {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.as_slice().is_empty()
    }

    #[must_use]
    pub const fn rejections(&self) -> [usize; 3] {
        self.rejections
    }

    #[must_use]
    pub const fn limit_rejections(&self) -> TraceLimitRejectionSummary {
        self.limit_rejections
    }
}

impl<'authority> Iterator for NativeSpanAdmissionGroups<'authority> {
    type Item = NativeSpanAdmissionGroup<'authority>;

    fn next(&mut self) -> Option<Self::Item> {
        self.groups.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.groups.size_hint()
    }
}

impl ExactSizeIterator for NativeSpanAdmissionGroups<'_> {}

impl<'authority> NativeSpanAdmissionGroup<'authority> {
    #[must_use]
    pub const fn shard(&self) -> VirtualShardId {
        self.shard
    }

    #[must_use]
    pub fn records(&self) -> usize {
        self.batch.records().len()
    }

    #[must_use]
    pub fn into_batch(self) -> NativeSpanBatch<'authority> {
        self.batch
    }
}

impl<'authority> NativeSpanBatch<'authority> {
    pub fn into_admission_groups(
        self,
        planner: &dyn AdmissionGroupPlanner,
    ) -> Result<NativeSpanAdmissionGroups<'authority>, AdmissionGroupPlanFailure> {
        let NativeSpanBatch {
            attribution,
            records,
            value_limit_profile,
            decoded_bytes: _,
            mut capacity,
            receiver,
            rejections,
            limit_rejections,
        } = self;
        let record_count = records.len();
        if record_count == 0 {
            return Ok(NativeSpanAdmissionGroups {
                groups: Vec::new().into_iter(),
                rejections,
                limit_rejections,
                _retained_capacity: capacity,
            });
        }
        let grouped_bytes = grouped_retained_native_batch_bytes(&records, records.capacity())
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
        let mut assignments = Vec::new();
        assignments
            .try_reserve_exact(record_count)
            .map_err(|_| AdmissionGroupPlanFailure::CapacityUnavailable)?;
        for (ordinal, record) in records.iter().enumerate() {
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| AdmissionGroupPlanFailure::RecordCountExceeded)?;
            let shard = planner.assigned_trace_shard(
                attribution.tenant_id(),
                SignalKind::Traces,
                ordinal,
                record,
            )?;
            assignments.push(shard);
        }
        let mut sorted_shards = Vec::new();
        sorted_shards
            .try_reserve_exact(record_count)
            .map_err(|_| AdmissionGroupPlanFailure::CapacityUnavailable)?;
        sorted_shards.extend_from_slice(&assignments);
        // Keep the historical shard ordering while using vectors whose exact
        // capacities can be charged before their backing allocations.
        sorted_shards.sort_unstable();
        let mut planned = Vec::<(VirtualShardId, Vec<positron_signals::SpanObservation>)>::new();
        planned
            .try_reserve_exact(sorted_shards.len())
            .map_err(|_| AdmissionGroupPlanFailure::CapacityUnavailable)?;
        let mut sorted_cursor = 0;
        while let Some(&shard) = sorted_shards.get(sorted_cursor) {
            let mut count = 1;
            while sorted_shards
                .get(
                    sorted_cursor
                        .checked_add(count)
                        .ok_or(AdmissionGroupPlanFailure::RecordCountExceeded)?,
                )
                .is_some_and(|candidate| *candidate == shard)
            {
                count = count
                    .checked_add(1)
                    .ok_or(AdmissionGroupPlanFailure::RecordCountExceeded)?;
            }
            let mut group = Vec::new();
            group
                .try_reserve_exact(count)
                .map_err(|_| AdmissionGroupPlanFailure::CapacityUnavailable)?;
            planned.push((shard, group));
            sorted_cursor = sorted_cursor
                .checked_add(count)
                .ok_or(AdmissionGroupPlanFailure::RecordCountExceeded)?;
        }
        drop(sorted_shards);
        for (record, shard) in records.into_iter().zip(assignments) {
            let group_index = planned
                .binary_search_by_key(&shard, |(candidate, _)| *candidate)
                .map_err(|_| AdmissionGroupPlanFailure::AssignmentUnavailable)?;
            let group = planned
                .get_mut(group_index)
                .map(|(_, records)| records)
                .ok_or(AdmissionGroupPlanFailure::AssignmentUnavailable)?;
            group.push(record);
        }
        let groups = planned
            .into_iter()
            .map(|(shard, records)| NativeSpanAdmissionGroup {
                shard,
                batch: NativeSpanBatch {
                    attribution,
                    records,
                    value_limit_profile,
                    decoded_bytes: 0,
                    capacity: None,
                    receiver,
                    rejections: [0; 3],
                    limit_rejections: TraceLimitRejectionSummary::EMPTY,
                },
            })
            .collect::<Vec<_>>()
            .into_iter();
        Ok(NativeSpanAdmissionGroups {
            groups,
            rejections,
            limit_rejections,
            _retained_capacity: capacity,
        })
    }
}
