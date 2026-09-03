use std::collections::BTreeMap;
use std::vec::IntoIter;

use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{ResourceAmounts, ResourceReservation};

use crate::{AdmissionGroupPlanFailure, AdmissionGroupPlanner};

use super::NativeSpanBatch;
use super::bounds::retained_batch_bytes;

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
            decoded_bytes,
            mut capacity,
            receiver,
            rejections,
        } = self;
        let record_count = records.len();
        if record_count == 0 {
            return Ok(NativeSpanAdmissionGroups {
                groups: Vec::new().into_iter(),
                rejections,
                _retained_capacity: capacity,
            });
        }
        let grouped_bytes = retained_batch_bytes(decoded_bytes, record_count)
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
        let mut planned = BTreeMap::<VirtualShardId, Vec<positron_signals::SpanObservation>>::new();
        for (ordinal, record) in records.into_iter().enumerate() {
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| AdmissionGroupPlanFailure::RecordCountExceeded)?;
            let shard = planner.assigned_trace_shard(
                attribution.tenant_id(),
                SignalKind::Traces,
                ordinal,
                &record,
            )?;
            planned.entry(shard).or_default().push(record);
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
                },
            })
            .collect::<Vec<_>>()
            .into_iter();
        Ok(NativeSpanAdmissionGroups {
            groups,
            rejections,
            _retained_capacity: capacity,
        })
    }
}
