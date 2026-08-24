use positron_governance::AuthorizedContext;
use positron_kernel::ResourceReservation;
use std::sync::Arc;

use crate::QueryBudget;

pub(super) const MAX_CANONICAL_PLAN_BYTES: usize = 65_536;

pub(super) struct CanonicalBuffer {
    bytes: [u8; MAX_CANONICAL_PLAN_BYTES],
    length: usize,
}

impl CanonicalBuffer {
    pub(super) const fn new() -> Self {
        Self {
            bytes: [0; MAX_CANONICAL_PLAN_BYTES],
            length: 0,
        }
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.length).unwrap_or(&[])
    }
}

impl std::fmt::Write for CanonicalBuffer {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self
            .length
            .checked_add(value.len())
            .ok_or(std::fmt::Error)?;
        let target = self
            .bytes
            .get_mut(self.length..end)
            .ok_or(std::fmt::Error)?;
        target.copy_from_slice(value.as_bytes());
        self.length = end;
        Ok(())
    }
}

pub struct PlannedQuery<'kernel> {
    pub(crate) context: AuthorizedContext,
    pub(crate) plan: Arc<super::LogicalPlan>,
    pub(crate) source: Arc<[u8]>,
    pub(crate) language: crate::query_service::QueryLanguage,
    pub(crate) budget: QueryBudget,
    pub(crate) plan_digest: [u8; 32],
    pub(crate) _reservation: ResourceReservation<'kernel>,
    pub(crate) _planning_memory: crate::planning_memory::PlanningReservation,
    pub(crate) started_at: u64,
    pub(crate) last_observed_at: u64,
    pub(crate) cpu_work_units: u64,
    pub(crate) cancellation: crate::QueryCancellation,
}

impl PlannedQuery<'_> {
    #[must_use]
    pub fn logical_plan(&self) -> &super::LogicalPlan {
        self.plan.as_ref()
    }

    /// Returns the query-scoped handle used to propagate disconnects and deadlines.
    #[must_use]
    pub fn cancellation(&self) -> crate::QueryCancellation {
        self.cancellation.clone()
    }
}
