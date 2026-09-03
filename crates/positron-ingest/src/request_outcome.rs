use positron_domain::routing::VirtualShardId;

use crate::{IngestFailureCode, IngestOutcome};

/// One independently terminal Admission Group outcome within a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionGroupOutcome {
    shard: VirtualShardId,
    attempted_records: usize,
    outcome: IngestOutcome,
}

impl AdmissionGroupOutcome {
    #[must_use]
    pub const fn new(
        shard: VirtualShardId,
        attempted_records: usize,
        outcome: IngestOutcome,
    ) -> Self {
        Self {
            shard,
            attempted_records,
            outcome,
        }
    }

    #[must_use]
    pub const fn shard(&self) -> VirtualShardId {
        self.shard
    }

    #[must_use]
    pub const fn attempted_records(&self) -> usize {
        self.attempted_records
    }

    #[must_use]
    pub const fn outcome(&self) -> IngestOutcome {
        self.outcome
    }
}

/// Truthful bounded result for all independent groups in one request.
#[derive(Debug, Eq, PartialEq)]
pub struct IngestRequestOutcome {
    groups: Vec<AdmissionGroupOutcome>,
    request_rejections: [usize; 3],
}

impl IngestRequestOutcome {
    #[must_use]
    pub fn new(groups: Vec<AdmissionGroupOutcome>) -> Self {
        Self {
            groups,
            request_rejections: [0; 3],
        }
    }

    #[must_use]
    pub fn with_rejections(
        groups: Vec<AdmissionGroupOutcome>,
        request_rejections: [usize; 3],
    ) -> Self {
        Self {
            groups,
            request_rejections,
        }
    }

    #[must_use]
    pub fn with_additional_rejections(mut self, additional: [usize; 3]) -> Self {
        for (current, added) in self.request_rejections.iter_mut().zip(additional) {
            *current = current.saturating_add(added);
        }
        self
    }

    #[must_use]
    pub fn groups(&self) -> &[AdmissionGroupOutcome] {
        &self.groups
    }

    #[must_use]
    pub fn accepted_records(&self) -> usize {
        self.groups
            .iter()
            .map(|group| match group.outcome {
                IngestOutcome::Full(committed) => committed.records(),
                IngestOutcome::Partial(partial) => partial.committed().records(),
                _ => 0,
            })
            .sum()
    }

    #[must_use]
    pub fn permanently_rejected_records(&self) -> usize {
        self.request_rejections
            .into_iter()
            .sum::<usize>()
            .saturating_add(
                self.groups
                    .iter()
                    .map(|group| match group.outcome {
                        IngestOutcome::Partial(partial) => partial.permanently_rejected(),
                        IngestOutcome::Permanent(_) => group.attempted_records,
                        _ => 0,
                    })
                    .sum(),
            )
    }

    #[must_use]
    pub fn terminal_failure(&self) -> Option<IngestOutcome> {
        self.groups
            .iter()
            .find_map(|group| match group.outcome {
                outcome @ IngestOutcome::Ambiguous(_) => Some(outcome),
                _ => None,
            })
            .or_else(|| {
                self.groups.iter().find_map(|group| match group.outcome {
                    outcome @ IngestOutcome::Retryable(_) => Some(outcome),
                    _ => None,
                })
            })
            .or_else(|| {
                if self.accepted_records() == 0 {
                    self.groups.iter().find_map(|group| match group.outcome {
                        outcome @ IngestOutcome::Permanent(_) => Some(outcome),
                        _ => None,
                    })
                } else {
                    None
                }
            })
    }

    #[must_use]
    pub fn capacity_only_retry(&self) -> bool {
        self.groups.iter().any(|group| {
            group.outcome == IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
        })
    }
}
