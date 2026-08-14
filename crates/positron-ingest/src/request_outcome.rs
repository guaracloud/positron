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
}

impl IngestRequestOutcome {
    #[must_use]
    pub fn new(groups: Vec<AdmissionGroupOutcome>) -> Self {
        Self { groups }
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
        self.groups
            .iter()
            .map(|group| match group.outcome {
                IngestOutcome::Partial(partial) => partial.permanently_rejected(),
                IngestOutcome::Permanent(_) => group.attempted_records,
                _ => 0,
            })
            .sum()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn group(attempted_records: usize, outcome: IngestOutcome) -> AdmissionGroupOutcome {
        AdmissionGroupOutcome::new(
            VirtualShardId::new(7).expect("fixed shard"),
            attempted_records,
            outcome,
        )
    }

    #[test]
    fn group_accessors_and_permanent_only_request_preserve_exact_truth() {
        let permanent = group(
            3,
            IngestOutcome::Permanent(IngestFailureCode::PolicyRejected),
        );
        assert_eq!(permanent.shard().value(), 7);
        assert_eq!(permanent.attempted_records(), 3);
        assert_eq!(
            permanent.outcome(),
            IngestOutcome::Permanent(IngestFailureCode::PolicyRejected)
        );
        let request = IngestRequestOutcome::new(vec![permanent]);
        assert_eq!(request.groups(), [permanent]);
        assert_eq!(request.accepted_records(), 0);
        assert_eq!(request.permanently_rejected_records(), 3);
        assert_eq!(request.terminal_failure(), Some(permanent.outcome()));
        assert!(!request.capacity_only_retry());
    }

    #[test]
    fn ambiguity_precedes_retry_and_capacity_retry_remains_explicit() {
        let retry = group(
            2,
            IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable),
        );
        let ambiguous = group(
            1,
            IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable),
        );
        let request = IngestRequestOutcome::new(vec![retry, ambiguous]);
        assert_eq!(request.terminal_failure(), Some(ambiguous.outcome()));
        assert!(request.capacity_only_retry());
        assert_eq!(request.permanently_rejected_records(), 0);
    }

    #[test]
    fn retry_precedes_permanent_and_empty_request_has_no_terminal_failure() {
        let permanent = group(
            1,
            IngestOutcome::Permanent(IngestFailureCode::InvalidRecord),
        );
        let retry = group(
            1,
            IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
        );
        let mixed = IngestRequestOutcome::new(vec![permanent, retry]);
        assert_eq!(mixed.terminal_failure(), Some(retry.outcome()));
        assert!(!mixed.capacity_only_retry());

        let empty = IngestRequestOutcome::new(vec![]);
        assert!(empty.groups().is_empty());
        assert_eq!(empty.terminal_failure(), None);
    }
}
