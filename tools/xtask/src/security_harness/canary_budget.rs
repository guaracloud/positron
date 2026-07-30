//! Allocation-independent candidate artifact count and byte accounting.

use crate::error::XtaskError;

pub(super) const MAXIMUM_ARTIFACT_BYTES: usize = 4_096;
const MAXIMUM_ARTIFACT_COUNT: usize = 9;
const MAXIMUM_TOTAL_ARTIFACT_BYTES: usize = MAXIMUM_ARTIFACT_COUNT * MAXIMUM_ARTIFACT_BYTES;

pub(super) struct ArtifactBudget {
    maximum_count: usize,
    maximum_per_artifact: usize,
    maximum_total: usize,
    count: usize,
    total: usize,
}

impl ArtifactBudget {
    pub(super) const fn candidate() -> Self {
        Self::new(
            MAXIMUM_ARTIFACT_COUNT,
            MAXIMUM_ARTIFACT_BYTES,
            MAXIMUM_TOTAL_ARTIFACT_BYTES,
        )
    }

    const fn new(maximum_count: usize, maximum_per_artifact: usize, maximum_total: usize) -> Self {
        Self {
            maximum_count,
            maximum_per_artifact,
            maximum_total,
            count: 0,
            total: 0,
        }
    }

    pub(super) fn charge(&mut self, bytes: usize) -> Result<(), XtaskError> {
        if self.count >= self.maximum_count {
            return Err(XtaskError::invalid(
                "candidate artifact scanner",
                "candidate artifact count exceeds the registered bound",
            ));
        }
        if bytes > self.maximum_per_artifact {
            return Err(XtaskError::invalid(
                "candidate artifact scanner",
                "candidate artifact exceeds the registered per-artifact bound",
            ));
        }
        let total = self.total.checked_add(bytes).ok_or_else(|| {
            XtaskError::invalid(
                "candidate artifact scanner",
                "aggregate byte count overflowed",
            )
        })?;
        if total > self.maximum_total {
            return Err(XtaskError::invalid(
                "candidate artifact scanner",
                "aggregate candidate artifact bytes exceed the registered bound",
            ));
        }
        self.count += 1;
        self.total = total;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_budget_accepts_boundaries_and_rejects_each_oversize_dimension() {
        let mut production = ArtifactBudget::candidate();
        for _ in 0..MAXIMUM_ARTIFACT_COUNT {
            assert!(production.charge(MAXIMUM_ARTIFACT_BYTES).is_ok());
        }
        assert!(production.charge(0).is_err());

        let mut aggregate = ArtifactBudget::new(3, MAXIMUM_ARTIFACT_BYTES, 8_192);
        assert!(aggregate.charge(4_096).is_ok());
        assert!(aggregate.charge(4_096).is_ok());
        assert!(aggregate.charge(1).is_err());

        let mut per_artifact = ArtifactBudget::candidate();
        assert!(per_artifact.charge(MAXIMUM_ARTIFACT_BYTES + 1).is_err());
    }
}
