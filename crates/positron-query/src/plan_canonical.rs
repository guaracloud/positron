use std::fmt::Write as _;

use super::{CanonicalBuffer, FilterPredicate, LogicalPlan};
use positron_kernel::ControlTokenProtector;

impl LogicalPlan {
    /// Computes the authenticated semantic plan identity shared by every
    /// frontend. Source spelling and frontend language are deliberately absent;
    /// only the parsed LogicalPlan's bounded operators and parameters enter
    /// this visitor.
    pub(crate) fn canonical_digest(
        &self,
        protector: &ControlTokenProtector<'_>,
    ) -> Result<[u8; 32], crate::QueryFailure> {
        let mut canonical = CanonicalBuffer::new();
        write!(
            canonical,
            "plan:v4;version={};axis={:?};range={}..{};limit={};filter=",
            self.version,
            self.axis,
            self.range.start_nanoseconds,
            self.range.end_nanoseconds,
            self.limit,
        )
        .map_err(|_| crate::QueryFailure::new(crate::QueryFailureCode::ResourceExhausted))?;
        match self.filter.as_ref() {
            Some(FilterPredicate::BodyEquals(value)) => write!(canonical, "body_equals:{value:?}"),
            Some(FilterPredicate::BodyContains(value)) => {
                write!(
                    canonical,
                    "body_contains:{}:{}",
                    value.source().len(),
                    value.source()
                )
            },
            Some(FilterPredicate::BodyRegex(value)) => {
                write!(
                    canonical,
                    "body_regex:{}:{}",
                    value.source().len(),
                    value.source()
                )
            },
            Some(FilterPredicate::AttributeEquals(query)) => {
                write!(canonical, "attribute_equals:{query:?}")
            },
            None => Ok(()),
        }
        .map_err(|_| crate::QueryFailure::new(crate::QueryFailureCode::ResourceExhausted))?;
        write!(
            canonical,
            ";projection={:?};aggregate={:?};ordering={:?};transform={:?}",
            self.projection, self.aggregate, self.ordering, self.transform,
        )
        .map_err(|_| crate::QueryFailure::new(crate::QueryFailureCode::ResourceExhausted))?;
        protector
            .digest_query_plan(b"query-plan-canonical-v1", canonical.as_slice())
            .map_err(|_| crate::QueryFailure::new(crate::QueryFailureCode::Internal))
    }
}
