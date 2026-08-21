use std::cmp::Ordering;

use crate::QueryRecord;

pub(crate) fn compare_records(
    left: &QueryRecord,
    right: &QueryRecord,
    ordering: crate::plan::OrderSpec,
) -> Ordering {
    let primary = left.ordering_time().cmp(&right.ordering_time());
    let primary = match ordering.primary_direction() {
        crate::plan::OrderDirection::Ascending => primary,
        crate::plan::OrderDirection::Descending => primary.reverse(),
    };
    if primary != Ordering::Equal {
        return primary;
    }
    let commit = left.commit_position().cmp(&right.commit_position());
    let commit = match ordering.commit_direction() {
        crate::plan::OrderDirection::Ascending => commit,
        crate::plan::OrderDirection::Descending => commit.reverse(),
    };
    if commit != Ordering::Equal {
        return commit;
    }
    let ordinal = left.record_ordinal().cmp(&right.record_ordinal());
    match ordering.commit_direction() {
        crate::plan::OrderDirection::Ascending => ordinal,
        crate::plan::OrderDirection::Descending => ordinal.reverse(),
    }
}
