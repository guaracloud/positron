use std::cmp::Ordering;

use crate::cursor::CursorState;
use crate::{QueryFailure, QueryFailureCode};

use super::{GroupEntry, charge_group_unit};

pub(super) fn find_group<'kernel, 'catalog, 'ledger>(
    service: &crate::QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    groups: &[GroupEntry],
    wanted: &[u8],
) -> Result<Result<usize, usize>, QueryFailure> {
    let mut start = 0_usize;
    let mut end = groups.len();
    while start < end {
        let middle = start
            .checked_add((end - start) / 2)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let existing = groups
            .get(middle)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        match compare_group_bytes(service, state, &existing.comparison, wanted)? {
            Ordering::Less => start = middle + 1,
            Ordering::Greater => end = middle,
            Ordering::Equal => return Ok(Ok(middle)),
        }
    }
    Ok(Err(start))
}

fn compare_group_bytes<'kernel, 'catalog, 'ledger>(
    service: &crate::QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    left: &[u8],
    right: &[u8],
) -> Result<Ordering, QueryFailure> {
    for (left, right) in left.iter().zip(right) {
        charge_group_unit(service, state)?;
        match left.cmp(right) {
            Ordering::Equal => {},
            ordering => return Ok(ordering),
        }
    }
    charge_group_unit(service, state)?;
    Ok(left.len().cmp(&right.len()))
}
