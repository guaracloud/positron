use positron_domain::routing::CommitPosition;

use super::cursor::TailCursorState;
use crate::result_key::HistoricalTotalKey;
use crate::{QueryFailure, QueryFailureCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HistoricalMarker {
    lower_bound: CommitPosition,
    handoff_frontier: CommitPosition,
}

impl HistoricalMarker {
    pub(super) fn new(
        lower_bound: CommitPosition,
        handoff_frontier: CommitPosition,
    ) -> Result<Self, QueryFailure> {
        if lower_bound > handoff_frontier {
            return Err(invalid());
        }
        Ok(Self {
            lower_bound,
            handoff_frontier,
        })
    }

    pub(super) const fn lower_bound(self) -> CommitPosition {
        self.lower_bound
    }

    pub(super) const fn handoff_frontier(self) -> CommitPosition {
        self.handoff_frontier
    }
}

impl TailCursorState {
    pub(super) fn historical_markers(&self) -> Option<&[HistoricalMarker]> {
        self.historical_markers.as_deref()
    }

    pub(super) fn set_historical_markers(
        &mut self,
        markers: Vec<HistoricalMarker>,
    ) -> Result<(), QueryFailure> {
        if markers.len() != self.positions().len() {
            return Err(invalid());
        }
        self.historical_markers = Some(markers);
        Ok(())
    }

    pub(super) fn clear_historical_markers(&mut self) {
        self.historical_markers = None;
        self.historical_key = None;
    }

    pub(super) fn historical_key(&self) -> Option<HistoricalTotalKey> {
        self.historical_key
    }

    pub(super) fn set_historical_key(&mut self, key: Option<HistoricalTotalKey>) {
        self.historical_key = key;
    }
}

const fn invalid() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::InvalidCursor)
}
