use crate::execution_state::stats_before_current;
use crate::execution_support::map_ledger_failure;
use crate::{
    QueryEvent, QueryFailure, QueryIncomplete, QueryService, QueryStats, QueryStream, QueryTerminal,
};

use super::resources::ExecutionResources;
use crate::cursor::CursorState;

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub(super) fn failed_page(
        &self,
        header: Option<QueryEvent>,
        failure: QueryFailure,
        state: &CursorState,
        delivered_before: QueryStats,
        resources: ExecutionResources,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        self.incomplete_page(
            header,
            failure,
            state,
            delivered_before,
            stats_before_current(state),
            resources,
        )
    }

    pub(super) fn failed_page_with_stats(
        &self,
        header: Option<QueryEvent>,
        failure: QueryFailure,
        state: &CursorState,
        delivered_before: QueryStats,
        terminal_stats: QueryStats,
        resources: ExecutionResources,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        self.incomplete_page(
            header,
            failure,
            state,
            delivered_before,
            terminal_stats,
            resources,
        )
    }

    fn incomplete_page(
        &self,
        header: Option<QueryEvent>,
        failure: QueryFailure,
        state: &CursorState,
        delivered_before: QueryStats,
        terminal_stats: QueryStats,
        resources: ExecutionResources,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let mut events = Vec::with_capacity(1);
        events.extend(header);
        self.incomplete_events(
            events,
            failure,
            state,
            delivered_before,
            terminal_stats,
            resources,
        )
    }

    pub(super) fn incomplete_events(
        &self,
        mut events: Vec<QueryEvent>,
        failure: QueryFailure,
        state: &CursorState,
        delivered_before: QueryStats,
        terminal_stats: QueryStats,
        resources: ExecutionResources,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        events.push(QueryEvent::Terminal(QueryTerminal::Incomplete(
            QueryIncomplete::new(failure, terminal_stats),
        )));
        self.stream(
            events,
            state,
            false,
            delivered_before,
            terminal_stats,
            resources,
        )
    }

    pub(super) fn stream(
        &self,
        events: Vec<QueryEvent>,
        state: &CursorState,
        retain_for_resume: bool,
        observed_stats: QueryStats,
        batch_stats: QueryStats,
        resources: ExecutionResources,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let ledger = self.ledger;
        let (admission, identity) = resources.into_stream();
        if identity.to_bytes() != state.lease_identity {
            return Err(QueryFailure::new(crate::QueryFailureCode::Internal));
        }
        let cancellation = state.cancellation.clone();
        let release = Box::new(move || {
            ledger
                .release_snapshot_lease(identity)
                .map_err(map_ledger_failure)
        });
        Ok(QueryStream::new_releasing(
            events,
            release,
            retain_for_resume,
            observed_stats,
            batch_stats,
            cancellation,
            Some(admission),
        ))
    }
}
