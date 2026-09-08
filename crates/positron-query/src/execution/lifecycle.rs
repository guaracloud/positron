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

    pub(super) fn incomplete_page(
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
        let mut resources = resources;
        if let Err(failure) = resources.persist_usage(ledger, self.trace_ledger, state) {
            return Err(resources.fail_before_stream(ledger, self.trace_ledger, state, failure));
        }
        let resources = resources.validate_lease_identity(
            ledger,
            self.trace_ledger,
            state,
            state.lease_identity,
        )?;
        let (admission, identity, target_identity) = resources.into_stream();
        let cancellation = state.cancellation.clone();
        let target_ledger = self.trace_ledger;
        let mut source_identity = Some(identity);
        let mut target_identity = target_identity;
        let release = Box::new(move || {
            let target_failure = match (target_identity, target_ledger) {
                (Some(identity), Some(ledger)) => match ledger.release_snapshot_lease(identity) {
                    Ok(()) => {
                        target_identity = None;
                        None
                    },
                    Err(failure) => Some(map_ledger_failure(failure)),
                },
                (Some(_), None) => Some(QueryFailure::new(crate::QueryFailureCode::Internal)),
                (None, _) => None,
            };
            let source_failure = match source_identity {
                Some(identity) => match ledger.release_snapshot_lease(identity) {
                    Ok(()) => {
                        source_identity = None;
                        None
                    },
                    Err(failure) => Some(map_ledger_failure(failure)),
                },
                None => None,
            };
            match (source_failure, target_failure) {
                (None, None) => Ok(()),
                (Some(source), None) | (None, Some(source)) => Err(source),
                (Some(source), Some(target)) => {
                    Err(crate::failure::stronger_failure(source, target))
                },
            }
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
