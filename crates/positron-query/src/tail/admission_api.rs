use super::{QueryFailure, QueryService, TailCursor, TailSession, TailSourceSet, TailStart};

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub fn tail(
        &self,
        query: crate::PlannedQuery<'kernel>,
        start: TailStart,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let reader = self
            .ledger
            .reader()
            .map_err(crate::execution_support::map_ledger_failure)?;
        self.tail_with_sources(query, start, TailSourceSet::single(reader)?)
    }

    pub fn tail_with_sources(
        &self,
        query: crate::PlannedQuery<'kernel>,
        start: TailStart,
        sources: TailSourceSet<'kernel, 'catalog, 'ledger>,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        self.admit_tail(query, start, None, sources)
    }

    pub fn resume_tail(
        &self,
        query: crate::PlannedQuery<'kernel>,
        cursor: &TailCursor,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let reader = self
            .ledger
            .reader()
            .map_err(crate::execution_support::map_ledger_failure)?;
        self.resume_tail_with_sources(query, cursor, TailSourceSet::single(reader)?)
    }

    pub fn resume_tail_with_sources(
        &self,
        query: crate::PlannedQuery<'kernel>,
        cursor: &TailCursor,
        sources: TailSourceSet<'kernel, 'catalog, 'ledger>,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let state = TailCursor::decode(&self.ledger.control_tokens(), cursor)?;
        let (tenant, _, _generation) = self.current_query_catalog(query.context)?;
        let signal_digest = sources.digest(&self.ledger.control_tokens())?;
        state.validate_for_resume(
            query.context.principal_id(),
            tenant,
            query.context.authorization_generation(),
            query.plan_digest,
            signal_digest,
            self.now()?,
        )?;
        super::resume::validate_resume_history(&state, &sources)?;
        self.admit_tail(
            query,
            TailStart::Now,
            Some((state, cursor.clone())),
            sources,
        )
    }
}
