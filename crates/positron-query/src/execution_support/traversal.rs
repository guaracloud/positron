use positron_domain::value::{NativeValueObserver, ObservedValueFailure};

use crate::{
    QueryBudgetDimension, QueryCancellation, QueryFailure, QueryFailureCode, QueryService,
    QueryWorkStage,
};

use super::{charge_work_counter, cpu_work_exhausted, map_domain_value_failure};

pub(crate) struct QueryValueObserver<'service, 'state, 'kernel, 'catalog, 'ledger> {
    service: &'service QueryService<'kernel, 'catalog, 'ledger>,
    consumed: &'state mut u64,
    limit: u64,
    cancellation: QueryCancellation,
    stage: QueryWorkStage,
}

impl<'service, 'state, 'kernel, 'catalog, 'ledger>
    QueryValueObserver<'service, 'state, 'kernel, 'catalog, 'ledger>
{
    pub(crate) const fn new(
        service: &'service QueryService<'kernel, 'catalog, 'ledger>,
        consumed: &'state mut u64,
        limit: u64,
        cancellation: QueryCancellation,
        stage: QueryWorkStage,
    ) -> Self {
        Self {
            service,
            consumed,
            limit,
            cancellation,
            stage,
        }
    }
}

impl NativeValueObserver for QueryValueObserver<'_, '_, '_, '_, '_> {
    type Error = QueryFailure;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        check_cancellation(&self.cancellation)?;
        let units = self.service.work_units(self.stage)?;
        check_cancellation(&self.cancellation)?;
        charge_work_counter(self.consumed, units)?;
        if cpu_work_exhausted(*self.consumed, self.limit) {
            return Err(QueryFailure::budget_exhausted(
                QueryBudgetDimension::CpuWorkUnits,
            ));
        }
        Ok(())
    }

    fn observe_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        if payload.len() > positron_domain::value::NATIVE_VALUE_PAYLOAD_CHUNK_BYTES {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        check_cancellation(&self.cancellation)
    }
}

pub(crate) fn map_observed_failure(failure: ObservedValueFailure<QueryFailure>) -> QueryFailure {
    match failure {
        ObservedValueFailure::Domain(failure) => map_domain_value_failure(failure),
        ObservedValueFailure::Observer(failure) => failure,
    }
}

fn check_cancellation(cancellation: &QueryCancellation) -> Result<(), QueryFailure> {
    if cancellation.is_cancelled() {
        Err(QueryFailure::new(QueryFailureCode::Cancelled))
    } else {
        Ok(())
    }
}
