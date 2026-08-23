use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode};

struct TransformWorkObserver<'a, 'kernel, 'catalog, 'ledger> {
    service: &'a crate::QueryService<'kernel, 'catalog, 'ledger>,
    state: &'a mut crate::cursor::CursorState,
    memory: &'a mut crate::memory::QueryMemory,
    transient_bytes: u64,
}

impl crate::transform::TransformObserver for TransformWorkObserver<'_, '_, '_, '_> {
    fn step(&mut self) -> Result<(), QueryFailure> {
        if self.state.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        let units = self.service.work_units(crate::QueryWorkStage::Operators)?;
        super::charge_work(self.state, units)?;
        if super::exhausted(self.state) {
            return Err(QueryFailure::budget_exhausted(
                QueryBudgetDimension::CpuWorkUnits,
            ));
        }
        Ok(())
    }

    fn reserve_memory(&mut self, bytes: u64) -> Result<(), QueryFailure> {
        self.memory.acquire(bytes)?;
        let Some(total) = self.transient_bytes.checked_add(bytes) else {
            self.memory.release(bytes)?;
            return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
        };
        self.transient_bytes = total;
        Ok(())
    }

    fn release_memory(&mut self, bytes: u64) -> Result<(), QueryFailure> {
        self.transient_bytes = self
            .transient_bytes
            .checked_sub(bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        self.memory.release(bytes)
    }
}

impl TransformWorkObserver<'_, '_, '_, '_> {
    fn release_all(&mut self, base: u64) -> Result<(), QueryFailure> {
        let total = base
            .checked_add(self.transient_bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        self.memory.release(total)?;
        self.transient_bytes = 0;
        Ok(())
    }

    fn transfer_to(&mut self, base: u64, final_bytes: u64) -> Result<(), QueryFailure> {
        let current = base
            .checked_add(self.transient_bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        if final_bytes > current {
            self.memory.acquire(final_bytes - current)?;
        } else if current > final_bytes {
            self.memory.release(current - final_bytes)?;
        }
        self.transient_bytes = 0;
        Ok(())
    }
}

pub(super) fn apply_transform(
    transform: crate::transform::BodyTransform,
    body: &positron_domain::value::ValidatedAttributeValue,
    service: &crate::QueryService<'_, '_, '_>,
    state: &mut crate::cursor::CursorState,
    memory: &mut crate::memory::QueryMemory,
) -> Result<(positron_domain::value::ValidatedAttributeValue, u64), QueryFailure> {
    let scratch = transform.scratch_memory_bytes(body)?;
    memory.acquire(scratch)?;
    let mut observer = TransformWorkObserver {
        service,
        state,
        memory,
        transient_bytes: 0,
    };
    let facts = match transform.apply_with_facts(body, &mut observer) {
        Ok(facts) => facts,
        Err(failure) => {
            observer.release_all(scratch)?;
            return Err(failure);
        },
    };
    let final_bytes = match u64::try_from(facts.retained_heap_bytes())
        .ok()
        .and_then(|bytes| bytes.checked_add(64))
    {
        Some(bytes) => bytes,
        None => {
            observer.release_all(scratch)?;
            return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
        },
    };
    if let Err(failure) = observer.transfer_to(scratch, final_bytes) {
        observer.release_all(scratch)?;
        return Err(failure);
    }
    Ok((facts.into_value(), final_bytes))
}
