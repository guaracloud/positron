use crate::cursor::CursorState;
use crate::execution_support::{QueryValueObserver, result_digest};
use crate::result_key::ResultResumeKey;
use crate::{QueryFailure, QueryFailureCode, QueryService};

pub(super) fn resume_key_for_page<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    page: &[crate::QueryRecord],
    digest: [u8; 32],
    needs_resume: bool,
    memory: &mut crate::memory::QueryMemory,
) -> Result<Option<ResultResumeKey>, QueryFailure> {
    if !needs_resume {
        return Ok(None);
    }
    let record = page
        .last()
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    if record.count().is_none() {
        return Ok(Some(ResultResumeKey::from_record(record, digest)));
    }
    let cancellation = state.cancellation.clone();
    let mut observer = QueryValueObserver::new(
        service,
        &mut state.cpu_work_units,
        state.budget.cpu_work_units(),
        cancellation.clone(),
        crate::QueryWorkStage::Output,
    );
    let digest = result_digest(
        &service.ledger.control_tokens(),
        &state.plan,
        record,
        &cancellation,
        &mut observer,
        memory,
    )?;
    Ok(Some(ResultResumeKey::from_record(record, digest)))
}

pub(super) fn find_resume_index<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    records: &[crate::QueryRecord],
    key: ResultResumeKey,
    memory: &mut crate::memory::QueryMemory,
) -> Result<usize, QueryFailure> {
    let mut found = None;
    for (index, record) in records.iter().enumerate() {
        let digest = if key.is_aggregate() {
            let cancellation = state.cancellation.clone();
            let mut observer = QueryValueObserver::new(
                service,
                &mut state.cpu_work_units,
                state.budget.cpu_work_units(),
                cancellation.clone(),
                crate::QueryWorkStage::Output,
            );
            result_digest(
                &service.ledger.control_tokens(),
                &state.plan,
                record,
                &cancellation,
                &mut observer,
                memory,
            )?
        } else {
            state.prior_digest
        };
        state.memory_peak_bytes = state.memory_peak_bytes.max(memory.peak());
        if key.matches_record(record, digest) {
            if found.replace(index).is_some() {
                return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
            }
        }
    }
    found
        .and_then(|index| index.checked_add(1))
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))
}

pub(super) fn materialize_page(
    records: crate::memory::RecordBuffer,
    start: usize,
    end: usize,
    memory: &mut crate::memory::QueryMemory,
) -> Result<Vec<crate::QueryRecord>, QueryFailure> {
    if start > end || end > records.len() {
        return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
    }
    let mut page = crate::memory::RecordBuffer::allocate(end - start, memory)?;
    let (records, input_slots, _) = records.into_parts();
    for (index, record) in records.into_iter().enumerate() {
        let dynamic_bytes = record.retained_dynamic_bytes()?;
        if (start..end).contains(&index) {
            page.push_acquired(record, dynamic_bytes)?;
        } else {
            memory.release(dynamic_bytes)?;
        }
    }
    memory.release(input_slots)?;
    Ok(page.into_parts().0)
}
