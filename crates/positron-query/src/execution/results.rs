use crate::cursor::CursorState;
use crate::execution_support::{QueryValueObserver, result_digest};
use crate::result_key::ResultResumeKey;
use crate::{QueryFailure, QueryFailureCode, QueryService};

pub(super) fn resume_key_for_page<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    page: &[crate::QueryRecord],
    needs_resume: bool,
    memory: &mut crate::memory::QueryMemory,
) -> Result<Option<ResultResumeKey>, QueryFailure> {
    if !needs_resume {
        return Ok(None);
    }
    let record = page
        .last()
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    let cancellation = state.cancellation.clone();
    let mut observer = QueryValueObserver::new(
        service,
        &mut state.physical_cpu_work_units,
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
    state.physical_memory_peak_bytes = state.physical_memory_peak_bytes.max(memory.peak());
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
        let cancellation = state.cancellation.clone();
        let mut observer = QueryValueObserver::new(
            service,
            &mut state.physical_cpu_work_units,
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
        state.physical_memory_peak_bytes = state.physical_memory_peak_bytes.max(memory.peak());
        if key.matches_record(record, digest) {
            remember_match(&mut found, index)?;
        }
    }
    found
        .and_then(|index| index.checked_add(1))
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))
}

fn remember_match(found: &mut Option<usize>, index: usize) -> Result<(), QueryFailure> {
    if found.replace(index).is_some() {
        Err(QueryFailure::new(QueryFailureCode::InvalidCursor))
    } else {
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::{materialize_page, remember_match};
    use crate::QueryFailureCode;
    use crate::memory::{QueryMemory, RecordBuffer};

    #[test]
    fn materialization_rejects_an_invalid_resume_window_before_allocation() {
        let mut memory = QueryMemory::new(1_024);
        let records = RecordBuffer::allocate(0, &mut memory).expect("empty input fits");
        assert_eq!(
            materialize_page(records, 1, 0, &mut memory)
                .expect_err("resume window cannot run backwards")
                .code(),
            QueryFailureCode::InvalidCursor
        );
    }

    #[test]
    fn duplicate_resume_matches_fail_closed_instead_of_selecting_one_row() {
        let mut found = Some(0);
        assert_eq!(
            remember_match(&mut found, 1)
                .expect_err("ambiguous resume frontier must fail closed")
                .code(),
            QueryFailureCode::InvalidCursor
        );
    }
}
