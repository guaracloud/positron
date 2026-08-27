use std::sync::Arc;

use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::Catalog;
use positron_kernel::{ActiveSegmentLedger, SegmentScope};
use positron_query::{
    QueryBudget, QueryFailureCode, QueryService, TailCursor, TailEvent, TailStart,
};

use super::tail_fuzz_support::{
    Branches, FuzzClock, FuzzRoot, FuzzWorkMeter, append_valid, budget, credential, describe, plan,
    query_context, sources,
};

pub(super) fn run(data: &[u8]) {
    if let Err(error) = run_checked(data) {
        panic!("tail state-machine fuzz invariant failed: {error}");
    }
}

fn run_checked(data: &[u8]) -> Result<(), String> {
    let root = FuzzRoot::new()?;
    let paths = root.paths()?;
    super::InstanceBootstrap::initialize(&paths, super::InitializationPlan::non_interactive())
        .map_err(describe)?;
    let claim = super::InstanceBootstrap::claim(&paths).map_err(describe)?;
    let instance = super::InstanceBootstrap::reopen(&paths).map_err(describe)?;
    let credential = credential(&claim)?;
    let context = query_context(&instance, credential)?;
    let secret = instance
        .key
        .catalog_secret(instance.instance)
        .map_err(describe)?;
    let catalog =
        Catalog::open(&instance._authority, instance.instance, secret).map_err(describe)?;
    let second_shard = VirtualShardId::new(2).map_err(describe)?;
    if second_shard == instance.logs_shard {
        return Err("fuzz fixture selected the primary shard twice".to_owned());
    }
    let first_scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    let second_scope = SegmentScope::new(instance.tenant, SignalKind::Logs, second_shard);
    let first_key = instance
        .key
        .segment_key(instance.instance, first_scope)
        .map_err(describe)?;
    let second_key = instance
        .key
        .segment_key(instance.instance, second_scope)
        .map_err(describe)?;
    let first_ledger =
        ActiveSegmentLedger::open(&instance._authority, &catalog, first_scope, first_key)
            .map_err(describe)?;
    let second_ledger =
        ActiveSegmentLedger::open(&instance._authority, &catalog, second_scope, second_key)
            .map_err(describe)?;
    append_valid(
        &instance._authority,
        &first_ledger,
        instance.tenant,
        instance.logs_shard,
        1,
        90,
        "first-historical",
    )?;
    append_valid(
        &instance._authority,
        &second_ledger,
        instance.tenant,
        second_shard,
        2,
        1,
        "second-historical",
    )?;
    let service = QueryService::with_runtime(
        instance._authority.governor(),
        &first_ledger,
        1,
        Arc::new(FuzzClock),
        Arc::new(FuzzWorkMeter),
    );
    let source = "pipeline:v1 logs | range query_time -100 100 | limit 16";
    let baseline = instance
        ._authority
        .governor()
        .inspect()
        .map_err(describe)?
        .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
    let mut branches = Branches::default();
    {
        let query = plan(&service, context, source, budget()?)?;
        let mut session = service
            .tail_with_sources(
                query,
                TailStart::Historical { max_rows: 1 },
                sources(&first_ledger, &second_ledger)?,
            )
            .map_err(|error| format!("initial tail: {error:?}"))?;
        if !matches!(session.poll(), Some(TailEvent::Header(_))) {
            return Err("tail fuzz did not emit its header".to_owned());
        }
        let first = match session.poll() {
            Some(TailEvent::Batch(batch)) => {
                branches.polls += 1;
                (batch.sequence(), batch.digest())
            },
            event => return Err(format!("tail fuzz missing first batch: {event:?}")),
        };
        for _ in 0..2 {
            let repeated = match session.poll() {
                Some(TailEvent::Batch(batch)) => batch,
                event => return Err(format!("tail fuzz repeat missing: {event:?}")),
            };
            branches.polls += 1;
            if (repeated.sequence(), repeated.digest()) != first {
                return Err("tail fuzz repeated batch identity changed".to_owned());
            }
            branches.repeats += 1;
        }
        match session.acknowledge(first.0, [0xA5; 32]) {
            Err(failure) if failure.code() == QueryFailureCode::InvalidCursor => {
                branches.acknowledgements += 1;
            },
            result => return Err(format!("tail fuzz malformed ack outcome: {result:?}")),
        }
        session
            .acknowledge(first.0, first.1)
            .map_err(|error| format!("initial ack: {error:?}"))?;
        branches.acknowledgements += 1;
        let cursor = session.cursor().clone();
        session.disconnect();
        if !matches!(session.poll(), Some(TailEvent::Terminal(_))) {
            return Err("tail fuzz disconnect did not terminate".to_owned());
        }
        drop(session);
        let query = plan(&service, context, source, budget()?)?;
        let mut resumed = service
            .resume_tail_with_sources(query, &cursor, sources(&first_ledger, &second_ledger)?)
            .map_err(|error| format!("resume tail: {error:?}"))?;
        branches.resumes += 1;
        if !matches!(resumed.poll(), Some(TailEvent::Header(_))) {
            return Err("tail fuzz valid resume did not emit a header".to_owned());
        }
        let mut forged_bytes = cursor.as_bytes().to_vec();
        let forged_byte = forged_bytes
            .get_mut(24)
            .ok_or_else(|| "tail fuzz cursor unexpectedly too short".to_owned())?;
        *forged_byte ^= 1;
        let forged = TailCursor::from_bytes(&forged_bytes).map_err(describe)?;
        let query = plan(&service, context, source, budget()?)?;
        match service.resume_tail_with_sources(
            query,
            &forged,
            sources(&first_ledger, &second_ledger)?,
        ) {
            Err(_) => branches.forged += 1,
            Ok(_) => return Err("tail fuzz forged cursor resumed".to_owned()),
        }
        match TailCursor::from_bytes(&[0; 1]) {
            Err(_) => branches.malformed += 1,
            Ok(_) => return Err("tail fuzz malformed cursor was accepted".to_owned()),
        }
        match resumed.poll() {
            Some(TailEvent::Batch(batch)) => {
                branches.polls += 1;
                resumed
                    .acknowledge(batch.sequence(), batch.digest())
                    .map_err(|error| format!("resume ack: {error:?}"))?;
                branches.acknowledgements += 1;
            },
            Some(TailEvent::Idle) => {},
            event => return Err(format!("tail fuzz resumed follow outcome: {event:?}")),
        }
        let query = plan(&service, context, source, budget()?)?;
        let mut cancelled = service
            .tail_with_sources(
                query,
                TailStart::Now,
                sources(&first_ledger, &second_ledger)?,
            )
            .map_err(|error| format!("cancellation tail: {error:?}"))?;
        if !matches!(cancelled.poll(), Some(TailEvent::Header(_))) {
            return Err("tail fuzz cancellation session missing header".to_owned());
        }
        cancelled.cancel();
        if !matches!(cancelled.poll(), Some(TailEvent::Terminal(_))) {
            return Err("tail fuzz cancellation did not terminate".to_owned());
        }
        branches.cancellations += 1;
        drop(cancelled);
        let low_budget = QueryBudget::new(1, 16, 16, 1_048_576, 1_048_576, 60)
            .map_err(describe)?
            .with_cpu_work_units(1)
            .map_err(describe)?;
        let query = plan(&service, context, source, low_budget)?;
        let mut budgeted = service
            .tail_with_sources(
                query,
                TailStart::Now,
                sources(&first_ledger, &second_ledger)?,
            )
            .map_err(|error| format!("budget tail: {error:?}"))?;
        if !matches!(budgeted.poll(), Some(TailEvent::Header(_))) {
            return Err("tail fuzz budget session missing header".to_owned());
        }
        if !matches!(budgeted.poll(), Some(TailEvent::Terminal(_))) {
            return Err("tail fuzz budget was not observed".to_owned());
        }
        branches.budgets += 1;
        for action in data.iter().copied().take(256) {
            match action % 4 {
                0 => match resumed.poll() {
                    Some(
                        TailEvent::Header(_)
                        | TailEvent::Batch(_)
                        | TailEvent::Idle
                        | TailEvent::Terminal(_),
                    ) => branches.polls += 1,
                    None => branches.polls += 1,
                },
                1 => {
                    let query = plan(&service, context, source, budget()?)?;
                    match service.resume_tail_with_sources(
                        query,
                        &cursor,
                        sources(&first_ledger, &second_ledger)?,
                    ) {
                        Ok(next) => {
                            resumed = next;
                            branches.resumes += 1;
                        },
                        Err(failure) if failure.code() == QueryFailureCode::StoreUnavailable => {
                            branches.resumes += 1;
                            break;
                        },
                        Err(failure) => {
                            return Err(format!("action resume: {failure:?}"));
                        },
                    }
                },
                2 => {
                    resumed.disconnect();
                    match resumed.poll() {
                        Some(TailEvent::Header(_)) => {
                            let event = resumed.poll();
                            if !matches!(event, Some(TailEvent::Terminal(_)) | None) {
                                return Err(format!(
                                    "tail fuzz action disconnect did not terminate: {event:?}"
                                ));
                            }
                        },
                        Some(TailEvent::Terminal(_)) | None => {},
                        event => {
                            return Err(format!("tail fuzz action disconnect emitted {event:?}"));
                        },
                    }
                    let query = plan(&service, context, source, budget()?)?;
                    match service.resume_tail_with_sources(
                        query,
                        &cursor,
                        sources(&first_ledger, &second_ledger)?,
                    ) {
                        Ok(next) => {
                            resumed = next;
                            branches.resumes += 1;
                        },
                        Err(failure) if failure.code() == QueryFailureCode::StoreUnavailable => {
                            branches.resumes += 1;
                            break;
                        },
                        Err(failure) => {
                            return Err(format!("action disconnect resume: {failure:?}"));
                        },
                    }
                },
                3 => {
                    resumed.cancel();
                    match resumed.poll() {
                        Some(TailEvent::Header(_)) => {
                            let event = resumed.poll();
                            if !matches!(event, Some(TailEvent::Terminal(_)) | None) {
                                return Err(format!(
                                    "tail fuzz action cancellation did not terminate: {event:?}"
                                ));
                            }
                        },
                        Some(TailEvent::Terminal(_)) | None => {},
                        event => {
                            return Err(format!("tail fuzz action cancellation emitted {event:?}"));
                        },
                    }
                    branches.cancellations += 1;
                },
                _ => return Err("tail fuzz action dispatch escaped its bound".to_owned()),
            }
        }
    }
    let remaining = instance
        ._authority
        .governor()
        .inspect()
        .map_err(describe)?
        .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
    if remaining != baseline {
        return Err(format!(
            "tail fuzz leaked query-tail capacity: {baseline} -> {remaining}"
        ));
    }
    branches.cleanup += 1;
    if branches.polls == 0
        || branches.repeats == 0
        || branches.acknowledgements == 0
        || branches.resumes == 0
        || branches.forged == 0
        || branches.malformed == 0
        || branches.cancellations == 0
        || branches.budgets == 0
        || branches.cleanup == 0
    {
        return Err("tail fuzz did not reach every required public branch".to_owned());
    }
    Ok(())
}
