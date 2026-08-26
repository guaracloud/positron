//! Native bounded query planning and execution.

#![forbid(unsafe_code)]

mod attribute_syntax;
mod budget;
mod cancellation;
mod cursor;
mod execution;
mod execution_state;
mod execution_support;
mod failure;
#[cfg(fuzzing)]
mod fuzzing;
mod memory;
mod native_literal;
mod operators;
mod plan;
mod planning_memory;
mod planning_observer;
mod planning_string;
mod query_service;
mod quoted;
mod result_key;
mod runtime;
mod search;
mod search_transfer;
mod service;
mod sql;
mod sql_helpers;
mod sql_lexer;
mod sql_selection;
mod stream;
mod stream_lifecycle;
mod tail;
mod transform;

pub use budget::{QueryBudget, QueryBudgetDimension};
pub use cancellation::QueryCancellation;
pub use cursor::QueryCursor;
pub use failure::{QueryFailure, QueryFailureCode};
pub use plan::{LogicalPlan, OrderDirection, PlannedQuery, TemporalAxis, TemporalRange};
pub use query_service::QueryService;
pub use runtime::{
    QueryClock, QueryClockFailure, QueryWorkFailure, QueryWorkMeter, QueryWorkStage,
};
pub use stream::{
    QueryBatch, QueryEvent, QueryHeader, QueryIncomplete, QueryRecord, QueryStats, QueryTerminal,
    ResultLease, ResultOrdering, ResultSchema, ResultSnapshot, ResultValueType,
};
pub use stream_lifecycle::QueryStream;
#[cfg(feature = "test-support")]
pub use tail::fail_next_encode as fail_next_tail_cursor_encode;
pub use tail::{
    TailCursor, TailCursorState, TailEvent, TailPosition, TailSession, TailSourceSet, TailStart,
    TailStats, TailTerminal,
};

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_inputs(data: &[u8]) {
    if data.len() > 4_096 {
        return;
    }
    if let Ok(source) = std::str::from_utf8(data) {
        let memory = planning_memory::PlanningMemory::new(4_096);
        let _ = service::parse_pipeline(source, &memory);
        let memory = planning_memory::PlanningMemory::new(4_096);
        let _ = service::parse_sql(source, &memory);
    }
    fuzz_query_cursor(data);
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_cursor(data: &[u8]) {
    const MAX_FUZZ_INPUT_BYTES: usize = 65_536;
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }
    let parsed = QueryCursor::from_bytes(data);
    if let Ok(cursor) = parsed {
        assert_eq!(cursor.as_bytes(), data);
        let reparsed = QueryCursor::from_bytes(cursor.as_bytes())
            .expect("a bounded cursor must remain decodable after a lossless copy");
        assert_eq!(reparsed, cursor);
    }
    if matches!(data.len(), 341 | 373 | 4_545) {
        assert!(QueryCursor::from_bytes(&data[..data.len() - 1]).is_err());
    }

    let protector = positron_kernel::fuzz_control_token_protector();
    let tenant = positron_domain::identity::TenantId::from_bytes([2; 16])
        .expect("fuzz tenant fixture is valid");
    let principal = positron_domain::identity::PrincipalId::from_bytes([1; 16])
        .expect("fuzz principal fixture is valid");
    let range = TemporalRange::new(-100, 100).expect("fuzz range is ordered");
    let plan = LogicalPlan::logs(TemporalAxis::QueryTime, range, 1);
    let source = b"pipeline:v1 logs | range query_time -100 100 | limit 1";
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 16_384, 60)
        .expect("fuzz budget is valid")
        .with_cpu_work_units(1_024)
        .expect("fuzz CPU budget is valid");
    let parsed_plan = service::parse_pipeline(
        std::str::from_utf8(source).expect("fixture source is UTF-8"),
        &planning_memory::PlanningMemory::new(budget.memory_bytes()),
    )
    .expect("fixture source parses");
    let plan_digest = parsed_plan
        .canonical_digest(&protector)
        .expect("fixture plan digest is bounded");
    let state = cursor::CursorState {
        principal,
        tenant,
        authorization_generation: 7,
        catalog_identity: [3; 32],
        catalog_generation: 8,
        frontier: 1,
        plan: std::sync::Arc::new(plan),
        source: Some(std::sync::Arc::from(source.to_vec().into_boxed_slice())),
        language: Some(query_service::QueryLanguage::Pipeline),
        plan_digest,
        resume_key: None,
        sequence: 0,
        prior_digest: [0; 32],
        lease_identity: [4; 16],
        expiry: 60,
        budget,
        scanned_bytes: 0,
        decoded_records: 0,
        physical_scanned_bytes: 0,
        physical_decoded_records: 0,
        output_rows: 0,
        output_bytes: 0,
        physical_output_rows: 0,
        physical_output_bytes: 0,
        memory_peak_bytes: 512,
        physical_memory_peak_bytes: 512,
        started_at: 0,
        last_observed_at: 0,
        cpu_work_units: 0,
        elapsed_wall_seconds: 0,
        physical_cpu_work_units: 0,
        physical_elapsed_wall_seconds: 0,
        reduced_pruning: true,
        resume_count: 0,
        repeated_batch_count: 0,
        cancellation: QueryCancellation::new(),
    };
    let canonical = cursor::encode(&protector, state).expect("fuzz cursor fixture is valid");
    let decoded = cursor::decode(&protector, &canonical).expect("fixture must authenticate");
    assert_eq!(decoded.principal, principal);
    assert_eq!(decoded.tenant, tenant);
    assert_eq!(decoded.authorization_generation, 7);
    assert_eq!(decoded.frontier, 1);
    assert_eq!(decoded.expiry, 60);
    assert_eq!(decoded.plan.limit(), 1);
    assert_eq!(decoded.memory_peak_bytes, 512);
    assert!(decoded.reduced_pruning);
    execution_state::validate_authorization(
        principal,
        tenant,
        7,
        decoded.principal,
        decoded.tenant,
        decoded.authorization_generation,
    )
    .expect("fixture authorization is valid");
    let _ = execution_state::commit_position(decoded.frontier);
    let source = std::str::from_utf8(
        decoded
            .source
            .as_deref()
            .expect("fixture source is retained"),
    )
    .expect("fixture source is UTF-8");
    let parsed = service::parse_pipeline(
        source,
        &planning_memory::PlanningMemory::new(decoded.budget.memory_bytes()),
    )
    .expect("fixture source parses");
    assert_eq!(parsed.limit(), decoded.plan.limit());
    let decoded_digest = parsed
        .canonical_digest(&protector)
        .expect("decoded plan digest is bounded");
    assert_eq!(decoded_digest, decoded.plan_digest);

    if !data.is_empty() {
        let mut variant = canonical.as_bytes().to_vec();
        const MUTATION_OFFSETS: [usize; 26] = [
            16,
            32,
            48,
            64,
            80,
            96,
            104,
            112,
            123,
            157,
            165,
            197,
            213,
            221,
            237,
            253,
            261,
            269,
            275,
            283,
            315,
            347,
            348,
            349,
            cursor::CURRENT_VERSION_START,
            cursor::CURRENT_VERSION_START + 1,
        ];
        for (index, byte) in data.iter().take(MUTATION_OFFSETS.len()).enumerate() {
            if let Some(slot) = variant.get_mut(MUTATION_OFFSETS[index]) {
                *slot ^= *byte;
            }
        }
        for (index, slot) in variant
            .get_mut(cursor::CURRENT_RESUME_KEY_START..cursor::CURRENT_RESUME_KEY_END)
            .into_iter()
            .flatten()
            .enumerate()
        {
            *slot ^= data[index % data.len()].wrapping_add(u8::try_from(index).unwrap_or(0));
        }
        for (index, slot) in variant
            .get_mut(cursor::CURRENT_AUTH_TAG_START..cursor::CURRENT_AUTH_TAG_END)
            .into_iter()
            .flatten()
            .enumerate()
        {
            *slot ^= data[index % data.len()];
        }
        let _ = cursor::fuzz_reauthenticate(&protector, &mut variant);
        if let Ok(cursor) = QueryCursor::from_bytes(&variant) {
            if let Ok(state) = cursor::decode(&protector, &cursor) {
                let _ = execution_state::validate_authorization(
                    principal,
                    tenant,
                    7,
                    state.principal,
                    state.tenant,
                    state.authorization_generation,
                );
                let _ = execution_state::commit_position(state.frontier);
                let _ = state.expiry.checked_sub(state.started_at);
            }
        }
    }
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_tail_cursor(data: &[u8]) {
    if data.len() > 4_096 {
        return;
    }
    let _ = QueryCursor::from_bytes(data);
    let protector = positron_kernel::fuzz_control_token_protector();
    let principal = positron_domain::identity::PrincipalId::from_bytes([1; 16])
        .expect("fuzz principal fixture is valid");
    let tenant = positron_domain::identity::TenantId::from_bytes([2; 16])
        .expect("fuzz tenant fixture is valid");
    let shard =
        positron_domain::routing::VirtualShardId::new(1).expect("fuzz shard fixture is valid");
    let state = tail::TailCursorState::new(
        principal,
        tenant,
        7,
        [3; 32],
        [5; 32],
        vec![tail::TailPosition::new(
            shard,
            positron_domain::routing::CommitPosition::origin(),
        )],
        60,
        0,
        [4; 32],
    )
    .expect("fuzz cursor state is valid");
    let cursor = tail::TailCursor::encode(&protector, &state).expect("fuzz cursor encodes");
    let decoded = tail::TailCursor::decode(&protector, &cursor).expect("fuzz cursor decodes");
    assert_eq!(decoded, state);
    let _ = tail::TailCursor::from_bytes(data);
    if !data.is_empty() {
        let mut mutated = cursor.as_bytes().to_vec();
        for (index, byte) in data.iter().enumerate().take(mutated.len()) {
            if let Some(slot) = mutated.get_mut(index) {
                *slot ^= *byte;
            }
        }
        let _ = tail::TailCursor::from_bytes(&mutated)
            .and_then(|cursor| tail::TailCursor::decode(&protector, &cursor));
    }
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_tail_state_machine(data: &[u8]) {
    const MAX_ROWS: usize = 64;
    const MAX_DELIVERED: usize = MAX_ROWS * 4;
    let protector = positron_kernel::fuzz_control_token_protector();
    let principal = positron_domain::identity::PrincipalId::from_bytes([1; 16])
        .expect("fuzz principal fixture is valid");
    let tenant = positron_domain::identity::TenantId::from_bytes([2; 16])
        .expect("fuzz tenant fixture is valid");
    let shard =
        positron_domain::routing::VirtualShardId::new(1).expect("fuzz shard fixture is valid");
    let mut state = tail::TailCursorState::new(
        principal,
        tenant,
        7,
        [3; 32],
        [5; 32],
        vec![tail::TailPosition::new(
            shard,
            positron_domain::routing::CommitPosition::origin(),
        )],
        4_096,
        0,
        [0; 32],
    )
    .expect("fuzz cursor state is valid");
    let mut cursor = tail::TailCursor::encode(&protector, &state).expect("fuzz cursor encodes");
    let mut committed = Vec::new();
    let mut delivered = Vec::new();
    let mut next = 1_u64;
    let mut next_delivery = 0_usize;
    let mut terminal_count = 0_u8;
    let mut connected = true;
    for action in data.iter().copied().take(4_096) {
        match action % 8 {
            0 if committed.len() < MAX_ROWS => {
                committed.push(next);
                next = next.saturating_add(1);
            },
            1 if connected && terminal_count == 0 => {
                if let Some(position) = committed.get(next_delivery).copied() {
                    if delivered.len() < MAX_DELIVERED {
                        delivered.push(position);
                        next_delivery = next_delivery.saturating_add(1);
                        let position = positron_domain::routing::CommitPosition::origin()
                            .advance_by(
                                std::num::NonZeroU64::new(position)
                                    .expect("fuzz positions are non-zero"),
                            )
                            .expect("fuzz position remains bounded");
                        state = state
                            .advance_batch(
                                &[tail::TailPosition::new(shard, position)],
                                [u8::try_from(position.value()).unwrap_or(u8::MAX); 32],
                            )
                            .expect("monotonic tail cursor advances");
                        cursor = tail::TailCursor::encode(&protector, &state)
                            .expect("advanced fuzz cursor encodes");
                    }
                }
            },
            2 => connected = false,
            3 if terminal_count == 0 => {
                connected = true;
                if next_delivery > 0 && delivered.len() < MAX_DELIVERED {
                    delivered.push(committed[next_delivery - 1]);
                }
            },
            4 | 5 if terminal_count == 0 => {
                terminal_count = 1;
                connected = false;
            },
            6 => {
                if let Ok(decoded) = tail::TailCursor::decode(&protector, &cursor) {
                    assert_eq!(decoded, state);
                }
            },
            _ => {},
        }
        assert!(committed.len() <= MAX_ROWS);
        assert!(delivered.len() <= MAX_DELIVERED);
        assert!(terminal_count <= 1);
        assert!(next_delivery <= committed.len());
        assert!(
            delivered
                .iter()
                .all(|position| committed.contains(position))
        );
        assert!(state.positions()[0].position().value() <= next);
    }
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_sql(data: &[u8]) {
    const MAX_RAW_BYTES: usize = 4_096;
    const MAX_PARITY_LITERAL_BYTES: usize = 512;
    let raw = bounded_lossy_query(data, MAX_RAW_BYTES);
    let first = service::parse_sql(&raw, &planning_memory::PlanningMemory::new(4_096));
    let second = service::parse_sql(&raw, &planning_memory::PlanningMemory::new(4_096));
    assert_eq!(query_classification(&first), query_classification(&second));
    if let (Ok(first), Ok(second)) = (&first, &second) {
        assert_eq!(first, second, "SQL plans must be deterministic");
    }

    let literal = bounded_lossy_query(data, MAX_PARITY_LITERAL_BYTES);
    let Some(literal) = escaped_query_literal(&literal) else {
        return;
    };
    let Some((sql, pipeline)) = parity_queries(&literal) else {
        return;
    };
    let sql_result = service::parse_sql(&sql, &planning_memory::PlanningMemory::new(4_096));
    let pipeline_result =
        service::parse_pipeline(&pipeline, &planning_memory::PlanningMemory::new(4_096));
    assert_eq!(
        query_classification(&sql_result),
        query_classification(&pipeline_result),
        "equivalent bounded frontends must classify identically"
    );
    if let (Ok(sql), Ok(pipeline)) = (&sql_result, &pipeline_result) {
        assert_eq!(sql, pipeline, "equivalent frontends must share one plan");
    }
}

#[cfg(fuzzing)]
fn bounded_lossy_query(data: &[u8], maximum_bytes: usize) -> String {
    let bounded = data.get(..data.len().min(maximum_bytes)).unwrap_or(data);
    let lossy = String::from_utf8_lossy(bounded);
    let mut output = String::new();
    if output
        .try_reserve_exact(lossy.len().min(maximum_bytes))
        .is_err()
    {
        return String::new();
    }
    for character in lossy.chars() {
        let Some(next_length) = output.len().checked_add(character.len_utf8()) else {
            break;
        };
        if next_length > maximum_bytes {
            break;
        }
        output.push(character);
    }
    output
}

#[cfg(fuzzing)]
fn escaped_query_literal(value: &str) -> Option<String> {
    let required = value.bytes().try_fold(0_usize, |length, byte| {
        length.checked_add(usize::from(matches!(byte, b'"' | b'\\' | b'|')))
    })?;
    let required = value.len().checked_add(required)?;
    let mut escaped = String::new();
    escaped.try_reserve_exact(required).ok()?;
    for character in value.chars() {
        if matches!(character, '"' | '\\' | '|') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    Some(escaped)
}

#[cfg(fuzzing)]
fn parity_queries(literal: &str) -> Option<(String, String)> {
    let sql_prefix =
        "SELECT body FROM logs WHERE query_time >= -100 AND query_time < 100 AND body = \"";
    let sql_suffix = "\" ORDER BY query_time, commit_position LIMIT 1";
    let pipeline_prefix = "pipeline:v1 logs | range query_time -100 100 | filter body == \"";
    let pipeline_suffix = "\" | limit 1";
    let mut sql = String::new();
    sql.try_reserve_exact(
        sql_prefix
            .len()
            .checked_add(literal.len())?
            .checked_add(sql_suffix.len())?,
    )
    .ok()?;
    sql.push_str(sql_prefix);
    sql.push_str(literal);
    sql.push_str(sql_suffix);
    let mut pipeline = String::new();
    pipeline
        .try_reserve_exact(
            pipeline_prefix
                .len()
                .checked_add(literal.len())?
                .checked_add(pipeline_suffix.len())?,
        )
        .ok()?;
    pipeline.push_str(pipeline_prefix);
    pipeline.push_str(literal);
    pipeline.push_str(pipeline_suffix);
    Some((sql, pipeline))
}

#[cfg(fuzzing)]
fn query_classification(
    result: &Result<LogicalPlan, QueryFailure>,
) -> (Option<QueryFailureCode>, Option<QueryBudgetDimension>) {
    match result {
        Ok(_) => (None, None),
        Err(failure) => (Some(failure.code()), failure.limiting_budget()),
    }
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_search_matcher(data: &[u8]) {
    if data.is_empty() || data.len() > 4_096 {
        return;
    }
    let pattern_len = usize::from(data[0]).min(data.len().saturating_sub(1));
    let (pattern, body) = data[1..].split_at(pattern_len);
    let Ok(pattern) = std::str::from_utf8(pattern) else {
        return;
    };
    let Ok(body) = std::str::from_utf8(body) else {
        return;
    };
    let Ok(mut regex) = search::BoundedRegex::from_source(pattern.to_owned()) else {
        return;
    };
    if regex.compile().is_err() {
        return;
    }
    let mut observer = search::UnobservedSearch;
    let _ = regex.is_match_observed(body, &mut observer);
    let Ok(mut substring) = search::BoundedSubstring::from_source(pattern.to_owned()) else {
        return;
    };
    if substring.compile().is_err() {
        return;
    }
    let _ = substring.is_match_observed(body, &mut observer);
    let literals = regex
        .pruning_literals()
        .iter()
        .map(|literal| literal.to_vec())
        .collect::<Vec<_>>();
    positron_signals::fuzz_text_search_pruning(body, &literals);
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_transforms(data: &[u8]) {
    fuzzing::fuzz_query_transforms(data);
}
