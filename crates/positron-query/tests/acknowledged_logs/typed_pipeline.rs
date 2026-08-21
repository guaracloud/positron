use std::error::Error;
use std::sync::Arc;

use positron_kernel::{SnapshotLeaseId, WorkClass};
use positron_query::{
    OrderDirection, QueryBudget, QueryEvent, QueryFailureCode, QueryService, QueryTerminal,
    ResultValueType,
};

use super::support::{
    BlockingOperatorWorkMeter, CancellingStageWorkMeter, SequenceClock, TestClock,
};
use super::terminal_and_bounds::QueryFixture;

type OrderedBodyBatch = (Vec<(String, u16)>, [u8; 32]);

#[test]
fn typed_projection_bytes_obey_the_exact_output_budget() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-projection-bytes")?;
    fixture.kernel.append_log("body-is-not-selected", 20, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source = "pipeline:v1 logs | range query_time -100 100 | project query_time, commit_position | limit 1";

    let exact = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 1, 16, 1_048_576, 60)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 1 && stats.output_bytes() == 16
    ));

    let exhausted = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 1, 15, 1_048_576, 60)?,
    )?;
    let exhausted_events = service.execute(exhausted)?.collect::<Vec<_>>();
    assert!(
        !exhausted_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        exhausted_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
    ));
    Ok(())
}

#[test]
fn projection_preserves_query_time_and_optional_event_time_simultaneously()
-> Result<(), Box<dyn Error>> {
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("event-time-projection")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(20),
                Some(CandidateAttributeValue::string("event".to_owned())),
            ),
            (
                None,
                Some(CandidateAttributeValue::string("missing".to_owned())),
            ),
        ],
        1,
    )?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time 0 100 | project query_time, event_time | limit 2",
        QueryBudget::new(1_048_576, 2, 2, 64, 1_048_576, 60)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("result header missing")?;
    assert_eq!(header.schema().columns(), ["query_time", "event_time"]);
    assert_eq!(
        header.schema().types(),
        [
            ResultValueType::UnixNanoseconds,
            ResultValueType::OptionalUnixNanoseconds,
        ]
    );
    let records = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("result batch missing")?;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].query_time().value(), 20);
    assert_eq!(records[0].event_time().map(|time| time.value()), Some(20));
    assert_eq!(records[1].query_time().value(), 50);
    assert_eq!(records[1].event_time(), None);
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 2 && stats.output_bytes() == 26
    ));
    Ok(())
}

#[test]
fn event_time_grouping_orders_missing_before_present_on_a_query_time_range()
-> Result<(), Box<dyn Error>> {
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("event-time-grouping")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(20),
                Some(CandidateAttributeValue::string("one".to_owned())),
            ),
            (
                None,
                Some(CandidateAttributeValue::string("missing".to_owned())),
            ),
            (
                Some(20),
                Some(CandidateAttributeValue::string("two".to_owned())),
            ),
        ],
        1,
    )?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time 0 100 | aggregate count by event_time | limit 3",
        QueryBudget::new(1_048_576, 3, 3, 64, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    let records = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("grouped result batch missing")?;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].event_time(), None);
    assert_eq!(records[0].count(), Some(1));
    assert_eq!(records[1].event_time().map(|time| time.value()), Some(20));
    assert_eq!(records[1].count(), Some(2));
    Ok(())
}

#[test]
fn event_time_range_excludes_records_without_event_time() -> Result<(), Box<dyn Error>> {
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("event-time-range-missing")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(20),
                Some(CandidateAttributeValue::string("event".to_owned())),
            ),
            (
                None,
                Some(CandidateAttributeValue::string("missing".to_owned())),
            ),
        ],
        1,
    )?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range event_time 0 100 | project query_time, event_time | limit 2",
        QueryBudget::new(1_048_576, 2, 2, 32, 1_048_576, 60)?,
    )?;

    let records = service
        .execute(query)?
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records().to_vec()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("event-time result batch missing")?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].query_time().value(), 20);
    assert_eq!(records[0].event_time().map(|time| time.value()), Some(20));
    Ok(())
}

#[test]
fn empty_string_body_equality_remains_distinct_from_a_missing_body() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("empty-body-equality")?;
    fixture.kernel.append_log_bodies(
        vec![
            Some(positron_domain::value::CandidateAttributeValue::string(
                String::new(),
            )),
            None,
        ],
        20,
        1,
    )?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"\" | limit 2",
        QueryBudget::new(1_048_576, 2, 2, 64, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let records = service
        .execute(query)?
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records().to_vec()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("result batch missing")?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body_text(), Some(""));
    Ok(())
}

#[test]
fn quoted_pipeline_literals_preserve_stage_delimiters_as_body_data() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("quoted-stage-delimiter")?;
    fixture.kernel.append_log("a|b", 20, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"a|b\" | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 16, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let records = service
        .execute(query)?
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records().to_vec()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("result batch missing")?;

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body_text(), Some("a|b"));
    Ok(())
}

#[test]
fn escaped_pipeline_literals_round_trip_quote_backslash_and_pipe() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("escaped-body-literal")?;
    fixture.kernel.append_log("a\"b\\c|d", 20, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | filter body == "a\"b\\c\|d" | limit 1"#,
        QueryBudget::new(1_048_576, 1, 1, 32, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let record = service
        .execute(query)?
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().first().cloned(),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("result record missing")?;

    assert_eq!(record.body_text(), Some("a\"b\\c|d"));
    Ok(())
}

#[test]
fn grouping_and_projection_preserve_every_native_body_kind_without_coercion()
-> Result<(), Box<dyn Error>> {
    use positron_domain::value::{CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile};

    let fixture = QueryFixture::new("native-body-values")?;
    let candidates = vec![
        CandidateAttributeValue::null(),
        CandidateAttributeValue::boolean(true),
        CandidateAttributeValue::signed_integer(7),
        CandidateAttributeValue::floating_point_bits((-0.0_f64).to_bits()),
        CandidateAttributeValue::floating_point_bits(0.0_f64.to_bits()),
        CandidateAttributeValue::floating_point_bits(0x7ff8_0000_0000_0001),
        CandidateAttributeValue::floating_point_bits(0xfff8_0000_0000_0001),
        CandidateAttributeValue::string(String::new()),
        CandidateAttributeValue::bytes(vec![0, 255]),
        CandidateAttributeValue::array(vec![
            CandidateAttributeValue::boolean(false),
            CandidateAttributeValue::signed_integer(1),
        ]),
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "k".to_owned(),
            CandidateAttributeValue::null(),
        )]),
    ];
    let expected = candidates
        .iter()
        .cloned()
        .map(|candidate| {
            candidate
                .validate_log_body(ValueLimitProfile::release_1_system_maximum())
                .map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut bodies = vec![None];
    bodies.extend(candidates.into_iter().map(Some));
    fixture.kernel.append_log_bodies(bodies, 20, 1)?;

    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 12",
        QueryBudget::new(1_048_576, 12, 12, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let records = service
        .execute(query)?
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records().to_vec()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("native grouped result batch missing")?;
    assert_eq!(records.len(), 12);
    assert_eq!(
        records
            .iter()
            .filter(|record| record.body_value().is_none() && record.count() == Some(1))
            .count(),
        1
    );
    for value in &expected {
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.body_value() == Some(value) && record.count() == Some(1)
                })
                .count(),
            1
        );
    }
    Ok(())
}

#[test]
fn projection_preserves_missing_and_native_body_values() -> Result<(), Box<dyn Error>> {
    use positron_domain::value::{CandidateAttributeValue, ValueLimitProfile};

    let fixture = QueryFixture::new("native-body-projection")?;
    let expected = [
        CandidateAttributeValue::boolean(false)
            .validate_log_body(ValueLimitProfile::release_1_system_maximum())?,
        CandidateAttributeValue::bytes(vec![1, 2, 3])
            .validate_log_body(ValueLimitProfile::release_1_system_maximum())?,
    ];
    fixture.kernel.append_log_bodies(
        vec![
            None,
            Some(CandidateAttributeValue::boolean(false)),
            Some(CandidateAttributeValue::bytes(vec![1, 2, 3])),
        ],
        10,
        1,
    )?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source = "pipeline:v1 logs | range query_time -100 100 | project body | limit 3";
    let query = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 3, 3, 17, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let records = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("native projection batch missing")?;

    assert_eq!(records.len(), 3);
    assert_eq!(records[0].body_value(), None);
    assert_eq!(records[1].body_value(), Some(&expected[0]));
    assert_eq!(records[2].body_value(), Some(&expected[1]));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.output_bytes() == 17
    ));

    let exhausted = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 3, 3, 16, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let exhausted_events = service.execute(exhausted)?.collect::<Vec<_>>();
    assert!(
        !exhausted_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        exhausted_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().output_bytes() == 0
    ));
    Ok(())
}

#[test]
fn version_one_equality_rejects_non_string_literal_syntax() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("native-filter-boundary")?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );

    for literal in ["true", "7", "null", "[1]"] {
        let source = format!("pipeline:v1 logs | filter body == {literal} | limit 1");
        let failure = match service.plan_pipeline(
            fixture.context,
            &source,
            QueryBudget::new(1_048_576, 1, 1, 64, 1_048_576, 60)?,
        ) {
            Ok(_) => return Err("version one accepted a non-string equality literal".into()),
            Err(failure) => failure,
        };
        assert_eq!(failure.code(), QueryFailureCode::UnsupportedQuery);
    }
    Ok(())
}

#[test]
fn typed_count_bytes_obey_the_exact_output_budget() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-count-bytes")?;
    fixture.kernel.append_log("counted", 20, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source = "pipeline:v1 logs | range query_time -100 100 | aggregate count | limit 1";

    let exact = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 1, 8, 1_048_576, 60)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 1 && stats.output_bytes() == 8
    ));

    let exhausted = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 1, 7, 1_048_576, 60)?,
    )?;
    let exhausted_events = service.execute(exhausted)?.collect::<Vec<_>>();
    assert!(
        !exhausted_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        exhausted_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
    ));
    Ok(())
}

#[test]
fn result_header_preserves_both_total_order_directions() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-order-header")?;
    fixture.kernel.append_log("ordered", 20, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | project body, query_time, commit_position | order by query_time desc, commit_position asc | limit 1",
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = match events.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("query header missing".into()),
    };
    assert_eq!(
        header.ordering().columns(),
        ["query_time", "commit_position", "record_ordinal"]
    );
    assert_eq!(
        header.ordering().directions(),
        [
            OrderDirection::Descending,
            OrderDirection::Ascending,
            OrderDirection::Ascending,
        ]
    );
    assert_eq!(
        header.schema().types(),
        [
            ResultValueType::NativeValue,
            ResultValueType::UnixNanoseconds,
            ResultValueType::CommitPosition,
        ]
    );
    assert_eq!(
        header.ordering().types(),
        [
            ResultValueType::UnixNanoseconds,
            ResultValueType::CommitPosition,
            ResultValueType::RecordOrdinal,
        ]
    );
    Ok(())
}

#[test]
fn grouped_schema_describes_native_keys_and_unsigned_counts() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-group-schema")?;
    fixture.kernel.append_log("group", 20, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time, commit_position | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = match events.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("grouped query header missing".into()),
    };

    assert_eq!(
        header.schema().columns(),
        ["body", "query_time", "commit_position", "count"]
    );
    assert_eq!(
        header.schema().types(),
        [
            ResultValueType::NativeValue,
            ResultValueType::UnixNanoseconds,
            ResultValueType::CommitPosition,
            ResultValueType::UnsignedInteger,
        ]
    );
    assert_eq!(
        header.ordering().types(),
        [
            ResultValueType::NativeValue,
            ResultValueType::UnixNanoseconds,
            ResultValueType::CommitPosition,
        ]
    );
    Ok(())
}

#[test]
fn batch_digest_binds_the_complete_typed_projection_and_repeats_stably()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-projection-digest")?;
    fixture.kernel.append_log("not-selected", 1, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let budget = QueryBudget::new(1_048_576, 16, 1, 16, 1_048_576, 60)?;

    let digest_for = |source| -> Result<[u8; 32], Box<dyn Error>> {
        let query = service.plan_pipeline(fixture.context, source, budget)?;
        service
            .execute(query)?
            .find_map(|event| match event {
                QueryEvent::Batch(batch) => Some(batch.digest()),
                QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
            })
            .ok_or_else(|| "result batch missing".into())
    };
    let query_time = "pipeline:v1 logs | range query_time -100 100 | project query_time | limit 1";
    let commit_position =
        "pipeline:v1 logs | range query_time -100 100 | project commit_position | limit 1";
    let event_time = "pipeline:v1 logs | range query_time -100 100 | project event_time | limit 1";
    let descending_query_time = "pipeline:v1 logs | range query_time -100 100 | project query_time | order by query_time desc, commit_position desc | limit 1";

    let first = digest_for(query_time)?;
    assert_eq!(first, digest_for(query_time)?);
    assert_ne!(first, digest_for(commit_position)?);
    assert_ne!(first, digest_for(event_time)?);
    assert_ne!(first, digest_for(descending_query_time)?);
    Ok(())
}

#[test]
fn same_time_records_in_one_block_have_a_stable_total_identity_across_reopen()
-> Result<(), Box<dyn Error>> {
    let mut fixture = QueryFixture::new("same-block-total-order")?;
    fixture.kernel.append_log_bodies(
        ["first", "second", "duplicate", "duplicate"]
            .into_iter()
            .map(|body| {
                Some(positron_domain::value::CandidateAttributeValue::string(
                    body.to_owned(),
                ))
            })
            .collect(),
        20,
        1,
    )?;

    let execute = |fixture: &QueryFixture| -> Result<OrderedBodyBatch, Box<dyn Error>> {
        let service = QueryService::new(
            fixture.kernel.authority.governor(),
            fixture.kernel.ledger()?,
            16,
        );
        let query = service.plan_pipeline(
            fixture.context,
            "logs | range query_time -100 100 | limit 4",
            QueryBudget::new(1_048_576, 4, 4, 69, 1_048_576, 60)?.with_cpu_work_units(16)?,
        )?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        let header = events
            .iter()
            .find_map(|event| match event {
                QueryEvent::Header(header) => Some(header),
                QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
            })
            .ok_or("result header missing")?;
        assert_eq!(
            header.ordering().columns(),
            ["query_time", "commit_position", "record_ordinal"]
        );
        let batch = events
            .iter()
            .find_map(|event| match event {
                QueryEvent::Batch(batch) => Some(batch),
                QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
            })
            .ok_or("result batch missing")?;
        let records = batch
            .records()
            .iter()
            .map(|record| {
                Ok((
                    record.body_text().ok_or("body missing")?.to_owned(),
                    record.record_ordinal().value(),
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        Ok((records, batch.digest()))
    };

    let active = execute(&fixture)?;
    assert_eq!(
        active.0,
        [
            ("first".to_owned(), 0),
            ("second".to_owned(), 1),
            ("duplicate".to_owned(), 2),
            ("duplicate".to_owned(), 3),
        ]
    );
    fixture.kernel.seal_and_reopen()?;
    assert_eq!(execute(&fixture)?, active);
    Ok(())
}

#[test]
fn default_total_order_charges_every_comparison_and_exhausts_explicitly()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("default-sort-work")?;
    fixture.kernel.append_log("later", 20, 1)?;
    fixture.kernel.append_log("earlier", 10, 2)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source = "logs | range query_time -100 100 | limit 2";

    let exact = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 2, 2, 32, 1_048_576, 60)?.with_cpu_work_units(4)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.cpu_work_units() == 4
    ));

    let exhausted = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 2, 2, 32, 1_048_576, 60)?.with_cpu_work_units(3)?,
    )?;
    let exhausted_events = service.execute(exhausted)?.collect::<Vec<_>>();
    assert!(matches!(
        exhausted_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().cpu_work_units() == 4
    ));
    assert!(
        !exhausted_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    Ok(())
}

#[test]
fn ordinary_sort_and_grouping_enforce_canonical_peak_memory_boundaries()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-peak-memory")?;
    fixture.kernel.append_log("later", 20, 1)?;
    fixture.kernel.append_log("earlier", 10, 2)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let ordinary = "logs | range query_time -100 100 | limit 2";
    for (memory_bytes, expected_complete) in [(1_432, true), (1_431, false)] {
        let query = service.plan_pipeline(
            fixture.context,
            ordinary,
            QueryBudget::new(1_048_576, 2, 2, 32, memory_bytes, 60)?.with_cpu_work_units(16)?,
        )?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        assert_eq!(
            matches!(
                events.last(),
                Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
            ),
            expected_complete
        );
        if !expected_complete {
            assert!(matches!(
                events.last(),
                Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                    if incomplete.code() == QueryFailureCode::BudgetExhausted
            ));
        }
    }

    fixture.kernel.append_log("third", 30, 3)?;
    fixture.kernel.append_log("fourth", 40, 4)?;
    let grouped =
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 4";
    for (memory_bytes, expected_complete) in [(3_223, true), (3_222, false)] {
        let query = service.plan_pipeline(
            fixture.context,
            grouped,
            QueryBudget::new(1_048_576, 4, 4, 95, memory_bytes, 60)?.with_cpu_work_units(16)?,
        )?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        assert_eq!(
            matches!(
                events.last(),
                Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
            ),
            expected_complete
        );
        if !expected_complete {
            assert!(matches!(
                events.last(),
                Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                    if incomplete.code() == QueryFailureCode::BudgetExhausted
            ));
        }
    }
    Ok(())
}

#[test]
fn default_total_order_observes_cancellation_inside_sorting() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("default-sort-cancel")?;
    fixture.kernel.append_log("third", 30, 1)?;
    fixture.kernel.append_log("first", 10, 2)?;
    fixture.kernel.append_log("second", 20, 3)?;
    let meter = CancellingStageWorkMeter::shared(positron_query::QueryWorkStage::Operators);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 3",
        QueryBudget::new(1_048_576, 3, 3, 16, 1_048_576, 60)?,
    )?;
    meter.bind(query.cancellation())?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    Ok(())
}

#[test]
fn cancellation_interrupts_substantial_default_sort_work() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("default-sort-mid-cancel")?;
    for identity in 1_u8..=8 {
        fixture.kernel.append_log(
            &format!("record-{identity}"),
            i64::from(9_u8.saturating_sub(identity)),
            identity,
        )?;
    }
    let meter = BlockingOperatorWorkMeter::shared(3);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "logs | range query_time -100 100 | limit 8",
        QueryBudget::new(1_048_576, 8, 8, 64, 1_048_576, 60)?,
    )?;
    let cancellation = query.cancellation();

    let events = std::thread::scope(|scope| -> Result<_, Box<dyn Error>> {
        let service = &service;
        let worker = scope.spawn(move || service.execute(query).map(Iterator::collect::<Vec<_>>));
        meter.wait_until_blocked()?;
        cancellation.cancel();
        meter.release()?;
        worker
            .join()
            .map_err(|_| "query execution thread panicked")?
            .map_err(Into::into)
    })?;
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, QueryEvent::Terminal(_)))
            .count(),
        1
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    Ok(())
}

#[test]
fn versioned_pipeline_rejects_operator_combinations_it_cannot_execute() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("typed-operator-combinations")?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let budget = QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?;
    for source in [
        "pipeline:v1 logs | range query_time -100 100 | project body | aggregate count | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | aggregate count | project body | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | aggregate count | order by query_time asc, commit_position asc | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | order by query_time asc, commit_position asc | filter body == \"late\" | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | project body | filter body == \"late\" | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | aggregate count | filter body == \"late\" | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"one\" | search body == \"two\" | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | project body | project query_time | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | aggregate count | aggregate count | limit 1",
    ] {
        let failure = service
            .plan_pipeline(fixture.context, source, budget)
            .err()
            .ok_or("unexecuted operator combination was accepted")?;
        assert_eq!(failure.code(), QueryFailureCode::UnsupportedQuery);
    }
    Ok(())
}

#[test]
fn grouped_count_emits_deterministic_typed_intrinsic_rows() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-grouped-count")?;
    fixture.kernel.append_log("beta", 20, 1)?;
    fixture.kernel.append_log("alpha", 10, 2)?;
    fixture.kernel.append_log("beta", 20, 3)?;
    fixture.kernel.append_log("beta", 10, 4)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 91, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = match events.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("query header missing".into()),
    };
    assert_eq!(header.schema().columns(), ["body", "query_time", "count"]);
    assert_eq!(header.ordering().columns(), ["body", "query_time"]);
    assert_eq!(
        header.ordering().directions(),
        [OrderDirection::Ascending, OrderDirection::Ascending]
    );
    let groups = events
        .iter()
        .filter_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .flatten()
        .map(|record| {
            (
                record.body_text().map(str::to_owned),
                record.query_time().value(),
                record.count(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        groups,
        [
            (Some("alpha".to_owned()), 10, Some(1)),
            (Some("beta".to_owned()), 10, Some(1)),
            (Some("beta".to_owned()), 20, Some(2)),
        ]
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 3 && stats.output_bytes() == 91
    ));

    let output_exhausted = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 90, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let output_events = service.execute(output_exhausted)?.collect::<Vec<_>>();
    assert!(
        !output_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        output_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
    ));

    let memory_exhausted = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 91, 8_737, 60)?.with_cpu_work_units(16)?,
    )?;
    let memory_events = service.execute(memory_exhausted)?.collect::<Vec<_>>();
    assert!(
        !memory_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        memory_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
    ));

    let work_exhausted = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 91, 1_048_576, 60)?.with_cpu_work_units(5)?,
    )?;
    let work_events = service.execute(work_exhausted)?.collect::<Vec<_>>();
    assert!(
        !work_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        work_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().cpu_work_units() == 6
    ));

    let commit_groups = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by commit_position | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 64, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let commit_events = service.execute(commit_groups)?.collect::<Vec<_>>();
    let commit_header = match commit_events.first() {
        Some(QueryEvent::Header(header)) => header,
        _ => return Err("commit grouping header missing".into()),
    };
    assert_eq!(
        commit_header.schema().columns(),
        ["commit_position", "count"]
    );
    assert_eq!(commit_header.ordering().columns(), ["commit_position"]);
    assert_eq!(
        commit_events
            .iter()
            .filter_map(|event| match event {
                QueryEvent::Batch(batch) => Some(batch.records()),
                QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
            })
            .flatten()
            .filter(|record| record.count() == Some(1))
            .count(),
        4
    );
    assert!(matches!(
        commit_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 4 && stats.output_bytes() == 64
    ));
    Ok(())
}

#[test]
fn cancellation_interrupts_grouping_and_releases_query_resources() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-group-cancellation")?;
    for identity in 1_u8..=8 {
        fixture
            .kernel
            .append_log(&format!("group-{identity}"), i64::from(identity), identity)?;
    }
    let meter = BlockingOperatorWorkMeter::shared(4);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        8,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let before = fixture
        .kernel
        .authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 8",
        QueryBudget::new(1_048_576, 8, 8, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let cancellation = query.cancellation();
    assert_eq!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before + 1
    );

    let events = std::thread::scope(|scope| -> Result<_, Box<dyn Error>> {
        let service = &service;
        let worker = scope.spawn(move || service.execute(query).map(Iterator::collect::<Vec<_>>));
        meter.wait_until_blocked()?;
        cancellation.cancel();
        meter.release()?;
        worker
            .join()
            .map_err(|_| "query execution thread panicked")?
            .map_err(Into::into)
    })?;
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, QueryEvent::Terminal(_)))
            .count(),
        1
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
    ));
    assert_eq!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before
    );
    let lease = events.iter().find_map(|event| match event {
        QueryEvent::Header(header) => Some(header.lease().identity()),
        QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
    });
    let lease = SnapshotLeaseId::new(lease.ok_or("cancelled query header missing")?)?;
    assert_eq!(
        fixture
            .kernel
            .ledger()?
            .resume_snapshot_lease(lease, 100)
            .expect_err("cancelled execution must release its snapshot lease")
            .code(),
        positron_kernel::LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn cancellation_is_observed_after_scan_and_before_output_construction() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("typed-stage-cancellation")?;
    fixture.kernel.append_log("one", 20, 1)?;
    let service = QueryService::new(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 3, 1_048_576, 60)?,
    )?;
    query.cancellation().cancel();
    assert_eq!(
        service
            .execute(query)
            .expect_err("pre-cancelled query must not acquire execution resources")
            .code(),
        QueryFailureCode::Cancelled
    );

    for stage in [
        positron_query::QueryWorkStage::ScanDecode,
        positron_query::QueryWorkStage::Output,
    ] {
        let meter = CancellingStageWorkMeter::shared(stage);
        let service = QueryService::with_runtime(
            fixture.kernel.authority.governor(),
            fixture.kernel.ledger()?,
            1,
            TestClock::shared(100),
            Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
        );
        let query = service.plan_pipeline(
            fixture.context,
            "pipeline:v1 logs | range query_time -100 100 | project query_time | limit 1",
            QueryBudget::new(1_048_576, 1, 1, 8, 1_048_576, 60)?,
        )?;
        meter.bind(query.cancellation())?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, QueryEvent::Terminal(_)))
                .count(),
            1
        );
        assert!(matches!(
            events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::Cancelled
                    && incomplete.stats().records() == 0
                    && incomplete.stats().output_bytes() == 0
        ));
    }
    Ok(())
}

#[test]
fn operator_wall_budget_is_checked_before_output() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-operator-wall")?;
    fixture.kernel.append_log("one", 20, 1)?;
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        SequenceClock::shared([100, 100, 100, 100, 100, 160]),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"one\" | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 3, 1_048_576, 60)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().wall_seconds() == 60
    ));
    Ok(())
}

#[test]
fn post_digest_wall_expiry_never_claims_an_unqueued_batch() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("post-digest-wall")?;
    fixture.kernel.append_log("one", 20, 1)?;
    let service = QueryService::with_clock(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        SequenceClock::shared([100, 100, 100, 100, 100, 100, 100, 160]),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"one\" | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 64, 1_048_576, 60)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();

    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
                && incomplete.stats().result_digest() == [0; 32]
    ));
    Ok(())
}
