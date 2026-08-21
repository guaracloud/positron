use std::error::Error;
use std::sync::Arc;

use positron_kernel::{SnapshotLeaseId, WorkClass};
use positron_query::{
    OrderDirection, QueryBudget, QueryEvent, QueryFailureCode, QueryService, QueryTerminal,
    ResultValueType,
};

use super::support::{
    BlockingOperatorWorkMeter, CancellingOperatorCallMeter, CancellingStageWorkMeter,
    ConstantWorkMeter, SequenceClock, StageCountingWorkMeter, TestClock, TestWorkMeter,
};
use super::terminal_and_bounds::QueryFixture;

type OrderedBodyBatch = (Vec<(String, u16)>, [u8; 32]);

#[test]
fn typed_projection_bytes_obey_the_exact_output_budget() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-projection-bytes")?;
    fixture.kernel.append_log("body-is-not-selected", 20, 1)?;
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source = "pipeline:v1 logs | range query_time -100 100 | project query_time, commit_position | limit 1";

    let exact = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 1, 17, 1_048_576, 60)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 1 && stats.output_bytes() == 17
    ));

    let exhausted = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 1, 16, 1_048_576, 60)?,
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
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::OutputBytes)
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
    let service = super::support::stage_work_service(
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
        [ResultValueType::QueryTime, ResultValueType::EventTime,]
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
            if stats.records() == 2 && stats.output_bytes() == 30
    ));
    Ok(())
}

#[test]
fn temporal_projection_preserves_provenance_quality_and_kernel_ingest_time()
-> Result<(), Box<dyn Error>> {
    use positron_domain::time::{QueryTimeProvenance, SourceTimeQuality};
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("lossless-temporal-projection")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(20),
                Some(CandidateAttributeValue::string("usable".to_owned())),
            ),
            (
                Some(0),
                Some(CandidateAttributeValue::string("zero".to_owned())),
            ),
            (
                None,
                Some(CandidateAttributeValue::string("missing".to_owned())),
            ),
        ],
        1,
    )?;
    let service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range ingest_time 0 100 | project query_time, event_time, ingest_time, commit_position | order by ingest_time asc, commit_position asc | limit 3",
        QueryBudget::new(1_048_576, 3, 3, 97, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("lossless temporal header missing")?;
    assert_eq!(
        header.schema().types(),
        [
            ResultValueType::QueryTime,
            ResultValueType::EventTime,
            ResultValueType::IngestTime,
            ResultValueType::CommitPosition,
        ]
    );
    assert_eq!(header.ordering().columns()[0], "ingest_time");
    assert_eq!(header.ordering().types()[0], ResultValueType::IngestTime);

    let records = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("lossless temporal batch missing")?;
    assert_eq!(records.len(), 3);
    assert_eq!(
        records[0]
            .query_time_value()
            .ok_or("Query Time missing")?
            .provenance(),
        QueryTimeProvenance::Event
    );
    assert_eq!(
        records[0]
            .event_time_value()
            .ok_or("Event Time missing")?
            .quality(),
        SourceTimeQuality::Usable
    );
    assert_eq!(
        records[0]
            .ingest_time_value()
            .ok_or("Ingest Time missing")?
            .instant()
            .value(),
        50
    );
    assert_eq!(
        records[1]
            .query_time_value()
            .ok_or("Query Time missing")?
            .provenance(),
        QueryTimeProvenance::Ingest
    );
    assert_eq!(
        records[1]
            .event_time_value()
            .ok_or("Event Time missing")?
            .quality(),
        SourceTimeQuality::Zero
    );
    assert_eq!(
        records[2]
            .query_time_value()
            .ok_or("Query Time missing")?
            .provenance(),
        QueryTimeProvenance::Ingest
    );
    let missing_event_time = records[2]
        .event_time_value()
        .ok_or("Event Time field missing")?;
    assert_eq!(missing_event_time.quality(), SourceTimeQuality::Missing);
    assert_eq!(missing_event_time.instant(), None);
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 3 && stats.output_bytes() == 97
    ));

    let grouping_service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(2_000_000_000),
        Arc::new(ConstantWorkMeter(0)),
    );
    let grouped = grouping_service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time 0 100 | aggregate count by ingest_time | limit 3",
        QueryBudget::new(1_048_576, 3, 3, 16, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let grouped_events = grouping_service.execute(grouped)?.collect::<Vec<_>>();
    let grouped_record = grouped_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().first(),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("Ingest Time group missing")?;
    assert_eq!(grouped_record.count(), Some(3));
    assert_eq!(
        grouped_record
            .ingest_time_value()
            .ok_or("grouped Ingest Time missing")?
            .instant()
            .value(),
        50
    );
    assert!(matches!(
        grouped_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.records() == 1 && stats.output_bytes() == 16
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
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        Arc::new(ConstantWorkMeter(0)),
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
    assert_eq!(
        records[0]
            .event_time_value()
            .ok_or("missing Event Time group absent")?
            .quality(),
        positron_domain::time::SourceTimeQuality::Missing
    );
    assert_eq!(records[0].count(), Some(1));
    assert_eq!(records[1].event_time().map(|time| time.value()), Some(20));
    assert_eq!(
        records[1]
            .event_time_value()
            .ok_or("present Event Time group absent")?
            .quality(),
        positron_domain::time::SourceTimeQuality::Usable
    );
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
    let service = super::support::zero_work_service(
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
fn event_time_ordering_uses_selected_axis_and_intrinsic_ties_in_both_directions()
-> Result<(), Box<dyn Error>> {
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("event-time-ordering-axis")?;
    fixture.kernel.append_logs(
        vec![
            (
                Some(0),
                Some(CandidateAttributeValue::string("zero-first".to_owned())),
            ),
            (
                Some(20),
                Some(CandidateAttributeValue::string("twenty".to_owned())),
            ),
            (
                Some(0),
                Some(CandidateAttributeValue::string("zero-second".to_owned())),
            ),
        ],
        1,
    )?;
    let service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range event_time -1 100 | project body, event_time | order by event_time asc, commit_position asc | limit 3",
        QueryBudget::new(1_048_576, 3, 3, 128, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
    )?;

    let records = service
        .execute(query)?
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records().to_vec()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("event-time ordered batch missing")?;
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].body_text(), Some("zero-first"));
    assert_eq!(records[1].body_text(), Some("zero-second"));
    assert_eq!(records[2].body_text(), Some("twenty"));

    let descending = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range event_time -1 100 | project body, event_time | order by event_time desc, commit_position desc | limit 3",
        QueryBudget::new(1_048_576, 3, 3, 128, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
    )?;
    let descending_records = service
        .execute(descending)?
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records().to_vec()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("descending event-time ordered batch missing")?;
    assert_eq!(descending_records[0].body_text(), Some("twenty"));
    assert_eq!(descending_records[1].body_text(), Some("zero-second"));
    assert_eq!(descending_records[2].body_text(), Some("zero-first"));
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
    let service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | filter body == \"\" | limit 2",
        QueryBudget::new(1_048_576, 2, 2, 64, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let records = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records().to_vec()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("result batch missing")?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body_text(), Some(""));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.reduced_pruning() && stats.limiting_budget().is_none()
    ));
    Ok(())
}

#[test]
fn quoted_pipeline_literals_preserve_stage_delimiters_as_body_data() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("quoted-stage-delimiter")?;
    fixture.kernel.append_log("a|b", 20, 1)?;
    let service = super::support::zero_work_service(
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
    let service = super::support::zero_work_service(
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

    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        Arc::new(ConstantWorkMeter(0)),
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
    let service = super::support::zero_work_service(
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
            if stats.output_bytes() == 17 && !stats.reduced_pruning()
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
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::OutputBytes)
    ));
    Ok(())
}

#[test]
fn typed_body_equality_accepts_every_native_literal_without_coercion() -> Result<(), Box<dyn Error>>
{
    use positron_domain::value::{CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile};

    let fixture = QueryFixture::new("typed-body-literals")?;
    let candidates = [
        ("null", CandidateAttributeValue::null()),
        ("bool(true)", CandidateAttributeValue::boolean(true)),
        ("int(-42)", CandidateAttributeValue::signed_integer(-42)),
        (
            "float_bits(0x7ff8000000000001)",
            CandidateAttributeValue::floating_point_bits(0x7ff8_0000_0000_0001),
        ),
        (
            r#"string("a\|b")"#,
            CandidateAttributeValue::string("a|b".to_owned()),
        ),
        (
            "bytes(0x00ff)",
            CandidateAttributeValue::bytes(vec![0x00, 0xff]),
        ),
        (
            r#"array(int(1),string("x"))"#,
            CandidateAttributeValue::array(vec![
                CandidateAttributeValue::signed_integer(1),
                CandidateAttributeValue::string("x".to_owned()),
            ]),
        ),
        ("array()", CandidateAttributeValue::array(vec![])),
        (
            r#"kv("k"=bool(false),"k"=null)"#,
            CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new("k".to_owned(), CandidateAttributeValue::boolean(false)),
                CandidateKeyValue::new("k".to_owned(), CandidateAttributeValue::null()),
            ]),
        ),
        ("kv()", CandidateAttributeValue::key_value_list(vec![])),
    ];
    let expected = candidates
        .iter()
        .map(|(_, candidate)| {
            candidate
                .clone()
                .validate_log_body(ValueLimitProfile::release_1_system_maximum())
        })
        .collect::<Result<Vec<_>, _>>()?;
    fixture.kernel.append_logs(
        candidates
            .iter()
            .enumerate()
            .map(|(index, (_, candidate))| {
                let event_time = i64::try_from(index).map(|index| index + 1);
                event_time.map(|event_time| (Some(event_time), Some(candidate.clone())))
            })
            .collect::<Result<Vec<_>, _>>()?,
        1,
    )?;
    let service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );

    for ((literal, _), expected) in candidates.iter().zip(&expected) {
        let source = format!(
            "pipeline:v1 logs | range query_time 0 100 | filter body == {literal} | limit 16"
        );
        let query = service.plan_pipeline(
            fixture.context,
            &source,
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
                .with_cpu_work_units(16)?,
        )?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        let records = events
            .iter()
            .find_map(|event| match event {
                QueryEvent::Batch(batch) => Some(batch.records()),
                QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
            })
            .ok_or_else(|| {
                format!("typed body filter returned no batch for {literal}: {events:?}")
            })?;
        assert_eq!(records.len(), 1, "unexpected match count for {literal}");
        assert_eq!(records[0].body_value(), Some(expected));
    }
    Ok(())
}

#[test]
fn attribute_filters_and_projection_preserve_paths_occurrences_and_native_types()
-> Result<(), Box<dyn Error>> {
    use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, CandidateKeyValue};
    use positron_policy::NativeLogAttribute;

    let fixture = QueryFixture::new("typed-attribute-query")?;
    fixture.kernel.append_attribute_logs(
        vec![
            (
                Some(10),
                vec![
                    NativeLogAttribute::new(
                        AttributeNamespace::Resource,
                        "service.name".to_owned(),
                        vec![
                            CandidateAttributeValue::string("api".to_owned()),
                            CandidateAttributeValue::signed_integer(7),
                            CandidateAttributeValue::null(),
                        ],
                    ),
                    NativeLogAttribute::new(
                        AttributeNamespace::Record,
                        "payload".to_owned(),
                        vec![CandidateAttributeValue::key_value_list(vec![
                            CandidateKeyValue::new(
                                "token".to_owned(),
                                CandidateAttributeValue::string("first".to_owned()),
                            ),
                            CandidateKeyValue::new(
                                "token".to_owned(),
                                CandidateAttributeValue::string("second".to_owned()),
                            ),
                        ])],
                    ),
                    NativeLogAttribute::new(
                        AttributeNamespace::InstrumentationScope,
                        "enabled".to_owned(),
                        vec![
                            CandidateAttributeValue::boolean(true),
                            CandidateAttributeValue::boolean(true),
                        ],
                    ),
                    NativeLogAttribute::new(
                        AttributeNamespace::Resource,
                        "strange |\"\\ key".to_owned(),
                        vec![CandidateAttributeValue::boolean(true)],
                    ),
                ],
            ),
            (Some(20), vec![]),
        ],
        1,
    )?;
    let service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source = concat!(
        "pipeline:v1 logs | range query_time 0 100 | ",
        "filter resource[\"service.name\"] any == int(7) | ",
        "project resource[\"service.name\"], record[\"payload\"][\"token\"], ",
        "scope[\"enabled\"] | limit 2"
    );
    let query = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 2, 2, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("attribute result header missing")?;
    assert_eq!(
        header.schema().columns(),
        [
            r#"resource["service.name"]"#,
            r#"record["payload"]["token"]"#,
            r#"scope["enabled"]"#,
        ]
    );
    assert_eq!(
        header.schema().types(),
        [
            ResultValueType::AttributeOccurrenceSet,
            ResultValueType::AttributeOccurrenceSet,
            ResultValueType::AttributeOccurrenceSet,
        ]
    );
    assert_eq!(header.schema().nullable(), [true, true, true]);
    let record = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().first(),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("attribute result row missing")?;
    let service_name = record
        .attribute_occurrence_set(0)
        .ok_or("resource occurrence set missing")?;
    assert_eq!(service_name.namespace(), AttributeNamespace::Resource);
    assert_eq!(service_name.len(), 3);
    assert_eq!(
        service_name.occurrence(0).and_then(|value| value.as_str()),
        Some("api")
    );
    assert_eq!(
        service_name
            .occurrence(1)
            .and_then(|value| value.as_signed_integer()),
        Some(7)
    );
    assert!(
        service_name
            .occurrence(2)
            .is_some_and(|value| value.is_null())
    );
    let tokens = record
        .attribute_occurrence_set(1)
        .ok_or("nested occurrence set missing")?;
    assert_eq!(tokens.len(), 2);
    assert_eq!(
        tokens.occurrence(0).and_then(|value| value.as_str()),
        Some("first")
    );
    assert_eq!(
        tokens.occurrence(1).and_then(|value| value.as_str()),
        Some("second")
    );
    let enabled = record
        .attribute_occurrence_set(2)
        .ok_or("scope occurrence set missing")?;
    assert_eq!(
        enabled.namespace(),
        AttributeNamespace::InstrumentationScope
    );
    assert_eq!(enabled.len(), 2);
    assert_eq!(
        enabled.occurrence(0).and_then(|value| value.as_boolean()),
        Some(true)
    );
    assert_eq!(
        enabled.occurrence(1).and_then(|value| value.as_boolean()),
        Some(true)
    );

    for predicate in [
        r#"scope["enabled"] all == bool(true)"#,
        r#"resource["service.name"] index(0) == string("api")"#,
        r#"resource["service.name"] any == null"#,
        r#"resource["strange \|\"\\ key"] any == bool(true)"#,
        concat!(
            r#"record["payload"] any == "#,
            r#"kv("token"=string("first"),"token"=string("second"))"#,
        ),
    ] {
        let source =
            format!("pipeline:v1 logs | range query_time 0 100 | filter {predicate} | limit 2");
        let query = service.plan_pipeline(
            fixture.context,
            &source,
            QueryBudget::new(1_048_576, 2, 2, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(16)?,
        )?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        assert!(
            events.iter().any(
                |event| matches!(event, QueryEvent::Batch(batch) if batch.records().len() == 1)
            )
        );
    }

    for predicate in [
        r#"record["absent"] any == null"#,
        r#"record["absent"] index(0) == null"#,
        r#"resource["service.name"] index(3) == null"#,
        r#"resource["service.name"] all == string("api")"#,
        r#"resource["service.name"] any == bool(true)"#,
    ] {
        let source =
            format!("pipeline:v1 logs | range query_time 0 100 | filter {predicate} | limit 2");
        let query = service.plan_pipeline(
            fixture.context,
            &source,
            QueryBudget::new(1_048_576, 2, 2, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(16)?,
        )?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, QueryEvent::Batch(_))),
            "unexpected match for {predicate}: {events:?}"
        );
    }

    let missing_all = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time 0 100 | filter record["absent"] all == null | limit 2"#,
        QueryBudget::new(1_048_576, 2, 2, 1_048_576, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
    )?;
    let missing_events = service.execute(missing_all)?.collect::<Vec<_>>();
    assert!(
        !missing_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );

    let escaped_path = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time 0 100 | project resource["strange \|\"\\ key"] | limit 2"#,
        QueryBudget::new(1_048_576, 2, 2, 1_048_576, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
    )?;
    let escaped_events = service.execute(escaped_path)?.collect::<Vec<_>>();
    let escaped_header = escaped_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("escaped attribute header missing")?;
    assert_eq!(
        escaped_header.schema().columns(),
        [r#"resource["strange \|\"\\ key"]"#]
    );

    let missing_projection = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time 0 100 | project record["absent"] | limit 2"#,
        QueryBudget::new(1_048_576, 2, 2, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;
    let missing_events = service.execute(missing_projection)?.collect::<Vec<_>>();
    let missing_record = missing_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().first(),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("missing-attribute projection produced no row")?;
    assert_eq!(missing_record.attribute_occurrence_set(0), None);
    Ok(())
}

#[test]
fn occurrence_set_projection_obeys_its_exact_canonical_peak_memory_bound()
-> Result<(), Box<dyn Error>> {
    use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
    use positron_policy::NativeLogAttribute;

    const EXACT_PEAK_BYTES: u64 = 66_498;

    let fixture = QueryFixture::new("attribute-projection-memory")?;
    fixture.kernel.append_attribute_logs(
        vec![(
            Some(10),
            vec![NativeLogAttribute::new(
                AttributeNamespace::Record,
                "x".to_owned(),
                vec![
                    CandidateAttributeValue::null(),
                    CandidateAttributeValue::null(),
                ],
            )],
        )],
        1,
    )?;
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
        Arc::new(ConstantWorkMeter(0)),
    );
    let source = r#"pipeline:v1 logs | range query_time 0 100 | project record["x"] | limit 1"#;

    let exact = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, EXACT_PEAK_BYTES, 60)?
            .with_cpu_work_units(16)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    assert!(
        exact_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(_)))
    ));

    let exhausted = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, EXACT_PEAK_BYTES - 1, 60)?
            .with_cpu_work_units(16)?,
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
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::MemoryBytes)
    ));
    Ok(())
}

#[test]
fn attribute_grouping_keeps_missing_distinct_from_the_full_occurrence_set()
-> Result<(), Box<dyn Error>> {
    use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
    use positron_policy::NativeLogAttribute;

    let fixture = QueryFixture::new("typed-attribute-grouping")?;
    fixture.kernel.append_attribute_logs(
        vec![
            (
                Some(10),
                vec![NativeLogAttribute::new(
                    AttributeNamespace::Resource,
                    "service.name".to_owned(),
                    vec![
                        CandidateAttributeValue::string("api".to_owned()),
                        CandidateAttributeValue::signed_integer(7),
                    ],
                )],
            ),
            (Some(20), vec![]),
            (
                Some(30),
                vec![NativeLogAttribute::new(
                    AttributeNamespace::Resource,
                    "service.name".to_owned(),
                    vec![
                        CandidateAttributeValue::string("api".to_owned()),
                        CandidateAttributeValue::signed_integer(7),
                    ],
                )],
            ),
        ],
        1,
    )?;
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(2_000_000_000),
        Arc::new(ConstantWorkMeter(0)),
    );
    let query = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time 0 100 | aggregate count by resource["service.name"] | limit 3"#,
        QueryBudget::new(1_048_576, 3, 3, 1_048_576, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
    )?;
    let events = service.execute(query)?.collect::<Vec<_>>();
    let header = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Header(header) => Some(header),
            QueryEvent::Batch(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("attribute group header missing")?;
    assert_eq!(
        header.schema().columns(),
        [r#"resource["service.name"]"#, "count"]
    );
    assert_eq!(header.schema().nullable(), [true, false]);
    let records = events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => Some(batch.records()),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or_else(|| format!("attribute group batch missing: {events:?}"))?;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].attribute_occurrence_set(0), None);
    assert_eq!(records[0].count(), Some(1));
    let present = records[1]
        .attribute_occurrence_set(0)
        .ok_or("present group missing")?;
    assert_eq!(present.len(), 2);
    assert_eq!(records[1].count(), Some(2));
    Ok(())
}

#[test]
fn version_one_equality_rejects_untyped_literal_syntax() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("native-filter-boundary")?;
    let service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );

    for literal in ["true", "7", "[1]", "float(1.0)"] {
        let source = format!(
            "pipeline:v1 logs | range query_time 0 100 | filter body == {literal} | limit 1"
        );
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
fn version_one_rejects_malformed_or_noncanonical_typed_literals() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("native-literal-errors")?;
    let service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let budget = QueryBudget::new(1_048_576, 1, 1, 64, 1_048_576, 60)?;

    for literal in [
        "bool(neither)",
        "bool(true",
        "int()",
        "int(+1)",
        "int(01)",
        "int(-01)",
        "int(9223372036854775808)",
        "float_bits(7ff8000000000001)",
        "float_bits(0x7FF8000000000001)",
        "float_bits(0x01)",
        "bytes(00ff)",
        "bytes(0x0)",
        "bytes(0xGG)",
        "array(int(1)",
        "array(unknown)",
        r#"kv("key"int(1))"#,
        r#"kv("key"=int(1)"#,
        r#"kv(""=null)"#,
        r#""value" trailing"#,
        r#"string("bad\nescape")"#,
        r#"string("unterminated)"#,
        "null trailing",
    ] {
        let source = format!(
            "pipeline:v1 logs | range query_time 0 100 | filter body == {literal} | limit 1"
        );
        let failure = service
            .plan_pipeline(fixture.context, &source, budget)
            .err()
            .ok_or_else(|| format!("accepted malformed native literal: {literal}"))?;
        assert_eq!(
            failure.code(),
            QueryFailureCode::UnsupportedQuery,
            "wrong failure for {literal}"
        );
    }

    let mut too_deep = String::new();
    for _ in 0..130 {
        too_deep.push_str("array(");
    }
    too_deep.push_str("null");
    for _ in 0..130 {
        too_deep.push(')');
    }
    let source =
        format!("pipeline:v1 logs | range query_time 0 100 | filter body == {too_deep} | limit 1");
    let failure = service
        .plan_pipeline(fixture.context, &source, budget)
        .err()
        .ok_or("accepted native literal beyond the bounded nesting depth")?;
    assert_eq!(failure.code(), QueryFailureCode::UnsupportedQuery);
    Ok(())
}

#[test]
fn version_one_rejects_malformed_attribute_paths_and_selectors() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("attribute-path-errors")?;
    let service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let budget = QueryBudget::new(1_048_576, 1, 1, 64, 1_048_576, 60)?;

    for predicate in [
        r#"stream["key"] any == null"#,
        r#"unknown["key"] any == null"#,
        r#"resource.key any == null"#,
        r#"resource["key" any == null"#,
        r#"resource["bad\nescape"] any == null"#,
        r#"resource["key"] == null"#,
        r#"resource["key"] some == null"#,
        r#"resource["key"] index() == null"#,
        r#"resource["key"] index(+1) == null"#,
        r#"resource["key"] index(01) == null"#,
        r#"resource["key"] index(65536) == null"#,
        r#"resource["key"] index(0) = null"#,
        r#"resource[""] any == null"#,
        r#"resource["key"]"#,
        r#"resource\key any == null"#,
    ] {
        let source =
            format!("pipeline:v1 logs | range query_time 0 100 | filter {predicate} | limit 1");
        let failure = service
            .plan_pipeline(fixture.context, &source, budget)
            .err()
            .ok_or_else(|| format!("accepted malformed attribute predicate: {predicate}"))?;
        assert_eq!(
            failure.code(),
            QueryFailureCode::UnsupportedQuery,
            "wrong failure for {predicate}"
        );
    }

    let mut excessive_path = String::from("resource");
    for _ in 0..=positron_signals::SchemaPath::system_max_segments() {
        excessive_path.push_str(r#"["x"]"#);
    }
    let source = format!(
        "pipeline:v1 logs | range query_time 0 100 | filter {excessive_path} any == null | limit 1"
    );
    let failure = service
        .plan_pipeline(fixture.context, &source, budget)
        .err()
        .ok_or("accepted attribute path beyond the segment bound")?;
    assert_eq!(failure.code(), QueryFailureCode::UnsupportedQuery);
    Ok(())
}

#[test]
fn typed_count_bytes_obey_the_exact_output_budget() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("typed-count-bytes")?;
    fixture.kernel.append_log("counted", 20, 1)?;
    let service = super::support::zero_work_service(
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
    let count_record = exact_events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().first(),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or("count result row missing")?;
    assert_eq!(count_record.query_time().value(), 0);
    assert_eq!(count_record.event_time(), None);
    assert_eq!(count_record.attribute_occurrence_set(0), None);

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
    let service = super::support::zero_work_service(
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
            ResultValueType::QueryTime,
            ResultValueType::CommitPosition,
        ]
    );
    assert_eq!(
        header.ordering().types(),
        [
            ResultValueType::QueryTime,
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
    let service = super::support::zero_work_service(
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
            ResultValueType::QueryTime,
            ResultValueType::CommitPosition,
            ResultValueType::UnsignedInteger,
        ]
    );
    assert_eq!(
        header.ordering().types(),
        [
            ResultValueType::NativeValue,
            ResultValueType::QueryTime,
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
    let service = super::support::zero_work_service(
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
fn batch_digest_streams_valid_bodies_larger_than_control_token_payloads()
-> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("streamed-result-digest")?;
    let body = "x".repeat(5_000);
    fixture.kernel.append_log(&body, 20, 1)?;
    let service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source = "pipeline:v1 logs | range query_time -100 100 | project body | limit 1";
    let execute = || -> Result<[u8; 32], Box<dyn Error>> {
        let query = service.plan_pipeline(
            fixture.context,
            source,
            QueryBudget::new(1_048_576, 1, 1, 8_192, 1_048_576, 60)?,
        )?;
        let events = service.execute(query)?.collect::<Vec<_>>();
        assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
        assert!(matches!(
            events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
                if stats.records() == 1 && stats.result_digest() != [0; 32]
        ));
        events
            .iter()
            .find_map(|event| match event {
                QueryEvent::Batch(batch) => Some(batch.digest()),
                QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
            })
            .ok_or_else(|| "large-body result batch missing".into())
    };

    assert_eq!(execute()?, execute()?);
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
        let service = super::support::zero_work_service(
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
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source = "logs | range query_time -100 100 | limit 2";

    let exact = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 2, 2, 32, 1_048_576, 60)?.with_cpu_work_units(6)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.cpu_work_units() == 6
    ));

    let exhausted = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 2, 2, 32, 1_048_576, 60)?.with_cpu_work_units(5)?,
    )?;
    let exhausted_events = service.execute(exhausted)?.collect::<Vec<_>>();
    assert!(matches!(
        exhausted_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().cpu_work_units() == 6
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
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        Arc::new(ConstantWorkMeter(0)),
    );
    let ordinary = "logs | range query_time -100 100 | limit 2";
    for (memory_bytes, expected_complete) in [(1_676, true), (1_675, false)] {
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
    for (memory_bytes, expected_complete) in [(3_351, true), (3_350, false)] {
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
    let service = super::support::zero_work_service(
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
        "pipeline:v1 logs | range query_time -100 100 | filter record[\"a\"] any == null | filter record[\"b\"] any == null | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | project body | project query_time | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | project body, query_time, event_time, ingest_time, commit_position, body | limit 1",
        "pipeline:v1 logs | range query_time -100 100 | project ,body | limit 1",
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
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        Arc::new(ConstantWorkMeter(0)),
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 94, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
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
            if stats.records() == 3 && stats.output_bytes() == 94
    ));

    let output_exhausted = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 93, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
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
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::OutputBytes)
    ));

    let memory_exhausted = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 91, 8_737, 60)?
            .with_cpu_work_units(16)?,
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
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::MemoryBytes)
    ));

    let metered_service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        Arc::new(TestWorkMeter),
    );
    let work_exhausted = metered_service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body, query_time | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 91, 1_048_576, 60)?.with_cpu_work_units(4)?,
    )?;
    let work_events = metered_service.execute(work_exhausted)?.collect::<Vec<_>>();
    assert!(
        !work_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        work_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().cpu_work_units() == 5
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
    ));

    let commit_groups = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by commit_position | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 64, 1_048_576, 60)?
            .with_cpu_work_units(16)?,
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
fn grouped_key_comparisons_consume_the_exact_cumulative_work_budget() -> Result<(), Box<dyn Error>>
{
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("group-comparison-work")?;
    fixture.kernel.append_log_bodies(
        vec![
            Some(CandidateAttributeValue::string("a".to_owned())),
            Some(CandidateAttributeValue::string("b".to_owned())),
        ],
        20,
        1,
    )?;
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let source = "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 2";

    let exact = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 2, 2, 64, 1_048_576, 60)?.with_cpu_work_units(20)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.cpu_work_units() == 20
    ));

    let exhausted = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 2, 2, 64, 1_048_576, 60)?.with_cpu_work_units(19)?,
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
                && incomplete.stats().cpu_work_units() == 20
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
    ));
    Ok(())
}

#[test]
fn group_key_construction_charges_large_native_values_before_lookup() -> Result<(), Box<dyn Error>>
{
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("group-key-construction-work")?;
    fixture.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::string("x".repeat(4_096)))],
        20,
        1,
    )?;
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 8_192, 1_048_576, 60)?.with_cpu_work_units(9)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().cpu_work_units() == 10
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    Ok(())
}

#[test]
fn cancellation_is_polled_during_native_group_key_construction() -> Result<(), Box<dyn Error>> {
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("group-key-construction-cancel")?;
    fixture.kernel.append_log_bodies(
        vec![Some(CandidateAttributeValue::string("x".repeat(4_096)))],
        20,
        1,
    )?;
    let meter = CancellingOperatorCallMeter::shared(10);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        16,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | aggregate count by body | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 8_192, 1_048_576, 60)?.with_cpu_work_units(18)?,
    )?;
    meter.bind(query.cancellation())?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
    ));
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
    Ok(())
}

#[test]
fn deep_native_predicate_work_exhausts_before_any_result_prefix() -> Result<(), Box<dyn Error>> {
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("deep-native-predicate-work")?;
    let mut body = CandidateAttributeValue::null();
    let mut literal = "null".to_owned();
    for _ in 0..8 {
        body = CandidateAttributeValue::array(vec![body]);
        literal = format!("array({literal})");
    }
    fixture.kernel.append_log_bodies(vec![Some(body)], 20, 1)?;
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    let source = format!(
        "pipeline:v1 logs | range query_time -100 100 | filter body == {literal} | limit 1"
    );
    let query = service.plan_pipeline(
        fixture.context,
        &source,
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    Ok(())
}

#[test]
fn deep_native_body_projection_defers_recursive_work_to_output() -> Result<(), Box<dyn Error>> {
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("deep-native-projection-work")?;
    let mut body = CandidateAttributeValue::null();
    for _ in 0..8 {
        body = CandidateAttributeValue::array(vec![body]);
    }
    fixture.kernel.append_log_bodies(vec![Some(body)], 20, 1)?;
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | project body | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(16)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    Ok(())
}

#[test]
fn deep_native_output_and_digest_share_the_cumulative_cpu_budget() -> Result<(), Box<dyn Error>> {
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("deep-native-output-work")?;
    let mut body = CandidateAttributeValue::null();
    for _ in 0..8 {
        body = CandidateAttributeValue::array(vec![body]);
    }
    fixture.kernel.append_log_bodies(vec![Some(body)], 20, 1)?;
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | project body | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(9)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    Ok(())
}

#[test]
fn deep_native_digest_traversal_is_cumulatively_metered() -> Result<(), Box<dyn Error>> {
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("deep-native-digest-work")?;
    let mut body = CandidateAttributeValue::null();
    for _ in 0..8 {
        body = CandidateAttributeValue::array(vec![body]);
    }
    fixture.kernel.append_log_bodies(vec![Some(body)], 20, 1)?;
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    let source = "pipeline:v1 logs | range query_time -100 100 | project body | limit 1";
    let query = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(18)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );

    let exact = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(19)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    assert!(
        exact_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.cpu_work_units() == 19 && stats.records() == 1
    ));
    Ok(())
}

#[test]
fn cancellation_interrupts_deep_native_digest_before_batch_delivery() -> Result<(), Box<dyn Error>>
{
    use positron_domain::value::CandidateAttributeValue;

    let fixture = QueryFixture::new("deep-native-digest-cancel")?;
    let mut body = CandidateAttributeValue::null();
    for _ in 0..8 {
        body = CandidateAttributeValue::array(vec![body]);
    }
    fixture.kernel.append_log_bodies(vec![Some(body)], 20, 1)?;
    let meter =
        CancellingOperatorCallMeter::shared_for_stage(positron_query::QueryWorkStage::Output, 14);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
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
        "pipeline:v1 logs | range query_time -100 100 | project body | limit 1",
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(128)?,
    )?;
    meter.bind(query.cancellation())?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
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
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert_eq!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before
    );
    Ok(())
}

#[test]
fn deep_attribute_path_projection_is_cumulatively_metered() -> Result<(), Box<dyn Error>> {
    use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, CandidateKeyValue};
    use positron_policy::NativeLogAttribute;

    let fixture = QueryFixture::new("deep-attribute-projection-work")?;
    let mut value = CandidateAttributeValue::null();
    let mut path = r#"record["payload"]"#.to_owned();
    for index in (0..8).rev() {
        let key = format!("k{index}");
        value = CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            key.clone(),
            value,
        )]);
    }
    for index in 0..8 {
        path.push_str(&format!(r#"["k{index}"]"#));
    }
    fixture.kernel.append_attribute_logs(
        vec![(
            Some(20),
            vec![NativeLogAttribute::new(
                AttributeNamespace::Record,
                "payload".to_owned(),
                vec![value],
            )],
        )],
        1,
    )?;
    let service = super::support::stage_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    let source = format!("pipeline:v1 logs | range query_time -100 100 | project {path} | limit 1");
    let query = service.plan_pipeline(
        fixture.context,
        &source,
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(93)?,
    )?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().records() == 0
                && incomplete.stats().cpu_work_units() == 94
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );

    let exact = service.plan_pipeline(
        fixture.context,
        &source,
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(94)?,
    )?;
    let exact_events = service.execute(exact)?.collect::<Vec<_>>();
    let Some(QueryEvent::Terminal(QueryTerminal::Complete(stats))) = exact_events.last() else {
        return Err("deep attribute projection did not complete".into());
    };
    assert_eq!(stats.cpu_work_units(), 94);
    assert_eq!(stats.records(), 1);
    Ok(())
}

#[test]
fn cancellation_interrupts_deep_attribute_projection_before_allocation_delivery()
-> Result<(), Box<dyn Error>> {
    use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, CandidateKeyValue};
    use positron_policy::NativeLogAttribute;

    let fixture = QueryFixture::new("deep-attribute-projection-cancel")?;
    let mut value = CandidateAttributeValue::null();
    let mut path = r#"record["payload"]"#.to_owned();
    for index in (0..8).rev() {
        let key = format!("k{index}");
        value = CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            key.clone(),
            value,
        )]);
    }
    for index in 0..8 {
        path.push_str(&format!(r#"["k{index}"]"#));
    }
    fixture.kernel.append_attribute_logs(
        vec![(
            Some(20),
            vec![NativeLogAttribute::new(
                AttributeNamespace::Record,
                "payload".to_owned(),
                vec![value],
            )],
        )],
        1,
    )?;
    let meter = CancellingOperatorCallMeter::shared(20);
    let service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let before = fixture
        .kernel
        .authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let source = format!("pipeline:v1 logs | range query_time -100 100 | project {path} | limit 1");
    let query = service.plan_pipeline(
        fixture.context,
        &source,
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(128)?,
    )?;
    meter.bind(query.cancellation())?;

    let events = service.execute(query)?.collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(QueryEvent::Header(_))));
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
                && incomplete.stats().records() == 0
                && incomplete.stats().output_bytes() == 0
    ));
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
    assert_eq!(
        fixture
            .kernel
            .authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before
    );
    Ok(())
}

#[test]
fn schema_catalog_prunes_false_attribute_predicates_without_changing_exact_results()
-> Result<(), Box<dyn Error>> {
    use positron_domain::value::AttributeNamespace;
    use positron_policy::NativeLogAttribute;
    use positron_signals::{
        LogScan, LogStore, OccurrenceSelector, ScanLimit, SchemaBudget, SchemaCatalog, SchemaPath,
        SchemaQuery, SchemaValue,
    };

    let mut fixture = QueryFixture::new("schema-aware-query")?;
    let path = SchemaPath::root(AttributeNamespace::Record, "indexed".to_owned())?;
    let schema = fixture.kernel.append_indexed_attribute_logs(
        vec![(
            Some(20),
            vec![NativeLogAttribute::new(
                AttributeNamespace::Record,
                "indexed".to_owned(),
                vec![positron_domain::value::CandidateAttributeValue::string(
                    "one".to_owned(),
                )],
            )],
        )],
        1,
        &path,
    )?;
    let service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    let budget =
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(128)?;
    let snapshot = fixture.kernel.ledger()?.snapshot()?;
    let stored_pruned = LogStore::new().scan_schema(
        fixture.kernel.authority.governor(),
        fixture
            .context
            .tenant_attribution()
            .ok_or("tenant")?
            .tenant_id(),
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        schema.catalog(),
        &SchemaQuery::value(
            path.clone(),
            OccurrenceSelector::Any,
            SchemaValue::string("absent"),
        ),
    )?;
    assert_eq!(stored_pruned.scanned_bytes(), 0);
    let absent = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | filter record["indexed"] any == string("absent") | limit 1"#,
        budget,
    )?;
    let pruned = service
        .execute_with_schema(absent, schema.catalog())?
        .collect::<Vec<_>>();
    assert!(
        !pruned
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    let Some(QueryEvent::Terminal(QueryTerminal::Complete(pruned_stats))) = pruned.last() else {
        return Err("schema-pruned query did not complete".into());
    };
    assert_eq!(pruned_stats.scanned_bytes(), 0);
    assert_eq!(pruned_stats.decoded_records(), 0);
    assert!(!pruned_stats.reduced_pruning());

    let present = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | filter record["indexed"] any == string("one") | project record["indexed"] | limit 1"#,
        budget,
    )?;
    let exact = service
        .execute_with_schema(present, schema.catalog())?
        .collect::<Vec<_>>();
    assert!(
        exact
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        exact.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.scanned_bytes() > 0
                && stats.decoded_records() == 1
                && !stats.reduced_pruning()
    ));

    let generic = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | filter record["indexed"] any == string("absent") | limit 1"#,
        budget,
    )?;
    let fallback = service.execute(generic)?.collect::<Vec<_>>();
    assert!(matches!(
        fallback.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.scanned_bytes() > 0
                && stats.decoded_records() == 1
                && stats.reduced_pruning()
    ));

    let tenant = fixture
        .context
        .tenant_attribution()
        .ok_or("tenant")?
        .tenant_id();
    let missing_catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let missing_evidence = service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | filter record["indexed"] any == string("one") | limit 1"#,
        budget,
    )?;
    let missing_events = service
        .execute_with_schema(missing_evidence, &missing_catalog)?
        .collect::<Vec<_>>();
    assert!(matches!(
        missing_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.scanned_bytes() > 0
                && stats.decoded_records() == 1
                && stats.reduced_pruning()
    ));

    let meter = StageCountingWorkMeter::shared();
    let metered_service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
        Arc::clone(&meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let source = r#"pipeline:v1 logs | range query_time -100 100 | filter record["indexed"] any == string("absent") | limit 1"#;
    let exhausted = metered_service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(7)?,
    )?;
    let exhausted_events = metered_service
        .execute_with_schema(exhausted, schema.catalog())?
        .collect::<Vec<_>>();
    assert!(matches!(
        exhausted_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::BudgetExhausted
                && incomplete.stats().cpu_work_units() == 8
                && incomplete.stats().limiting_budget()
                    == Some(positron_query::QueryBudgetDimension::CpuWorkUnits)
    ));
    let exact = metered_service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(8)?,
    )?;
    let exact_events = metered_service
        .execute_with_schema(exact, schema.catalog())?
        .collect::<Vec<_>>();
    assert!(matches!(
        exact_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.cpu_work_units() == 8
                && stats.scanned_bytes() == 0
                && stats.decoded_records() == 0
    ));

    let cancelling_meter = CancellingOperatorCallMeter::shared_for_stage(
        positron_query::QueryWorkStage::ScanDecode,
        1,
    );
    let cancelling_service = QueryService::with_runtime(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
        TestClock::shared(100),
        Arc::clone(&cancelling_meter) as Arc<dyn positron_query::QueryWorkMeter>,
    );
    let cancelled = cancelling_service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 1, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(128)?,
    )?;
    cancelling_meter.bind(cancelled.cancellation())?;
    let cancelled_events = cancelling_service
        .execute_with_schema(cancelled, schema.catalog())?
        .collect::<Vec<_>>();
    assert!(matches!(
        cancelled_events.first(),
        Some(QueryEvent::Header(_))
    ));
    assert!(matches!(
        cancelled_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::Cancelled
                && incomplete.stats().records() == 0
    ));
    assert_eq!(
        cancelled_events
            .iter()
            .filter(|event| matches!(event, QueryEvent::Terminal(_)))
            .count(),
        1
    );

    drop(stored_pruned);
    drop(snapshot);
    drop(service);
    drop(metered_service);
    drop(cancelling_service);
    let reopened_schema = positron_signals::SchemaCatalog::decode_catalog_object(
        &schema.catalog().encode_catalog_object()?,
    )?;
    fixture.kernel.seal_and_reopen()?;
    let verified_service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    for (literal, expected_batch) in [("one", true), ("absent", false)] {
        let verified = verified_service.plan_pipeline(
            fixture.context,
            &format!(
                r#"pipeline:v1 logs | range query_time -100 100 | filter record["indexed"] any == string("{literal}") | limit 1"#
            ),
            budget,
        )?;
        let verified_events = verified_service
            .execute_with_schema(verified, &reopened_schema)?
            .collect::<Vec<_>>();
        assert_eq!(
            verified_events
                .iter()
                .any(|event| matches!(event, QueryEvent::Batch(_))),
            expected_batch
        );
        assert!(matches!(
            verified_events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
                if !stats.reduced_pruning()
                    && stats.decoded_records() == u64::from(expected_batch)
        ));
    }
    drop(verified_service);

    fixture.kernel.append_attribute_logs(
        vec![(
            Some(21),
            vec![NativeLogAttribute::new(
                AttributeNamespace::Record,
                "indexed".to_owned(),
                vec![positron_domain::value::CandidateAttributeValue::string(
                    "two".to_owned(),
                )],
            )],
        )],
        2,
    )?;
    fixture.kernel.append_attribute_logs(
        vec![
            (
                Some(22),
                vec![NativeLogAttribute::new(
                    AttributeNamespace::Record,
                    "indexed".to_owned(),
                    vec![positron_domain::value::CandidateAttributeValue::array(
                        vec![positron_domain::value::CandidateAttributeValue::null()],
                    )],
                )],
            ),
            (
                Some(23),
                vec![NativeLogAttribute::new(
                    AttributeNamespace::Record,
                    "indexed".to_owned(),
                    vec![
                        positron_domain::value::CandidateAttributeValue::key_value_list(vec![
                            positron_domain::value::CandidateKeyValue::new(
                                "k".to_owned(),
                                positron_domain::value::CandidateAttributeValue::boolean(true),
                            ),
                        ]),
                    ],
                )],
            ),
        ],
        3,
    )?;
    let active_service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    let active_budget =
        QueryBudget::new(1_048_576, 3, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(128)?;
    let active_fallback = active_service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | filter record["indexed"] any == string("two") | limit 1"#,
        active_budget,
    )?;
    let active_events = active_service
        .execute_with_schema(active_fallback, schema.catalog())?
        .collect::<Vec<_>>();
    assert!(
        active_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_))),
        "active fallback events: {active_events:?}"
    );
    assert!(matches!(
        active_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.scanned_bytes() > 0
                && stats.decoded_records() == 3
                && stats.reduced_pruning()
    ));
    let structural_budget =
        QueryBudget::new(1_048_576, 4, 1, 1_048_576, 1_048_576, 60)?.with_cpu_work_units(128)?;
    for literal in ["array(null)", r#"kv("k"=bool(true))"#] {
        let structural = active_service.plan_pipeline(
            fixture.context,
            &format!(
                r#"pipeline:v1 logs | range query_time -100 100 | filter record["indexed"] any == {literal} | limit 1"#
            ),
            structural_budget,
        )?;
        let structural_events = active_service
            .execute_with_schema(structural, schema.catalog())?
            .collect::<Vec<_>>();
        assert!(
            structural_events
                .iter()
                .any(|event| matches!(event, QueryEvent::Batch(_))),
            "structural {literal} events: {structural_events:?}"
        );
        assert!(matches!(
            structural_events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
                if stats.decoded_records() == 4 && stats.reduced_pruning()
        ));
    }
    drop(active_service);
    fixture.kernel.seal_and_reopen()?;
    let fallback_reopened_service = super::support::zero_work_service(
        fixture.kernel.authority.governor(),
        fixture.kernel.ledger()?,
        1,
    );
    let reopened_fallback = fallback_reopened_service.plan_pipeline(
        fixture.context,
        r#"pipeline:v1 logs | range query_time -100 100 | filter record["indexed"] any == string("two") | limit 1"#,
        active_budget,
    )?;
    let reopened_fallback_events = fallback_reopened_service
        .execute_with_schema(reopened_fallback, &reopened_schema)?
        .collect::<Vec<_>>();
    assert!(
        reopened_fallback_events
            .iter()
            .any(|event| matches!(event, QueryEvent::Batch(_)))
    );
    assert!(matches!(
        reopened_fallback_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
            if stats.scanned_bytes() > 0
                && stats.decoded_records() == 3
                && stats.reduced_pruning()
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
    let service = super::support::zero_work_service(
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
            "pipeline:v1 logs | range query_time -100 100 | project body | limit 1",
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
    let service = super::support::zero_work_clock_service(
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
    let service = super::support::zero_work_clock_service(
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
