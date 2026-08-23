use std::error::Error;

use positron_domain::value::AttributeValueKind;
use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryRecord, QueryTerminal};

use super::terminal_and_bounds::QueryFixture;

fn first_record(events: &[QueryEvent]) -> Result<&QueryRecord, Box<dyn Error>> {
    events
        .iter()
        .find_map(|event| match event {
            QueryEvent::Batch(batch) => batch.records().first(),
            QueryEvent::Header(_) | QueryEvent::Terminal(_) => None,
        })
        .ok_or_else(|| "query result record missing".into())
}

fn execute(fixture: &QueryFixture, source: &str) -> Result<Vec<QueryEvent>, Box<dyn Error>> {
    let service = fixture.service(16)?;
    let query = service.plan_pipeline(
        fixture.context,
        source,
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
    )?;
    Ok(service.execute(query)?.collect())
}

fn assert_unsupported(events: &[QueryEvent]) {
    assert!(matches!(
        events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
            if incomplete.code() == QueryFailureCode::UnsupportedQuery
    ));
}

#[test]
fn json_escape_number_order_and_empty_container_contract_is_public() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("query-json-edge-values")?;
    fixture.kernel.append_log(
        r#" {"a":1,"a":2,"empty_array":[],"empty_object":{},"escaped":"\"\\\/\b\f\n\r\t","unicode":"\uD834\uDD1E","letter":"\u0061","huge":9223372036854775808} "#,
        20,
        1,
    )?;
    let events = execute(
        &fixture,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
    )?;
    let body = first_record(&events)?.body_value().ok_or("body missing")?;
    assert_eq!(body.kind(), AttributeValueKind::KeyValueList);
    assert_eq!(body.key_value_list_len(), Some(8));
    assert_eq!(body.key_value_entry(0).map(|entry| entry.key()), Some("a"));
    assert_eq!(body.key_value_entry(1).map(|entry| entry.key()), Some("a"));
    assert_eq!(
        body.key_value_entry(2)
            .and_then(|entry| entry.value().array_len()),
        Some(0)
    );
    assert_eq!(
        body.key_value_entry(3)
            .and_then(|entry| entry.value().key_value_list_len()),
        Some(0)
    );
    assert_eq!(
        body.key_value_entry(4)
            .and_then(|entry| entry.value().as_str()),
        Some("\"\\/\u{0008}\u{000c}\n\r\t")
    );
    assert_eq!(
        body.key_value_entry(5)
            .and_then(|entry| entry.value().as_str()),
        Some("𝄞")
    );
    assert!(
        body.key_value_entry(6)
            .and_then(|entry| entry.value().as_str())
            .is_some_and(|value| value == "a")
    );
    assert!(
        body.key_value_entry(7)
            .and_then(|entry| entry.value().as_floating_point_bits())
            .is_some()
    );
    Ok(())
}

#[test]
fn json_malformed_and_structural_limits_are_stable() -> Result<(), Box<dyn Error>> {
    let malformed = [
        "",
        "1 2",
        "tru",
        "[1,]",
        "[1 2]",
        "{\"a\"}",
        "{\"a\":}",
        "01",
        "1.",
        "1e",
        "-",
        "1e400",
        &"1".repeat(400),
        "\"unterminated",
        "\"bad\\q\"",
        "\"\u{0001}\"",
        "\"\\uDD1E\"",
        "\"\\uD834x\"",
        "\"\\uD834\\u0041\"",
        "\"\\u12x4\"",
    ];
    for (index, source) in malformed.into_iter().enumerate() {
        let fixture = QueryFixture::new(&format!("query-json-malformed-{index}"))?;
        fixture.kernel.append_log(source, 20, 1)?;
        assert_unsupported(&execute(
            &fixture,
            "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
        )?);
    }

    let mut nested = "[".repeat(33);
    nested.push('0');
    nested.push_str(&"]".repeat(33));
    let fixture = QueryFixture::new("query-json-depth")?;
    fixture.kernel.append_log(&nested, 20, 1)?;
    assert_unsupported(&execute(
        &fixture,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
    )?);

    let object = format!(
        "{{{}}}",
        (0..1_025)
            .map(|index| format!("\"k{index}\":0"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let fixture = QueryFixture::new("query-json-object-limit")?;
    fixture.kernel.append_log(&object, 20, 1)?;
    assert_unsupported(&execute(
        &fixture,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
    )?);

    let array = format!(
        "[{}]",
        (0..1_025).map(|_| "0").collect::<Vec<_>>().join(",")
    );
    let fixture = QueryFixture::new("query-json-array-limit")?;
    fixture.kernel.append_log(&array, 20, 1)?;
    assert_unsupported(&execute(
        &fixture,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
    )?);

    let oversized = format!("\"{}\"", "x".repeat(65_536));
    let fixture = QueryFixture::new("query-json-input-limit")?;
    fixture.kernel.append_log(&oversized, 20, 1)?;
    assert_unsupported(&execute(
        &fixture,
        "pipeline:v1 logs | range query_time -100 100 | json | limit 1",
    )?);
    Ok(())
}
