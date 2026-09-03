use positron_domain::time::EventTime;
use positron_domain::value::{CandidateAttributeValue, ValueLimitProfile};
use positron_signals::{
    SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails, SpanResourceMetadata,
    SpanScopeMetadata, SpanStatus, SpanStatusCode, TraceStoreFailureCode,
};

fn profile() -> ValueLimitProfile {
    ValueLimitProfile::release_1_system_maximum()
}

fn attribute(key: &str) -> SpanAttributeSet {
    SpanAttributeSet::checked(
        key.to_owned(),
        vec![CandidateAttributeValue::boolean(true)],
        profile(),
    )
    .expect("valid detail attribute")
}

fn valid_resource() -> SpanResourceMetadata {
    SpanResourceMetadata::checked(4, "https://resource.example/v1".to_owned())
        .expect("valid resource metadata")
}

fn valid_scope() -> SpanScopeMetadata {
    SpanScopeMetadata::checked(
        "instrumentation".to_owned(),
        "1.2.3".to_owned(),
        5,
        "https://scope.example/v1".to_owned(),
    )
    .expect("valid scope metadata")
}

#[test]
fn native_detail_boundaries_have_stable_typed_failures() {
    let status = SpanStatus::checked(SpanStatusCode::Error, "x".repeat(65_537))
        .expect_err("oversized status messages must be bounded");
    assert_eq!(status.code(), TraceStoreFailureCode::LimitExceeded);

    let resource = SpanResourceMetadata::checked(0, "x".repeat(65_537))
        .expect_err("oversized resource schema URLs must be bounded");
    assert_eq!(resource.code(), TraceStoreFailureCode::LimitExceeded);

    let scope = SpanScopeMetadata::checked("x".repeat(65_537), String::new(), 0, String::new())
        .expect_err("oversized scope names must be bounded");
    assert_eq!(scope.code(), TraceStoreFailureCode::LimitExceeded);

    let empty_event = SpanEvent::checked(EventTime::missing(), String::new(), Vec::new(), 0)
        .expect_err("event names are required native detail identity");
    assert_eq!(empty_event.code(), TraceStoreFailureCode::InvalidInput);

    let empty_link = SpanLink::checked([0; 16], [1; 8], String::new(), 0, Vec::new(), 0)
        .expect_err("link identity must not be all zero");
    assert_eq!(empty_link.code(), TraceStoreFailureCode::InvalidInput);

    let attributes = (0..=1_024)
        .map(|index| attribute(&format!("attribute-{index}")))
        .collect();
    let too_many_attributes =
        SpanEvent::checked(EventTime::missing(), "event".to_owned(), attributes, 0)
            .expect_err("detail attribute collections must be bounded");
    assert_eq!(
        too_many_attributes.code(),
        TraceStoreFailureCode::LimitExceeded
    );

    let too_many_events = (0..=1_024)
        .map(|index| {
            SpanEvent::checked(
                EventTime::missing(),
                format!("event-{index}"),
                Vec::new(),
                0,
            )
            .expect("valid event")
        })
        .collect();
    let collection_failure = SpanObservationDetails::checked(
        String::new(),
        0,
        SpanStatus::checked(SpanStatusCode::Unset, String::new()).expect("status"),
        too_many_events,
        Vec::new(),
        0,
        0,
        0,
        valid_resource(),
        valid_scope(),
    )
    .expect_err("event collections must be bounded");
    assert_eq!(
        collection_failure.code(),
        TraceStoreFailureCode::LimitExceeded
    );

    let aggregate_failure = SpanObservationDetails::checked(
        String::new(),
        0,
        SpanStatus::checked(SpanStatusCode::Unset, String::new()).expect("status"),
        (0..17)
            .map(|_| {
                SpanEvent::checked(EventTime::missing(), "x".repeat(65_536), Vec::new(), 0)
                    .expect("valid large event")
            })
            .collect(),
        Vec::new(),
        0,
        0,
        0,
        SpanResourceMetadata::checked(0, String::new()).expect("resource"),
        SpanScopeMetadata::checked(String::new(), String::new(), 0, String::new()).expect("scope"),
    )
    .expect_err("aggregate detail bytes must be bounded");
    assert_eq!(
        aggregate_failure.code(),
        TraceStoreFailureCode::LimitExceeded
    );
}

#[test]
fn native_detail_success_preserves_ordered_event_and_link_attributes() {
    let event = SpanEvent::checked(
        EventTime::missing(),
        "event".to_owned(),
        vec![attribute("event.attribute")],
        7,
    )
    .expect("event");
    let link = SpanLink::checked(
        [0x11; 16],
        [0x22; 8],
        "vendor=link".to_owned(),
        0x500,
        vec![attribute("link.attribute")],
        8,
    )
    .expect("link");
    let details = SpanObservationDetails::checked(
        "vendor=trace".to_owned(),
        0x400,
        SpanStatus::checked(SpanStatusCode::Ok, "accepted".to_owned()).expect("status"),
        vec![event],
        vec![link],
        9,
        10,
        11,
        valid_resource(),
        valid_scope(),
    )
    .expect("details");

    assert_eq!(details.trace_state(), "vendor=trace");
    assert_eq!(details.flags(), 0x400);
    assert_eq!(details.status().code(), SpanStatusCode::Ok);
    assert_eq!(details.status().message(), "accepted");
    assert_eq!(details.events().len(), 1);
    assert_eq!(details.events()[0].name(), "event");
    assert_eq!(details.events()[0].dropped_attributes_count(), 7);
    assert_eq!(details.events()[0].attributes()[0].key(), "event.attribute");
    assert_eq!(details.links().len(), 1);
    assert_eq!(details.links()[0].trace_id(), [0x11; 16]);
    assert_eq!(details.links()[0].flags(), 0x500);
    assert_eq!(details.links()[0].attributes()[0].key(), "link.attribute");
    assert_eq!(details.resource().dropped_attributes_count(), 4);
    assert_eq!(details.scope().dropped_attributes_count(), 5);
}
