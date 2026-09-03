use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_signals::{SamplingDecision, SpanKind, SpanObservation, TraceStoreFailureCode};

#[test]
fn native_span_rejects_an_end_timestamp_before_its_start() -> Result<(), Box<dyn std::error::Error>>
{
    let start = EventTime::received(UnixNanoseconds::new(20), SourceTimeQuality::Usable)?;
    let end = EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable)?;
    let policy = positron_policy::PolicyProvenance::new(1, [0x41; 32], Vec::new())?;
    let failure = SpanObservation::checked_native(
        [0x42; 16],
        [0x43; 8],
        None,
        "reversed".to_owned(),
        start,
        end,
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        policy,
    )
    .expect_err("native observations must reject reversed timestamps");
    assert_eq!(failure.code(), TraceStoreFailureCode::InvalidInput);
    Ok(())
}
