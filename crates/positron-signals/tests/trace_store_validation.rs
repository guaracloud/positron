use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::ValueLimitProfile;
use positron_policy::{IngestPolicy, NativeTraceCandidate, PolicyReceiver, TracePolicyEvaluation};
use positron_signals::{SamplingDecision, SpanKind, SpanObservation, TraceStoreFailureCode};

#[test]
fn native_span_rejects_an_end_timestamp_before_its_start() -> Result<(), Box<dyn std::error::Error>>
{
    let start = EventTime::received(UnixNanoseconds::new(20), SourceTimeQuality::Usable)?;
    let end = EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable)?;
    let policy = IngestPolicy::preserving(1)?;
    let evaluated = match policy.evaluate_trace(
        NativeTraceCandidate::new(Vec::new()),
        PolicyReceiver::OtlpGrpc,
    )? {
        TracePolicyEvaluation::Accepted(evaluated) => *evaluated,
        TracePolicyEvaluation::Rejected => return Err("preserving policy rejected span".into()),
    };
    let failure = SpanObservation::checked_evaluated(
        ValueLimitProfile::release_1_system_maximum(),
        [0x42; 16],
        [0x43; 8],
        None,
        "reversed".to_owned(),
        start,
        end,
        SpanKind::Internal,
        SamplingDecision::Unknown,
        evaluated,
        Default::default(),
    )
    .expect_err("native observations must reject reversed timestamps");
    assert_eq!(failure.code(), TraceStoreFailureCode::InvalidInput);
    Ok(())
}
