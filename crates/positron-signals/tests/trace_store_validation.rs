use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::ValueLimitProfile;
use positron_policy::{IngestPolicy, NativeTraceCandidate, PolicyReceiver, TracePolicyEvaluation};
use positron_signals::{SamplingDecision, SpanKind, SpanObservation};

#[test]
fn native_span_preserves_contradictory_times_and_quality() -> Result<(), Box<dyn std::error::Error>>
{
    let start = EventTime::received(UnixNanoseconds::new(20), SourceTimeQuality::Usable)?;
    let end = EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Contradictory)?;
    let policy = IngestPolicy::preserving(1)?;
    let evaluated = match policy.evaluate_trace(
        NativeTraceCandidate::new(Vec::new()),
        PolicyReceiver::OtlpGrpc,
    )? {
        TracePolicyEvaluation::Accepted(evaluated) => *evaluated,
        TracePolicyEvaluation::Rejected => return Err("preserving policy rejected span".into()),
    };
    let observation = SpanObservation::checked_evaluated(
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
    .expect("contradictory times remain valid observations");
    assert_eq!(
        observation.start_time().instant(),
        Some(UnixNanoseconds::new(20))
    );
    assert_eq!(
        observation.end_time().instant(),
        Some(UnixNanoseconds::new(10))
    );
    assert_eq!(
        observation.start_time().quality(),
        SourceTimeQuality::Usable
    );
    assert_eq!(
        observation.end_time().quality(),
        SourceTimeQuality::Contradictory
    );
    Ok(())
}
