use std::sync::Arc;

use super::super::super::ResponseEncoding;
use super::support::{
    Completion, HttpHarness, ScriptedBackend, decode_status, decode_success, trace_body_for,
};

#[test]
fn live_http_trace_export_maps_retry_classes_and_releases_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        let backend = Arc::new(ScriptedBackend::new([
            Completion::Capacity,
            Completion::Retryable,
            Completion::Permanent,
            Completion::Ambiguous,
            Completion::Committed,
        ]));
        let harness = HttpHarness::start(backend.clone())?;
        let baseline = harness.governor_snapshot()?.outstanding_total();

        let capacity = harness.request(
            encoding,
            trace_body_for(encoding)?,
            None,
            Some(&harness.bearer),
            None,
            None,
        )?;
        assert_eq!(
            capacity.status(),
            429,
            "content_type={}, body={:?}, backend_calls={}",
            capacity.content_type(),
            capacity.body(),
            backend.calls()
        );
        assert_eq!(capacity.retry_after_seconds(), Some(1));
        assert_eq!(decode_status(&capacity, encoding).code, 8);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);

        let retryable = harness.request(
            encoding,
            trace_body_for(encoding)?,
            None,
            Some(&harness.bearer),
            None,
            None,
        )?;
        assert_eq!(retryable.status(), 503);
        assert_eq!(retryable.retry_after_seconds(), None);
        assert_eq!(decode_status(&retryable, encoding).code, 14);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);

        let permanent = harness.request(
            encoding,
            trace_body_for(encoding)?,
            None,
            Some(&harness.bearer),
            None,
            None,
        )?;
        assert_eq!(permanent.status(), 400);
        assert_eq!(decode_status(&permanent, encoding).code, 3);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);

        // The backend records the commit before returning the ambiguous result.
        // Dropping this response models a lost producer response; the retry is
        // still allowed to commit because the contract is at-least-once.
        let ambiguous = harness.request(
            encoding,
            trace_body_for(encoding)?,
            None,
            Some(&harness.bearer),
            None,
            None,
        )?;
        assert_eq!(ambiguous.status(), 503);
        assert!(
            decode_status(&ambiguous, encoding)
                .message
                .contains("retry may duplicate spans")
        );
        drop(ambiguous);
        assert_eq!(backend.committed_records(), 1);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);

        let retry_after_lost_response = harness.request(
            encoding,
            trace_body_for(encoding)?,
            None,
            Some(&harness.bearer),
            None,
            None,
        )?;
        assert_eq!(retry_after_lost_response.status(), 200);
        let response = decode_success(&retry_after_lost_response, encoding)?;
        assert!(response.partial_success.is_none());
        assert_eq!(backend.committed_records(), 2);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);
    }
    Ok(())
}
