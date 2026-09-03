use std::sync::Arc;

use opentelemetry_proto::tonic::common::v1::KeyValue;
use prost::Message;

use super::super::super::ResponseEncoding;
use super::support::{HttpHarness, ScriptedBackend, decode_success, trace_request};

#[test]
fn live_http_trace_export_reports_per_span_rejection_as_partial_success()
-> Result<(), Box<dyn std::error::Error>> {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        let backend = Arc::new(ScriptedBackend::new([]));
        let harness = HttpHarness::start(backend.clone())?;
        let baseline = harness.governor_snapshot()?.outstanding_total();
        let mut request = trace_request();
        request
            .resource_spans
            .first_mut()
            .and_then(|resource| resource.scope_spans.first_mut())
            .and_then(|scope| scope.spans.first_mut())
            .ok_or("trace fixture span missing")?
            .attributes
            .push(KeyValue {
                key: "profile-only".to_owned(),
                key_strindex: 1,
                ..KeyValue::default()
            });
        let body = match encoding {
            ResponseEncoding::Protobuf => request.encode_to_vec(),
            ResponseEncoding::Json => serde_json::to_vec(&request)?,
        };
        let response = harness.request(encoding, body, None, Some(&harness.bearer), None, None)?;
        assert_eq!(response.status(), 200);
        let partial = decode_success(&response, encoding)?
            .partial_success
            .ok_or("missing partial success")?;
        assert_eq!(partial.rejected_spans, 1);
        assert_eq!(
            partial.error_message,
            "some spans were permanently rejected"
        );
        assert_eq!(backend.calls(), 0);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);
    }
    Ok(())
}
