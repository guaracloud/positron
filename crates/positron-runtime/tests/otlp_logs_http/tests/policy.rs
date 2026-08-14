use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceResponse;
use positron_ingest::{
    IngestPolicy, PolicyAction, PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
};
use prost::Message;

use super::support::{HttpEncoding, LiveHttpHarness, otlp_request};

#[test]
fn json_and_protobuf_apply_the_same_native_policy_before_persistence()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = IngestPolicy::compile(
        61,
        [0x61; 32],
        vec![PolicyRule::new(
            "http-truncate",
            vec![PolicyPredicate::receiver(PolicyReceiver::OtlpLogs)],
            PolicyAction::TruncateBytes(PolicyTarget::body(), 4),
        )?],
    )?;
    let harness = LiveHttpHarness::start_with("policy", |configuration| {
        configuration.with_ingest_policy(policy)
    })?;

    for encoding in [HttpEncoding::Json, HttpEncoding::Protobuf] {
        let response = harness.export(encoding, otlp_request("sensitive"))?;
        assert_eq!(response.status(), 200);
        match encoding {
            HttpEncoding::Json => assert!(
                serde_json::from_slice::<ExportLogsServiceResponse>(response.body())?
                    .partial_success
                    .is_none()
            ),
            HttpEncoding::Protobuf => assert!(
                ExportLogsServiceResponse::decode(response.body())?
                    .partial_success
                    .is_none()
            ),
        }
    }
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["sens", "sens"]
    );
    Ok(())
}
