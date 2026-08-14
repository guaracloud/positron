use std::error::Error;
use std::sync::Arc;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_ingest::{
    AdmissionGroupPlanFailure, AdmissionGroupPlanner, IngestPolicy, NativeLogCandidate,
    PolicyAction, PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
};
use positron_runtime::ListenerRole;
use prost::Message;

use super::{producer, support};

struct TwoShardPlan {
    first: VirtualShardId,
    second: VirtualShardId,
}

impl AdmissionGroupPlanner for TwoShardPlan {
    fn assigned_shard(
        &self,
        _tenant: TenantId,
        signal: SignalKind,
        ordinal: u32,
        _record: &NativeLogCandidate,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        if signal != SignalKind::Logs {
            return Err(AdmissionGroupPlanFailure::UnsupportedSignal);
        }
        Ok(if ordinal == 0 {
            self.first
        } else {
            self.second
        })
    }
}

#[test]
fn independent_groups_commit_without_request_rollback_and_retries_may_duplicate()
-> Result<(), Box<dyn Error>> {
    let policy = IngestPolicy::reject_exact_text_body(
        43,
        [0x43; 32],
        "reject-second-loki-group",
        "reject-me",
    )?;
    let planner = Arc::new(TwoShardPlan {
        first: VirtualShardId::new(1)?,
        second: VirtualShardId::new(2)?,
    });
    let harness = support::LiveLokiHarness::start_with("partial-groups", |configuration| {
        configuration
            .with_ingest_policy(policy)
            .with_admission_group_planner(planner)
    })?;
    let body = br#"{"streams":[{"stream":{"app":"policy"},"values":[["42","keep-me"],["43","reject-me"]]}]}"#;
    let headers = [
        ("Authorization", format!("Bearer {}", harness.bearer())),
        ("Content-Type", "application/json".to_owned()),
    ];
    let borrowed = headers
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect::<Vec<_>>();

    for _ in 0..2 {
        support::assert_status(
            harness.http(
                ListenerRole::LokiPush,
                "POST",
                "/loki/api/v1/push",
                &borrowed,
                body,
            )?,
            400,
        );
    }
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["keep-me", "keep-me"]
    );
    Ok(())
}

#[test]
fn value_limits_reject_before_store_block_commit() -> Result<(), Box<dyn Error>> {
    let harness = support::LiveLokiHarness::start("value-limit")?;
    let line = "x".repeat(262_145);
    let body = format!(
        "{{\"streams\":[{{\"stream\":{{\"app\":\"limits\"}},\"values\":[[\"42\",\"{line}\"]]}}]}}"
    );
    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", &format!("Bearer {}", harness.bearer())),
                ("Content-Type", "application/json"),
            ],
            body.as_bytes(),
        )?,
        400,
    );
    assert!(
        harness
            .query_log_bodies("logs | range query_time 0 100 | limit 16")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn loki_push_and_otlp_alias_encodings_share_one_native_policy() -> Result<(), Box<dyn Error>> {
    let policy = IngestPolicy::compile(
        63,
        [0x63; 32],
        vec![
            truncate_rule("loki-truncate", PolicyReceiver::LokiPush)?,
            truncate_rule("otlp-alias-truncate", PolicyReceiver::OtlpLogs)?,
        ],
    )?;
    let harness = support::LiveLokiHarness::start_with("policy-matrix", |configuration| {
        configuration.with_ingest_policy(policy)
    })?;
    let auth = format!("Bearer {}", harness.bearer());

    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", &auth),
                ("Content-Type", "application/json"),
            ],
            br#"{"streams":[{"stream":{"app":"policy"},"values":[["42","json-sensitive"]]}]}"#,
        )?,
        204,
    );
    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", &auth),
                ("Content-Type", "application/x-protobuf"),
                ("Content-Encoding", "snappy"),
            ],
            &producer::snappy_push("snappy-sensitive")?,
        )?,
        204,
    );

    let request = otlp_request("otlp-sensitive");
    let protobuf = request.encode_to_vec();
    let json = serde_json::to_vec(&request)?;
    for (content_type, body) in [
        ("application/x-protobuf", protobuf.as_slice()),
        ("application/json", json.as_slice()),
    ] {
        support::assert_status(
            harness.http(
                ListenerRole::LokiPush,
                "POST",
                "/otlp/v1/logs",
                &[("Authorization", &auth), ("Content-Type", content_type)],
                body,
            )?,
            200,
        );
    }
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 2000000000 | limit 16")?,
        ["json", "otlp", "otlp", "snap"]
    );
    Ok(())
}

fn truncate_rule(id: &str, receiver: PolicyReceiver) -> Result<PolicyRule, Box<dyn Error>> {
    Ok(PolicyRule::new(
        id,
        vec![PolicyPredicate::receiver(receiver)],
        PolicyAction::TruncateBytes(PolicyTarget::body(), 4),
    )?)
}

fn otlp_request(body: &str) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(body.to_owned())),
                    }),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}
