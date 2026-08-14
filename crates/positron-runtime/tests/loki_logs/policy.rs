use std::error::Error;
use std::sync::Arc;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_ingest::{
    AdmissionGroupPlanFailure, AdmissionGroupPlanner, IngestPolicy, NativeLogCandidate,
};
use positron_runtime::ListenerRole;

use super::support;

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
