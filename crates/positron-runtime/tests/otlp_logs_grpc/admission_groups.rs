use std::sync::Arc;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_ingest::{
    AdmissionGroupPlanFailure, AdmissionGroupPlanner, IngestPolicy, NativeLogCandidate,
};
use positron_runtime::{ExitOutcome, ShutdownTrigger};

use super::support::{LiveGrpcHarness, otlp_request};

struct ExplicitTwoShardPlan {
    first: VirtualShardId,
    second: VirtualShardId,
}

impl AdmissionGroupPlanner for ExplicitTwoShardPlan {
    fn assigned_shard(
        &self,
        _tenant: TenantId,
        signal: SignalKind,
        record_ordinal: u32,
        _record: &NativeLogCandidate,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        if signal != SignalKind::Logs {
            return Err(AdmissionGroupPlanFailure::UnsupportedSignal);
        }
        Ok(if record_ordinal == 0 {
            self.first
        } else {
            self.second
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn independent_groups_commit_and_report_permanent_rejection_without_rollback()
-> Result<(), Box<dyn std::error::Error>> {
    let policy =
        IngestPolicy::reject_exact_text_body(7, [0x77; 32], "reject-second-group", "reject-me")?;
    let planner = Arc::new(ExplicitTwoShardPlan {
        first: VirtualShardId::new(1)?,
        second: VirtualShardId::new(2)?,
    });
    let harness = LiveGrpcHarness::start_with("admission-groups", |configuration| {
        configuration
            .with_ingest_policy(policy)
            .with_admission_group_planner(planner)
    })?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{}", harness.endpoint())),
    )
    .await??;

    for _ in 0..2 {
        let mut payload = otlp_request("group-one");
        let rejected = otlp_request("reject-me")
            .resource_logs
            .into_iter()
            .next()
            .and_then(|resource| resource.scope_logs.into_iter().next())
            .and_then(|scope| scope.log_records.into_iter().next())
            .ok_or("rejected record fixture missing")?;
        payload
            .resource_logs
            .first_mut()
            .and_then(|resource| resource.scope_logs.first_mut())
            .ok_or("accepted scope fixture missing")?
            .log_records
            .push(rejected);
        let request = harness.authorize(tonic::Request::new(payload))?;
        let partial = tokio::time::timeout(Duration::from_secs(2), client.export(request))
            .await??
            .into_inner()
            .partial_success
            .ok_or("two-group mixed outcome omitted OTLP partial success")?;
        assert_eq!(partial.rejected_log_records, 1);
    }

    let bodies = harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?;
    assert_eq!(bodies, ["group-one", "group-one"]);
    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
