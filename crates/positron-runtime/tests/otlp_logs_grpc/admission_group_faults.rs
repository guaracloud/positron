use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_ingest::{AdmissionGroupPlanFailure, AdmissionGroupPlanner, NativeLogCandidate};
use positron_kernel::{
    LedgerFailureCode, LedgerFileEvent, LedgerOperationFaultSource, SegmentScope,
};
use positron_runtime::{ExitOutcome, ShutdownTrigger};
use tonic::Code;

use super::support::{LiveGrpcHarness, otlp_request};

struct ExplicitTwoShardPlan;

impl AdmissionGroupPlanner for ExplicitTwoShardPlan {
    fn assigned_shard(
        &self,
        _tenant: TenantId,
        _signal: SignalKind,
        record_ordinal: u32,
        _record: &NativeLogCandidate,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        VirtualShardId::new(record_ordinal.saturating_add(1))
            .map_err(|_| AdmissionGroupPlanFailure::AssignmentUnavailable)
    }
}

struct OneShotShardFault {
    shard: VirtualShardId,
    event: LedgerFileEvent,
    fired: AtomicBool,
}

impl OneShotShardFault {
    fn new(shard: VirtualShardId, event: LedgerFileEvent) -> Self {
        Self {
            shard,
            event,
            fired: AtomicBool::new(false),
        }
    }
}

impl LedgerOperationFaultSource for OneShotShardFault {
    fn take_failure(
        &self,
        scope: SegmentScope,
        event: LedgerFileEvent,
    ) -> Option<LedgerFailureCode> {
        (scope.shard_id() == self.shard
            && event == self.event
            && self
                .fired
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok())
        .then_some(LedgerFailureCode::StorageUnavailable)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn second_group_prewrite_fault_is_retryable_without_rolling_back_first_group()
-> Result<(), Box<dyn std::error::Error>> {
    run_two_shard_fault(
        "group2-retryable",
        LedgerFileEvent::WriteFrame,
        "temporarily unavailable",
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn second_group_frontier_sync_fault_is_ambiguous_without_rolling_back_first_group()
-> Result<(), Box<dyn std::error::Error>> {
    run_two_shard_fault(
        "group2-ambiguous",
        LedgerFileEvent::SynchronizeFrontierDirectory,
        "ambiguous",
    )
    .await
}

async fn run_two_shard_fault(
    label: &str,
    event: LedgerFileEvent,
    expected_message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let second_shard = VirtualShardId::new(2)?;
    let fault = Arc::new(OneShotShardFault::new(second_shard, event));
    let source: Arc<dyn LedgerOperationFaultSource> = fault.clone();
    let harness = LiveGrpcHarness::start_with(label, |configuration| {
        configuration
            .with_admission_group_planner(Arc::new(ExplicitTwoShardPlan))
            .with_ledger_operation_fault_source(source)
    })?;
    let mut client = LogsServiceClient::connect(format!("http://{}", harness.endpoint())).await?;
    let status = client
        .export(harness.authorize(tonic::Request::new(two_record_request()?))?)
        .await
        .expect_err("second shard operation fault must fail the request");
    assert_eq!(status.code(), Code::Unavailable);
    assert!(status.message().contains(expected_message));
    assert!(fault.fired.load(Ordering::Acquire));
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["first-durable"]
    );
    let initial_second = harness
        .query_log_bodies_on_shard(second_shard, "logs | range query_time 0 100 | limit 16")?;
    if event == LedgerFileEvent::WriteFrame {
        assert!(initial_second.is_empty());
    } else {
        assert!(initial_second.len() <= 1);
    }

    assert!(
        client
            .export(harness.authorize(tonic::Request::new(two_record_request()?))?)
            .await?
            .into_inner()
            .partial_success
            .is_none()
    );
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["first-durable", "first-durable"]
    );
    let retried_second = harness
        .query_log_bodies_on_shard(second_shard, "logs | range query_time 0 100 | limit 16")?;
    assert_eq!(retried_second.len(), initial_second.len().saturating_add(1));
    assert!(retried_second.iter().all(|body| body == "second-faulted"));
    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}

fn two_record_request()
-> Result<opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest, &'static str> {
    let mut payload = otlp_request("first-durable");
    let second = otlp_request("second-faulted")
        .resource_logs
        .into_iter()
        .next()
        .and_then(|resource| resource.scope_logs.into_iter().next())
        .and_then(|scope| scope.log_records.into_iter().next())
        .ok_or("second record fixture missing")?;
    payload
        .resource_logs
        .first_mut()
        .and_then(|resource| resource.scope_logs.first_mut())
        .ok_or("first record fixture missing")?
        .log_records
        .push(second);
    Ok(payload)
}
