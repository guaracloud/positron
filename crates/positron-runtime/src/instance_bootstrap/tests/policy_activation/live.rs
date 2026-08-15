use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_ingest::{
    AdmissionGroupPlanFailure, AdmissionGroupPlanner, IngestFailureCode, IngestOutcome,
    IngestPolicy, NativeLogCandidate, PolicyAction, PolicyRule,
};
use prost::Message;

use crate::services::ServiceHandle;

use super::super::super::{InitializationPlan, InstanceBootstrap};
use super::super::support::Roots;

struct BlockingTwoGroups {
    entered: mpsc::SyncSender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
    shards: [VirtualShardId; 2],
    blocked: AtomicBool,
}

impl AdmissionGroupPlanner for BlockingTwoGroups {
    fn assigned_shard(
        &self,
        _tenant: TenantId,
        _signal: SignalKind,
        ordinal: u32,
        _record: &NativeLogCandidate,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        if ordinal == 0 && !self.blocked.swap(true, Ordering::AcqRel) {
            self.entered
                .send(())
                .map_err(|_| AdmissionGroupPlanFailure::AssignmentUnavailable)?;
            self.resume
                .lock()
                .map_err(|_| AdmissionGroupPlanFailure::AssignmentUnavailable)?
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| AdmissionGroupPlanFailure::AssignmentUnavailable)?;
        }
        self.shards
            .get(
                usize::try_from(ordinal)
                    .map_err(|_| AdmissionGroupPlanFailure::RecordCountExceeded)?,
            )
            .copied()
            .ok_or(AdmissionGroupPlanFailure::RecordCountExceeded)
    }
}

#[test]
fn running_service_switches_after_activation_but_inflight_groups_keep_one_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let mut initialized = InstanceBootstrap::reopen(&paths)?;
    let administrator = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let ingest_secret = claim.ingest_secret().ok_or("ingest secret")?.to_owned();
    let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(1);
    initialized.admission_group_planner = Arc::new(BlockingTwoGroups {
        entered: entered_sender,
        resume: Mutex::new(resume_receiver),
        shards: [initialized.logs_shard, VirtualShardId::new(2)?],
        blocked: AtomicBool::new(false),
    });
    let initialized = Arc::new(initialized);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;

    let inflight = thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let inflight_services = services.clone();
        let ingest_secret = ingest_secret.clone();
        let handle = scope.spawn(move || {
            inflight_services.ingest_otlp_logs(
                &ingest_secret,
                request(&["old-first", "old-second"]).encode_to_vec(),
            )
        });
        entered_receiver.recv_timeout(Duration::from_secs(2))?;
        services
            .activate_ingest_policy(
                administrator,
                ResourceGeneration::new(1)?,
                AdministrativeIdempotencyKey::new([0xa1; 16])?,
                IngestPolicy::compile(
                    2,
                    vec![PolicyRule::new(
                        "reject-after-activation",
                        Vec::new(),
                        PolicyAction::Reject,
                    )?],
                )?,
            )
            .map_err(|failure| std::io::Error::other(format!("activation: {failure:?}")))?;
        resume_sender.send(())?;
        let joined = handle
            .join()
            .map_err(|_| std::io::Error::other("service thread panicked"))?;
        Ok(joined
            .map_err(|failure| std::io::Error::other(format!("in-flight ingest: {failure:?}")))?)
    })?;
    assert_eq!(inflight.groups().len(), 2);
    assert_eq!(inflight.accepted_records(), 2);

    let after = services
        .ingest_otlp_logs(&ingest_secret, request(&["new-request"]).encode_to_vec())
        .map_err(|failure| std::io::Error::other(format!("new ingest: {failure:?}")))?;
    assert_eq!(after.permanently_rejected_records(), 1);
    assert_eq!(
        after.terminal_failure(),
        Some(IngestOutcome::Permanent(IngestFailureCode::PolicyRejected))
    );
    Ok(())
}

fn request(bodies: &[&str]) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: bodies
                    .iter()
                    .map(|body| LogRecord {
                        time_unix_nano: 42,
                        observed_time_unix_nano: 84,
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue((*body).to_owned())),
                        }),
                        ..LogRecord::default()
                    })
                    .collect(),
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}
