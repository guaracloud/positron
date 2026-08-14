use std::error::Error;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, ReceiveFailure};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use prost::Message;

use super::support::{fixture, temporary_roots};

#[test]
fn nonempty_trace_and_span_ids_require_their_exact_native_widths() -> Result<(), Box<dyn Error>> {
    let roots = temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("missing ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let fixture = fixture(instance.default_tenant_id())?;

    for (trace_id, span_id) in [(vec![1; 15], vec![]), (vec![], vec![2; 7])] {
        let request = AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
            context,
            fixture.authority.governor(),
            request_with_ids(trace_id, span_id).encode_to_vec(),
        )?;
        assert_eq!(
            OtlpLogsReceiver::new()
                .decode(request)
                .expect_err("wrong-width nonempty correlation ID must fail closed"),
            ReceiveFailure::MalformedPayload
        );
    }
    Ok(())
}

fn request_with_ids(trace_id: Vec<u8>, span_id: Vec<u8>) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    trace_id,
                    span_id,
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}
