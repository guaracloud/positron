use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};

use super::super::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, OtlpPayload};
use crate::tests::support::attribution;

#[test]
fn all_zero_trace_and_span_ids_map_to_absent_association() -> Result<(), Box<dyn std::error::Error>>
{
    let decoded = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    trace_id: vec![0; 16],
                    span_id: vec![0; 8],
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    };
    let request = AuthenticatedOtlpLogsRequest {
        attribution: attribution(),
        payload: OtlpPayload::Decoded(Box::new(decoded)),
        capacity: None,
    };

    let batch = OtlpLogsReceiver::new().decode(request)?;
    let metadata = &batch.records[0].metadata;

    assert_eq!(metadata.trace_id(), None);
    assert_eq!(metadata.span_id(), None);
    Ok(())
}
