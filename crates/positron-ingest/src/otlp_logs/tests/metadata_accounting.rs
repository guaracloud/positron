use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::InstrumentationScope;
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_kernel::{ResourceAmounts, ResourceDimension, WorkClaim, WorkKind};

use super::super::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, OtlpPayload, ReceiveFailure};
use crate::tests::support::{Fixture, attribution, fixture};

const RECORDS: usize = 1_024;
const EXACT_CLONED_METADATA_BYTES: u64 = 1_048_576;

#[test]
fn shared_metadata_fanout_is_reserved_per_clone_and_one_byte_per_record_over_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let exact = admitted(&fixture, 256)?;
    let batch = OtlpLogsReceiver::new().decode(exact)?;

    assert_eq!(batch.records().len(), RECORDS);
    assert_eq!(
        fixture
            .authority
            .governor()
            .inspect()?
            .usage(ResourceDimension::MemoryBytes),
        EXACT_CLONED_METADATA_BYTES
    );
    drop(batch);
    assert_eq!(
        fixture
            .authority
            .governor()
            .inspect()?
            .usage(ResourceDimension::MemoryBytes),
        0
    );

    let over = admitted(&fixture, 257)?;
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(over)
            .expect_err("one extra shared byte cloned into every record exceeds the request bound"),
        ReceiveFailure::ValueLimitExceeded
    );
    assert_eq!(
        fixture
            .authority
            .governor()
            .inspect()?
            .usage(ResourceDimension::MemoryBytes),
        0
    );
    Ok(())
}

fn admitted<'authority>(
    fixture: &'authority Fixture,
    final_metadata_bytes: usize,
) -> Result<AuthenticatedOtlpLogsRequest<'authority>, Box<dyn std::error::Error>> {
    let initial = fixture.authority.governor().reserve(WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        ResourceAmounts::new([
            4_194_304,
            1,
            1,
            1_048_576,
            u64::try_from(RECORDS)?,
            0,
            0,
            0,
            1,
            1,
            0,
        ]),
    )?)?;
    let repeated = "m".repeat(256);
    let final_value = "n".repeat(final_metadata_bytes);
    let decoded = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            schema_url: repeated.clone(),
            scope_logs: vec![ScopeLogs {
                schema_url: final_value,
                scope: Some(InstrumentationScope {
                    name: repeated.clone(),
                    version: repeated,
                    ..InstrumentationScope::default()
                }),
                log_records: vec![LogRecord::default(); RECORDS],
            }],
            ..ResourceLogs::default()
        }],
    };
    Ok(AuthenticatedOtlpLogsRequest {
        attribution: attribution(),
        payload: OtlpPayload::Decoded(Box::new(decoded)),
        capacity: Some(initial),
    })
}
