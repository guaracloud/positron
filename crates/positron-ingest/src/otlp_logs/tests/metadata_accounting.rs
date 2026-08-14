use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::value::CandidateAttributeValue;
use positron_kernel::{ResourceAmounts, ResourceDimension, WorkClaim, WorkKind};

use super::super::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, OtlpPayload, ReceiveFailure};
use crate::tests::support::{Fixture, attribution, fixture};
use crate::{AdmissionGroupPlanFailure, AdmissionGroupPlanner, NativeLogCandidate};

const RECORDS: usize = 1_024;
const EXACT_CLONED_METADATA_BYTES: u64 = 1_048_576;

struct OneShardPlan;

impl AdmissionGroupPlanner for OneShardPlan {
    fn assigned_shard(
        &self,
        _tenant: positron_domain::identity::TenantId,
        _signal: SignalKind,
        _record_ordinal: u32,
        _record: &NativeLogCandidate,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        VirtualShardId::new(1).map_err(|_| AdmissionGroupPlanFailure::AssignmentUnavailable)
    }
}

#[test]
fn shared_metadata_fanout_is_reserved_per_clone_and_one_byte_per_record_over_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let exact = admitted(&fixture, 256)?;
    let batch = OtlpLogsReceiver::new().decode(exact)?;

    assert_eq!(batch.records().len(), RECORDS);
    let retained_bytes = fixture
        .authority
        .governor()
        .inspect()?
        .usage(ResourceDimension::MemoryBytes);
    assert_eq!(retained_bytes, batch.decoded_bytes);
    assert!(retained_bytes > EXACT_CLONED_METADATA_BYTES);
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

#[test]
fn empty_record_structures_and_group_planning_are_retained_in_memory_charge()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let batch = OtlpLogsReceiver::new().decode(admitted_empty(&fixture, RECORDS)?)?;
    let decoded_usage = fixture
        .authority
        .governor()
        .inspect()?
        .usage(ResourceDimension::MemoryBytes);
    assert!(
        decoded_usage >= u64::try_from(RECORDS * std::mem::size_of::<NativeLogCandidate>())?,
        "empty native candidates must retain a nonzero fixed allocation charge"
    );

    let groups = batch.into_admission_groups(&OneShardPlan)?;
    let grouped_usage = fixture
        .authority
        .governor()
        .inspect()?
        .usage(ResourceDimension::MemoryBytes);
    assert!(grouped_usage > decoded_usage);
    drop(groups);
    assert_eq!(
        fixture
            .authority
            .governor()
            .inspect()?
            .usage(ResourceDimension::MemoryBytes),
        0
    );

    let over = admitted_empty(&fixture, RECORDS + 1)?;
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(over)
            .expect_err("one record over the 1024-unit boundary must be rejected"),
        ReceiveFailure::ValueLimitExceeded
    );
    Ok(())
}

#[test]
fn single_occurrence_vector_capacity_is_included_in_retained_charge()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let empty = OtlpLogsReceiver::new().decode(admitted_empty(&fixture, 1)?)?;
    let empty_usage = fixture
        .authority
        .governor()
        .inspect()?
        .usage(ResourceDimension::MemoryBytes);
    drop(empty);

    let attributed = OtlpLogsReceiver::new().decode(admitted_one_attribute(&fixture)?)?;
    let attributed_usage = fixture
        .authority
        .governor()
        .inspect()?
        .usage(ResourceDimension::MemoryBytes);
    let occurrence_capacity = 4 * std::mem::size_of::<CandidateAttributeValue>();
    let retained_increment = occurrence_capacity
        .checked_add(1)
        .ok_or("retained test bound overflowed")?;
    assert!(
        attributed_usage.checked_sub(empty_usage) >= Some(u64::try_from(retained_increment)?),
        "one occurrence retains the vector's minimum allocation capacity: empty={empty_usage}, attributed={attributed_usage}, expected_increment={retained_increment}"
    );
    drop(attributed);
    Ok(())
}

fn admitted_empty<'authority>(
    fixture: &'authority Fixture,
    records: usize,
) -> Result<AuthenticatedOtlpLogsRequest<'authority>, Box<dyn std::error::Error>> {
    let initial = fixture.authority.governor().reserve(WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        ResourceAmounts::new([4_194_304, 1, 1, 1_048_576, 1_025, 0, 0, 0, 1, 1, 0]),
    )?)?;
    Ok(AuthenticatedOtlpLogsRequest {
        attribution: attribution(),
        payload: OtlpPayload::Decoded(Box::new(ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord::default(); records],
                    ..ScopeLogs::default()
                }],
                ..ResourceLogs::default()
            }],
        })),
        capacity: Some(initial),
        receiver: crate::PolicyReceiver::OtlpGrpc,
    })
}

fn admitted_one_attribute(
    fixture: &Fixture,
) -> Result<AuthenticatedOtlpLogsRequest<'_>, Box<dyn std::error::Error>> {
    let mut admitted = admitted_empty(fixture, 1)?;
    let OtlpPayload::Decoded(request) = &mut admitted.payload else {
        return Err("decoded fixture payload missing".into());
    };
    request
        .resource_logs
        .first_mut()
        .and_then(|resource| resource.scope_logs.first_mut())
        .and_then(|scope| scope.log_records.first_mut())
        .ok_or("empty record fixture missing")?
        .attributes
        .push(KeyValue {
            key: "k".to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::BoolValue(true)),
            }),
            key_strindex: 0,
        });
    Ok(admitted)
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
        receiver: crate::PolicyReceiver::OtlpGrpc,
    })
}
