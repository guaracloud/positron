use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::{EventTime, ObservedTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSet, AttributeOccurrenceSetCandidate, ByteLimit,
    CandidateAttributeValue, CandidateKeyValue, CollectionLimit, DynamicValueLimits, NestingLimit,
    RecordLimits, RequestLimits, ValidatedAttributeValue, ValueLimitProfile,
    ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, PreparedStoreBlock, PrimaryDataVolume,
    SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};

use super::{
    AttributeRepresentation, LogRecord, LogScan, LogStore, LogStoreFailureCode, PolicyProvenance,
    ScanLimit, StoredLogAttribute, StoredLogRecord,
};
use crate::log_store::tests::support::{
    TemporaryRoot, establish_kernel_authority, preparation_capacity,
};

mod body;
mod capacity;
mod codec;
mod malformed;
mod public_contract;
mod scan;
mod support;
mod time;

fn minimal_record(body: &str, _ingest_time: i64) -> Result<LogRecord, Box<dyn Error>> {
    Ok(LogRecord::checked_minimal(
        None,
        Some(body.to_owned()),
        vec![],
        PolicyProvenance::new(1, [0x70; 32], vec![])?,
    )?)
}

fn clock(instant: i64) -> LifecycleClock<FixedLifecycleClockSource> {
    LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        instant,
    )))
}

fn encoded_log_fixture(tenant: TenantId) -> Vec<u8> {
    let mut bytes = b"PLOGBL01".to_vec();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&tenant.to_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(2);
    bytes.push(0);
    bytes.extend_from_slice(&1_i64.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(1);
    bytes.push(1);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.push(b'k');
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&[1; 32]);
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes
}

fn replaced_byte(bytes: &[u8], offset: usize, value: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut replaced = bytes.to_vec();
    *replaced
        .get_mut(offset)
        .ok_or("malformed fixture replacement offset")? = value;
    Ok(replaced)
}

fn replaced_bytes(bytes: &[u8], offset: usize, values: [u8; 2]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut replaced = bytes.to_vec();
    replaced
        .get_mut(offset..offset + values.len())
        .ok_or("malformed fixture replacement range")?
        .copy_from_slice(&values);
    Ok(replaced)
}

fn occurrences(
    profile: ValueLimitProfile,
    namespace: AttributeNamespace,
    key: &str,
    values: Vec<CandidateAttributeValue>,
) -> Result<AttributeOccurrenceSet, Box<dyn Error>> {
    Ok(
        AttributeOccurrenceSetCandidate::new(namespace, key.to_owned(), values)
            .validate(profile)?,
    )
}

fn value(
    profile: ValueLimitProfile,
    candidate: CandidateAttributeValue,
) -> Result<ValidatedAttributeValue, Box<dyn Error>> {
    let set = occurrences(
        profile,
        AttributeNamespace::Record,
        "value",
        vec![candidate],
    )?;
    Ok(set
        .occurrence(0)
        .ok_or("validated singleton occurrence missing")?
        .clone())
}

fn value_profile() -> Result<ValueLimitProfile, Box<dyn Error>> {
    let request = RequestLimits::new(
        ByteLimit::new(1_048_576)?,
        ByteLimit::new(1_048_576)?,
        CollectionLimit::new(1_024)?,
        CollectionLimit::new(4_096)?,
    );
    let record = RecordLimits::new(
        ByteLimit::new(1_048_576)?,
        ByteLimit::new(1_048_576)?,
        ByteLimit::new(262_144)?,
    );
    let dynamic = DynamicValueLimits::new(
        ByteLimit::new(65_536)?,
        CollectionLimit::new(1_024)?,
        ByteLimit::new(65_536)?,
        NestingLimit::new(16)?,
        CollectionLimit::new(1_024)?,
        CollectionLimit::new(1_024)?,
    );
    Ok(
        ValueLimitProfileCandidate::new(ValueLimitSet::new(request, record, dynamic), None)
            .validate()?,
    )
}
