use positron_domain::identity::TenantId;
use positron_domain::time::{EventTime, ObservedTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::AttributeNamespace;

use super::LogStoreFailure;
use super::types::{AttributeRepresentation, StoredLogRecord};
use positron_kernel::LedgerSnapshot;

const MAGIC: &[u8; 8] = b"PLOGBL01";
const LEGACY_VERSION: u16 = 1;
const METADATA_VERSION: u16 = 2;
const VERSION: u16 = METADATA_VERSION;
#[cfg(fuzzing)]
mod fuzz;
mod limits;
mod metadata;
mod primitives;
mod record;
mod size;
mod value;
#[cfg(fuzzing)]
pub(super) use fuzz::fuzz_decode_block;
use limits::CodecLimits;
use primitives::{Input, put_bytes, put_count, put_i32, put_u16, put_u32};
pub(super) use size::encoded_block_length;

pub(super) fn encode_block(
    tenant: TenantId,
    records: &[StoredLogRecord],
    encoded_bytes: usize,
) -> Result<Vec<u8>, LogStoreFailure> {
    let limits = CodecLimits::release_1()?;
    if records.is_empty() || records.len() > limits.records {
        return Err(LogStoreFailure::limit_exceeded());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(encoded_bytes)
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    output.extend_from_slice(MAGIC);
    put_u16(&mut output, VERSION);
    output.extend_from_slice(&tenant.to_bytes());
    put_count(&mut output, records.len())?;
    for record in records {
        encode_record(&mut output, record, limits.nesting_depth)?;
    }
    if output.len() != encoded_bytes {
        return Err(LogStoreFailure::invalid_input());
    }
    Ok(output)
}

fn encode_record(
    output: &mut Vec<u8>,
    record: &StoredLogRecord,
    maximum_nesting_depth: u8,
) -> Result<(), LogStoreFailure> {
    encode_event_time(output, record.event_time());
    if let Some(observed) = record.observed_time() {
        output.push(1);
        encode_observed_time(output, observed);
    } else {
        output.push(0);
    }
    metadata::encode(output, record.record().metadata())?;
    output.extend_from_slice(&record.ingest_time().instant().value().to_be_bytes());
    if let Some(body) = record.body() {
        output.push(1);
        value::encode(output, body, maximum_nesting_depth)?;
    } else {
        output.push(0);
    }
    put_count(output, record.attributes().len())?;
    for attribute in record.attributes() {
        output.push(match attribute.representation() {
            AttributeRepresentation::Generic => 1,
            AttributeRepresentation::SchemaOverflow => 2,
        });
        let occurrences = attribute.occurrences();
        output.push(namespace_tag(occurrences.namespace()));
        put_bytes(output, occurrences.key().as_bytes())?;
        put_count(output, occurrences.len())?;
        for index in 0..occurrences.len() {
            let occurrence = occurrences
                .occurrence(index)
                .ok_or_else(LogStoreFailure::invalid_input)?;
            value::encode(output, occurrence, maximum_nesting_depth)?;
        }
    }
    let policy = record.policy_provenance();
    output.extend_from_slice(&policy.generation().to_be_bytes());
    output.extend_from_slice(&policy.digest());
    put_count(output, policy.applied_rules().len())?;
    for rule in policy.applied_rules() {
        put_bytes(output, rule.as_bytes())?;
    }
    Ok(())
}

fn encode_event_time(output: &mut Vec<u8>, time: EventTime) {
    output.push(quality_tag(time.quality()));
    if let Some(instant) = time.instant() {
        output.extend_from_slice(&instant.value().to_be_bytes());
    }
}

fn encode_observed_time(output: &mut Vec<u8>, time: ObservedTime) {
    output.push(quality_tag(time.quality()));
    output.extend_from_slice(
        &time
            .instant()
            .map_or(0, UnixNanoseconds::value)
            .to_be_bytes(),
    );
}

pub(super) fn decode_block(
    expected_tenant: TenantId,
    snapshot: &LedgerSnapshot<'_>,
    bytes: &[u8],
    limit: usize,
) -> Result<DecodedBlock, LogStoreFailure> {
    decode_block_cancellable(
        expected_tenant,
        snapshot,
        bytes,
        limit,
        &super::scan::NeverCancelled,
    )
}

pub(super) fn decode_block_cancellable(
    expected_tenant: TenantId,
    snapshot: &LedgerSnapshot<'_>,
    bytes: &[u8],
    limit: usize,
    cancellation: &dyn super::ScanCancellation,
) -> Result<DecodedBlock, LogStoreFailure> {
    BlockDecode::new(expected_tenant, bytes)?.decode(snapshot, limit, cancellation)
}

fn decode_block_header_with<'input>(
    expected_tenant: TenantId,
    mut input: Input<'input>,
) -> Result<(Input<'input>, u16, CodecLimits, usize), LogStoreFailure> {
    if input.take(MAGIC.len())? != MAGIC {
        return Err(LogStoreFailure::malformed_block());
    }
    let version = input.u16()?;
    if !matches!(version, LEGACY_VERSION | METADATA_VERSION) {
        return Err(LogStoreFailure::malformed_block());
    }
    let tenant: [u8; 16] = input
        .take(16)?
        .try_into()
        .map_err(|_| LogStoreFailure::malformed_block())?;
    if tenant != expected_tenant.to_bytes() {
        return Err(LogStoreFailure::physical_scope_mismatch());
    }
    let limits = CodecLimits::release_1()?;
    let count = input.count(limits.records)?;
    if count == 0 {
        return Err(LogStoreFailure::malformed_block());
    }
    Ok((input, version, limits, count))
}

pub(super) struct BlockDecode<'input> {
    input: Input<'input>,
    version: u16,
    limits: CodecLimits,
    count: usize,
}

impl<'input> BlockDecode<'input> {
    fn new(expected_tenant: TenantId, bytes: &'input [u8]) -> Result<Self, LogStoreFailure> {
        Self::from_input(expected_tenant, Input::new(bytes))
    }

    pub(super) fn observed(
        expected_tenant: TenantId,
        bytes: &'input [u8],
        cancellation: &'input dyn super::ScanCancellation,
        observer: &'input dyn super::ScanObserver,
    ) -> Result<Self, LogStoreFailure> {
        Self::from_input(
            expected_tenant,
            Input::observed(bytes, cancellation, observer),
        )
    }

    fn from_input(
        expected_tenant: TenantId,
        input: Input<'input>,
    ) -> Result<Self, LogStoreFailure> {
        input.observe_component()?;
        let (input, version, limits, count) = decode_block_header_with(expected_tenant, input)?;
        Ok(Self {
            input,
            version,
            limits,
            count,
        })
    }

    pub(super) const fn record_count(&self) -> usize {
        self.count
    }

    pub(super) fn validate(
        mut self,
        cancellation: &dyn super::ScanCancellation,
    ) -> Result<(), LogStoreFailure> {
        for _ in 0..self.count {
            check_decode_cancellation(cancellation)?;
            record::validate(&mut self.input, self.limits, self.version)?;
        }
        check_decode_cancellation(cancellation)?;
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(LogStoreFailure::malformed_block())
        }
    }

    pub(super) fn decode(
        mut self,
        snapshot: &LedgerSnapshot<'_>,
        limit: usize,
        cancellation: &dyn super::ScanCancellation,
    ) -> Result<DecodedBlock, LogStoreFailure> {
        decode_block_records(
            snapshot,
            limit,
            cancellation,
            &mut self.input,
            self.version,
            self.limits,
            self.count,
        )
    }
}

fn check_decode_cancellation(
    cancellation: &dyn super::ScanCancellation,
) -> Result<(), LogStoreFailure> {
    if cancellation.is_cancelled() {
        Err(LogStoreFailure::cancelled())
    } else {
        Ok(())
    }
}

fn decode_block_records(
    snapshot: &LedgerSnapshot<'_>,
    limit: usize,
    cancellation: &dyn super::ScanCancellation,
    input: &mut Input<'_>,
    version: u16,
    limits: CodecLimits,
    count: usize,
) -> Result<DecodedBlock, LogStoreFailure> {
    let retained_count = count.min(limit);
    let mut records = bounded_vec(retained_count)?;
    for index in 0..count {
        if cancellation.is_cancelled() {
            return Err(LogStoreFailure::cancelled());
        }
        let decoded = record::decode(input, limits, version)?;
        if index < retained_count {
            records.push(decoded.into_stored(snapshot));
        }
    }
    let truncated = retained_count < count;
    if !input.is_empty() {
        return Err(LogStoreFailure::malformed_block());
    }
    if cancellation.is_cancelled() {
        return Err(LogStoreFailure::cancelled());
    }
    Ok(DecodedBlock { records, truncated })
}

pub(super) struct DecodedBlock {
    pub(super) records: Vec<StoredLogRecord>,
    pub(super) truncated: bool,
}

pub(super) fn bounded_vec<T>(count: usize) -> Result<Vec<T>, LogStoreFailure> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    Ok(values)
}

fn quality_tag(quality: SourceTimeQuality) -> u8 {
    match quality {
        SourceTimeQuality::Usable => 1,
        SourceTimeQuality::Missing => 2,
        SourceTimeQuality::Zero => 3,
        SourceTimeQuality::Outlier => 4,
        SourceTimeQuality::Contradictory => 5,
    }
}

fn namespace_tag(namespace: AttributeNamespace) -> u8 {
    match namespace {
        AttributeNamespace::Resource => 1,
        AttributeNamespace::InstrumentationScope => 2,
        AttributeNamespace::Record => 3,
        AttributeNamespace::Stream => 4,
    }
}
