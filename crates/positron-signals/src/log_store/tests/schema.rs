use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, PrimaryDataVolume, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};

use super::{AttributeRepresentation, LogRecord, LogScan, LogStore, ScanLimit};
use crate::log_store::tests::support::{
    TemporaryRoot, establish_kernel_authority, preparation_capacity,
};
use crate::{SchemaBudget, SchemaCatalog};

#[test]
fn schema_overflow_survives_preparation_and_kernel_scan_losslessly() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(8)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let policy = IngestPolicy::preserving(1)?;
    let make_record = |key: &str, value: &str| -> Result<LogRecord, Box<dyn Error>> {
        let candidate = NativeLogCandidate::new(
            None,
            None,
            Some(CandidateAttributeValue::string("body".to_owned())),
            vec![NativeLogAttribute::new(
                AttributeNamespace::Record,
                key.to_owned(),
                vec![CandidateAttributeValue::string(value.to_owned())],
            )],
            LogMetadata::empty(),
        );
        let PolicyEvaluation::Accepted(evaluated) =
            policy.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
        else {
            return Err("preserving policy rejected fixture".into());
        };
        Ok(LogRecord::checked_evaluated(
            LogStore::value_limit_profile(),
            *evaluated,
        )?)
    };
    let first = make_record("first", "one")?;
    let second = make_record("second", "two")?;
    let mut schema = SchemaCatalog::new(SchemaBudget::new(1, 512, 512, 256)?)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    ledger.append(
        LogStore::new()
            .prepare_with_schema(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x68; 16])?,
                vec![first.clone(), second.clone()],
                &mut schema,
            )?
            .into_store_block(),
    )?;
    let result = LogStore::new().scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(2)?),
    )?;
    assert_eq!(result.records()[0].record(), &first);
    assert_eq!(result.records()[1].record(), &second);
    assert_eq!(
        result.records()[0].attributes()[0].representation(),
        AttributeRepresentation::Generic
    );
    assert_eq!(
        result.records()[1].attributes()[0].representation(),
        AttributeRepresentation::SchemaOverflow
    );
    assert_eq!(schema.overflow_record_count(), 1);
    Ok(())
}
