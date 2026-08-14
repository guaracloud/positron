use positron_domain::value::PolicyValueMarker;

use super::*;

#[test]
fn version_three_policy_evidence_and_provenance_survive_ledger_reopen() -> Result<(), Box<dyn Error>>
{
    let profile = value_profile()?;
    let body = value(
        profile,
        CandidateAttributeValue::truncated(CandidateAttributeValue::string("sens".to_owned())),
    )?;
    let attributes = vec![
        StoredLogAttribute::generic(occurrences(
            profile,
            AttributeNamespace::Record,
            "removed",
            vec![CandidateAttributeValue::policy_marker(
                PolicyValueMarker::Removed,
            )],
        )?),
        StoredLogAttribute::generic(occurrences(
            profile,
            AttributeNamespace::Record,
            "redacted",
            vec![CandidateAttributeValue::policy_marker(
                PolicyValueMarker::Redacted,
            )],
        )?),
    ];
    let provenance = PolicyProvenance::new(
        68,
        [0x68; 32],
        vec!["truncate-body".to_owned(), "remove-key".to_owned()],
    )?;
    let record = LogRecord::checked_native(
        profile,
        EventTime::missing(),
        None,
        Some(body),
        attributes,
        LogMetadata::empty(),
        provenance.clone(),
    )?;
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x68; 16])?,
        CatalogSecret::from_owned(Box::new([0x69; 32]), Box::new([0x6a; 32])),
    )?;
    let shard = VirtualShardId::new(68)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x6b; 32]));
    let store = LogStore::new();
    let prepared = store.prepare(
        preparation_capacity(&authority, tenant)?,
        &clock(680),
        tenant,
        shard,
        StoreBlockIdentity::new([0x6c; 16])?,
        vec![record],
    )?;
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    ledger.append(prepared.into_store_block())?;
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let snapshot = reopened.snapshot()?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    let persisted = &result.records()[0];
    assert_eq!(
        persisted.body().and_then(|body| body.as_str()),
        Some("sens")
    );
    assert!(persisted.body().is_some_and(|body| body.was_truncated()));
    assert_eq!(
        persisted.attributes()[0]
            .occurrences()
            .occurrence(0)
            .and_then(|value| value.policy_marker()),
        Some(PolicyValueMarker::Removed)
    );
    assert_eq!(
        persisted.attributes()[1]
            .occurrences()
            .occurrence(0)
            .and_then(|value| value.policy_marker()),
        Some(PolicyValueMarker::Redacted)
    );
    assert_eq!(persisted.policy_provenance(), &provenance);
    Ok(())
}

#[test]
fn version_two_plain_records_remain_readable() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let record = minimal_record("version-two", 2)?;
    let mut bytes = encoded_block(tenant, record, 2)?;
    bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        observe_encoded(tenant, bytes, 70)?,
        EncodedObservation::Read {
            body: Some("version-two".to_owned()),
            metadata_empty: true,
        }
    );
    Ok(())
}

#[test]
fn version_three_policy_tags_fail_closed_when_claimed_as_version_two() -> Result<(), Box<dyn Error>>
{
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let profile = value_profile()?;
    let marker = value(
        profile,
        CandidateAttributeValue::policy_marker(PolicyValueMarker::Redacted),
    )?;
    let record = LogRecord::checked_native(
        profile,
        EventTime::missing(),
        None,
        Some(marker),
        Vec::new(),
        LogMetadata::empty(),
        PolicyProvenance::new(71, [0x71; 32], vec!["redact".to_owned()])?,
    )?;
    let mut bytes = encoded_block(tenant, record, 3)?;
    bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        observe_encoded(tenant, bytes, 71)?,
        EncodedObservation::Failed(LogStoreFailureCode::MalformedBlock)
    );
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
enum EncodedObservation {
    Read {
        body: Option<String>,
        metadata_empty: bool,
    },
    Failed(LogStoreFailureCode),
}

fn encoded_block(
    tenant: TenantId,
    record: LogRecord,
    ingest_time: i64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let length = crate::log_store::codec::encoded_block_length(std::slice::from_ref(&record))?;
    let stored = StoredLogRecord::new(record, clock(ingest_time).assign_ingest_time()?);
    Ok(crate::log_store::codec::encode_block(
        tenant,
        &[stored],
        length,
    )?)
}

fn observe_encoded(
    tenant: TenantId,
    bytes: Vec<u8>,
    marker: u8,
) -> Result<EncodedObservation, Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([marker; 16])?,
        CatalogSecret::from_owned(Box::new([marker + 1; 32]), Box::new([marker + 2; 32])),
    )?;
    let shard = VirtualShardId::new(u32::from(marker))?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([marker + 3; 32])),
    )?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([marker + 4; 16])?,
        bytes,
    )?)?;
    let snapshot = ledger.snapshot()?;
    Ok(
        match LogStore::new().scan(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
        ) {
            Ok(result) => EncodedObservation::Read {
                body: result.records()[0]
                    .body()
                    .and_then(|body| body.as_str())
                    .map(ToOwned::to_owned),
                metadata_empty: result.records()[0].metadata() == &LogMetadata::empty(),
            },
            Err(failure) => EncodedObservation::Failed(failure.code()),
        },
    )
}
