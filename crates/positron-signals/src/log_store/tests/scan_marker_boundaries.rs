use super::*;

use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, AttributeValueKind,
    CandidateAttributeValue, MarkerAction,
};
use positron_policy::PolicyProvenance;

#[test]
fn bounded_scan_validates_marker_tail_without_materializing_it() -> Result<(), Box<dyn Error>> {
    let profile = value_profile()?;
    let first = minimal_record("first", 1)?;
    let tail = LogRecord::checked_receiver_candidate(
        profile,
        None,
        None,
        None,
        vec![AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "sensitive".to_owned(),
            vec![
                CandidateAttributeValue::redaction_marker(
                    AttributeValueKind::String,
                    MarkerAction::Redacted,
                ),
                CandidateAttributeValue::truncated(
                    CandidateAttributeValue::string("safe".to_owned()),
                    MarkerAction::TruncatedBytes,
                ),
            ],
        )],
        PolicyProvenance::new(
            2,
            [0x72; 32],
            vec!["redact".to_owned(), "truncate".to_owned()],
        )?,
    )?;
    assert_eq!(
        tail.attributes()[0]
            .occurrences()
            .occurrence(0)
            .ok_or("missing marker occurrence")?
            .marker_action(),
        Some(MarkerAction::Redacted)
    );
    assert_eq!(
        tail.attributes()[0]
            .occurrences()
            .occurrence(1)
            .ok_or("missing truncation occurrence")?
            .truncation_action(),
        Some(MarkerAction::TruncatedBytes)
    );

    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(73)?;
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x19; 16])?,
        CatalogSecret::from_owned(Box::new([0x29; 32]), Box::new([0x39; 32])),
    )?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    ledger.append(
        LogStore::new()
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &clock(1_000),
                tenant,
                shard,
                StoreBlockIdentity::new([0x69; 16])?,
                vec![first.clone(), tail],
            )?
            .into_store_block(),
    )?;

    let result = LogStore::new().scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.records().len(), 1);
    assert_eq!(result.decoded_records(), 1);
    assert_eq!(result.records()[0].record(), &first);
    assert!(!result.complete());
    Ok(())
}
