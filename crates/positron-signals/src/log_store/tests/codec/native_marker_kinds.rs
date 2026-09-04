use super::*;

use positron_domain::value::{AttributeValueKind, MarkerAction};
use positron_policy::{
    IngestPolicy, NativeLogAttribute, NativeLogCandidate, PolicyAction, PolicyAttributePath,
    PolicyEvaluation, PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
};

#[test]
fn public_log_store_reopen_preserves_redaction_kinds_for_all_scalar_natives()
-> Result<(), Box<dyn Error>> {
    let profile = value_profile()?;
    let attributes = [
        ("redacted-null", CandidateAttributeValue::null()),
        ("redacted-boolean", CandidateAttributeValue::boolean(true)),
        (
            "removed-integer",
            CandidateAttributeValue::signed_integer(-7),
        ),
        (
            "removed-floating",
            CandidateAttributeValue::floating_point_bits(3.5_f64.to_bits()),
        ),
    ];
    let mut rules = Vec::with_capacity(attributes.len());
    for (key, _) in attributes.iter() {
        let path = PolicyAttributePath::new(AttributeNamespace::Record, *key)?;
        let action = if key.starts_with("redacted") {
            PolicyAction::Redact(PolicyTarget::attribute(path.clone()))
        } else {
            PolicyAction::Remove(PolicyTarget::attribute(path.clone()))
        };
        rules.push(PolicyRule::new(
            *key,
            vec![PolicyPredicate::attribute_exists(path)],
            action,
        )?);
    }
    let policy = IngestPolicy::compile(17, rules)?;
    let candidate = NativeLogCandidate::new(
        None,
        None,
        None,
        attributes
            .into_iter()
            .map(|(key, value)| {
                NativeLogAttribute::new(AttributeNamespace::Record, key.to_owned(), vec![value])
            })
            .collect(),
        positron_policy::LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        policy.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("policy unexpectedly rejected scalar marker candidate".into());
    };
    let record = LogRecord::checked_evaluated(profile, *evaluated)?;
    let expected = [
        (MarkerAction::Redacted, AttributeValueKind::Null),
        (MarkerAction::Redacted, AttributeValueKind::Boolean),
        (MarkerAction::Removed, AttributeValueKind::SignedInteger),
        (MarkerAction::Removed, AttributeValueKind::FloatingPoint),
    ];
    for (attribute, (action, kind)) in record.attributes().iter().zip(expected) {
        let value = attribute
            .occurrences()
            .occurrence(0)
            .ok_or("missing scalar marker occurrence")?;
        assert_eq!(value.marker_action(), Some(action));
        assert_eq!(value.marker_original_kind(), Some(kind));
        assert!(!value.is_null());
        assert_eq!(value.as_boolean(), None);
        assert_eq!(value.as_signed_integer(), None);
        assert_eq!(value.as_floating_point_bits(), None);
        assert_eq!(value.as_str(), None);
        assert_eq!(value.as_bytes(), None);
    }

    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(72)?;
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x58; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    LogStore::new()
        .prepare_unretained_for_test(
            preparation_capacity(&authority, tenant)?,
            &clock(1_200),
            tenant,
            shard,
            StoreBlockIdentity::new([0x68; 16])?,
            vec![record.clone()],
        )
        .map(|prepared| ledger.append(prepared.into_store_block()))??;
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let store = LogStore::new();
    let result = store.scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    let scanned = result
        .records()
        .first()
        .ok_or("missing reopened scalar marker record")?
        .record();
    assert_eq!(scanned, &record);
    for (attribute, (action, kind)) in scanned.attributes().iter().zip(expected) {
        let value = attribute
            .occurrences()
            .occurrence(0)
            .ok_or("missing reopened scalar marker occurrence")?;
        assert_eq!(value.marker_action(), Some(action));
        assert_eq!(value.marker_original_kind(), Some(kind));
        assert!(!value.is_null());
        assert_eq!(value.as_boolean(), None);
        assert_eq!(value.as_signed_integer(), None);
        assert_eq!(value.as_floating_point_bits(), None);
        assert_eq!(value.as_str(), None);
        assert_eq!(value.as_bytes(), None);
    }
    Ok(())
}
