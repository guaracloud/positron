use std::error::Error;

use positron_domain::value::{
    ByteLimit, RecordLimits, ValueLimitProfile, ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_ingest::{
    AuthenticatedOtlpLogsRequest, IngestFailureCode, IngestOutcome, IngestPolicy, LogIngest,
    OtlpLogsReceiver, PolicyAction, PolicyPredicate, PolicyRule, PolicyTarget,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use prost::Message;

use super::policy_actions::{attributed_instance, bodies_request, ingest_and_scan};
use super::support::fixture;

#[test]
fn body_remove_redact_and_utf8_truncate_persist_typed_evidence() -> Result<(), Box<dyn Error>> {
    let (instance, context) = attributed_instance("body-policy")?;
    let fixture = fixture(instance.default_tenant_id())?;
    let request = AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
        context,
        fixture.authority.governor(),
        bodies_request(&["remove-body", "redact-body", "ol\u{00e1}-mundo"]).encode_to_vec(),
    )?;
    let batch = OtlpLogsReceiver::new().decode(request)?;
    let policy = IngestPolicy::compile(
        24,
        vec![
            PolicyRule::new(
                "remove-body",
                vec![PolicyPredicate::body_exact_text("remove-body")?],
                PolicyAction::Remove(PolicyTarget::body()),
            )?,
            PolicyRule::new(
                "redact-body",
                vec![PolicyPredicate::body_exact_text("redact-body")?],
                PolicyAction::Redact(PolicyTarget::body()),
            )?,
            PolicyRule::new(
                "truncate-body",
                vec![PolicyPredicate::body_exact_text("ol\u{00e1}-mundo")?],
                PolicyAction::TruncateBytes(PolicyTarget::body(), 5),
            )?,
        ],
    )?;
    let result = ingest_and_scan(&fixture, batch, &policy, 52)?;
    let records = result.records();
    assert_eq!(records.len(), 3);
    assert!(records[0].body().is_none());
    assert!(records[1].body().is_some_and(|body| body.is_null()));
    let truncated = records[2].body().ok_or("truncated body disappeared")?;
    assert_eq!(truncated.as_str(), Some("ol\u{00e1}-"));
    assert_eq!(
        records[0].policy_provenance().applied_rules(),
        &["remove-body"]
    );
    assert_eq!(
        records[1].policy_provenance().applied_rules(),
        &["redact-body"]
    );
    assert_eq!(
        records[2].policy_provenance().applied_rules(),
        &["truncate-body"]
    );
    Ok(())
}

#[test]
fn body_truncation_precedes_the_post_policy_value_limit_profile() -> Result<(), Box<dyn Error>> {
    let (instance, context) = attributed_instance("body-limit-policy")?;
    let fixture = fixture(instance.default_tenant_id())?;
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let tenant = ValueLimitSet::new(
        maximum.request(),
        RecordLimits::new(
            maximum.record().encoded_bytes(),
            maximum.record().decoded_bytes(),
            ByteLimit::new(4)?,
        ),
        maximum.dynamic_value(),
    );
    let profile = ValueLimitProfileCandidate::new(maximum, Some(tenant)).validate()?;
    let request = AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
        context,
        fixture.authority.governor(),
        bodies_request(&["12345"]).encode_to_vec(),
    )?;
    let batch = OtlpLogsReceiver::with_value_limit_profile(profile).decode(request)?;
    let policy = IngestPolicy::compile(
        26,
        vec![PolicyRule::new(
            "fit-body-limit",
            Vec::new(),
            PolicyAction::TruncateBytes(PolicyTarget::body(), 4),
        )?],
    )?;
    let result = ingest_and_scan(&fixture, batch, &policy, 102)?;
    let body = result.records()[0].body().ok_or("truncated body missing")?;
    assert_eq!(body.as_str(), Some("1234"));
    Ok(())
}

#[test]
fn unchanged_body_that_exceeds_the_post_policy_limit_is_rejected() -> Result<(), Box<dyn Error>> {
    let (instance, context) = attributed_instance("body-limit-preserved")?;
    let fixture = fixture(instance.default_tenant_id())?;
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let tenant = ValueLimitSet::new(
        maximum.request(),
        RecordLimits::new(
            maximum.record().encoded_bytes(),
            maximum.record().decoded_bytes(),
            ByteLimit::new(4)?,
        ),
        maximum.dynamic_value(),
    );
    let profile = ValueLimitProfileCandidate::new(maximum, Some(tenant)).validate()?;
    let request = AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
        context,
        fixture.authority.governor(),
        bodies_request(&["12345"]).encode_to_vec(),
    )?;
    let batch = OtlpLogsReceiver::with_value_limit_profile(profile).decode(request)?;
    let policy = IngestPolicy::preserving(27)?;
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x68; 16])?,
        CatalogSecret::from_owned(Box::new([0x69; 32]), Box::new([0x6a; 32])),
    )?;
    let shard = positron_domain::routing::VirtualShardId::new(103)?;
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(
            fixture.tenant,
            positron_domain::routing::SignalKind::Logs,
            shard,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x6b; 32])),
    )?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(
        positron_domain::time::UnixNanoseconds::new(600),
    ));
    assert_eq!(
        LogIngest::new(
            &fixture.authority,
            &ledger,
            &clock,
            &policy,
            fixture.tenant,
            shard,
        )
        .accept(batch, StoreBlockIdentity::new([0x6c; 16])?),
        IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded)
    );
    assert!(ledger.snapshot()?.blocks().is_empty());
    Ok(())
}
