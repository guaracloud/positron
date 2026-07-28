//! Public contract tests for the foundational Domain Types seam.

use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use positron_domain::{
    identity::{PrincipalId, Scope, TenantAttribution, TenantId, TenantSlug},
    lifecycle::{TenantLifecycle, TenantLifecycleState},
    outcome::{CompletionState, DomainFailure, DomainFailureCode, FailureSource, RetryClass},
    routing::{AssignmentEpoch, CommitPosition, SignalKind, VirtualShardId},
    time::{
        EventTime, IngestTimeCandidate, ObservedTime, QueryTime, QueryTimeProvenance,
        SourceTimeQuality, UnixNanoseconds,
    },
    value::{
        AttributeNamespace, AttributeOccurrenceSetCandidate, AttributeValueKind, ByteLimit,
        CandidateAttributeValue, CandidateKeyValue, CollectionLimit, NestingLimit,
        ValueLimitProfileCandidate, ValueLimitSet,
    },
};

#[test]
fn tenant_identity_uses_canonical_text_and_rejects_a_sentinel() -> Result<(), DomainFailure> {
    let tenant = TenantId::from_bytes([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
        0xfe,
    ])?;

    assert_eq!(
        tenant.to_canonical_text(),
        "01234567-89ab-cdef-1032-547698badcfe"
    );
    assert_eq!(
        TenantId::parse_canonical(&tenant.to_canonical_text())?,
        tenant
    );
    assert!(matches!(
        TenantId::from_bytes([0; 16]),
        Err(failure) if failure.code() == DomainFailureCode::InvalidIdentifier
    ));
    assert!(matches!(
        TenantId::parse_canonical("01234567-89AB-cdef-1032-547698badcfe"),
        Err(failure) if failure.code() == DomainFailureCode::InvalidIdentifier
    ));

    Ok(())
}

#[test]
fn canonical_identity_byte_views_and_tenant_display_are_lossless() -> Result<(), DomainFailure> {
    let tenant_bytes = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
        0xfe,
    ];
    let principal_bytes = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
        0x01,
    ];
    let tenant = TenantId::from_bytes(tenant_bytes)?;
    let principal = PrincipalId::from_bytes(principal_bytes)?;

    assert_eq!(tenant.to_bytes(), tenant_bytes);
    assert_eq!(tenant.to_string(), "01234567-89ab-cdef-1032-547698badcfe");
    assert_eq!(principal.to_bytes(), principal_bytes);

    Ok(())
}

#[test]
fn tenant_identifier_canonical_text_round_trips_retained_adversarial_seeds()
-> Result<(), DomainFailure> {
    let seeds = [
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe,
        ],
        [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ],
    ];

    for seed in seeds {
        let identifier = TenantId::from_bytes(seed)?;
        assert_eq!(
            TenantId::parse_canonical(&identifier.to_canonical_text())?,
            identifier
        );
    }

    Ok(())
}

#[test]
fn tenant_identifier_rejects_noncanonical_length_and_separator_shape() {
    assert!(matches!(
        TenantId::parse_canonical("01234567-89ab"),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidIdentifier
                && failure.source() == FailureSource::TenantId
    ));
    assert!(matches!(
        TenantId::parse_canonical("01234567_89ab-cdef-1032-547698badcfe"),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidIdentifier
                && failure.source() == FailureSource::TenantId
    ));
}

#[test]
fn tenant_identity_rejection_has_a_closed_typed_outcome() {
    let result = TenantId::from_bytes([0; 16]);

    assert!(matches!(
        result,
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidIdentifier
                && failure.retry_class() == RetryClass::AfterInputCorrection
                && failure.completion_state() == CompletionState::Rejected
                && failure.source() == FailureSource::TenantId
    ));
}

#[test]
fn reachable_domain_failures_render_as_bounded_safe_diagnostics() -> Result<(), DomainFailure> {
    fn is_bounded_diagnostic(failure: DomainFailure) -> bool {
        let diagnostic = failure.to_string();
        !diagnostic.is_empty() && diagnostic.len() <= 96
    }

    let tenant = TenantId::from_bytes([1; 16])?;
    let principal = PrincipalId::from_bytes([2; 16])?;
    let system_limits = ValueLimitSet::new(
        ByteLimit::new(16)?,
        ByteLimit::new(16)?,
        CollectionLimit::new(1)?,
        NestingLimit::new(1)?,
    );
    let raised_tenant_limits = ValueLimitSet::new(
        ByteLimit::new(17)?,
        ByteLimit::new(16)?,
        CollectionLimit::new(1)?,
        NestingLimit::new(1)?,
    );
    let valid_profile = ValueLimitProfileCandidate::new(system_limits, None).validate()?;

    assert!(TenantId::from_bytes([0; 16]).is_err_and(is_bounded_diagnostic));
    assert!(
        TenantAttribution::new(principal, Scope::SystemAdministration, tenant)
            .is_err_and(is_bounded_diagnostic)
    );
    assert!(
        TenantLifecycle::active()
            .complete_purge()
            .is_err_and(is_bounded_diagnostic)
    );
    assert!(
        EventTime::received(UnixNanoseconds::new(1), SourceTimeQuality::Missing)
            .is_err_and(is_bounded_diagnostic)
    );
    assert!(
        AssignmentEpoch::initial()
            .advance_by(NonZeroU64::MAX)?
            .next()
            .is_err_and(is_bounded_diagnostic)
    );
    assert!(
        ValueLimitProfileCandidate::new(system_limits, Some(raised_tenant_limits))
            .validate()
            .is_err_and(is_bounded_diagnostic)
    );
    assert!(ByteLimit::new(0).is_err_and(is_bounded_diagnostic));
    assert!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "status".to_owned(),
            vec![],
        )
        .validate(valid_profile)
        .is_err_and(is_bounded_diagnostic)
    );

    Ok(())
}

#[test]
fn tenant_slug_has_one_bounded_canonical_form() -> Result<(), DomainFailure> {
    let slug = TenantSlug::parse_canonical("production-logs")?;

    assert_eq!(slug.as_str(), "production-logs");
    assert!(matches!(
        TenantSlug::parse_canonical("Production-Logs"),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidIdentifier
                && failure.source() == FailureSource::TenantSlug
    ));
    assert!(matches!(
        TenantSlug::parse_canonical("-production"),
        Err(failure) if failure.code() == DomainFailureCode::InvalidIdentifier
    ));
    assert!(matches!(
        TenantSlug::parse_canonical("production-"),
        Err(failure) if failure.code() == DomainFailureCode::InvalidIdentifier
    ));

    Ok(())
}

#[test]
fn tenant_slug_requires_between_one_and_sixty_three_ascii_bytes() -> Result<(), DomainFailure> {
    assert_eq!(TenantSlug::parse_canonical("a")?.as_str(), "a");
    let maximum = "a".repeat(63);
    assert_eq!(
        TenantSlug::parse_canonical(&maximum)?.as_str(),
        maximum,
        "the configured maximum is inclusive"
    );
    assert!(matches!(
        TenantSlug::parse_canonical(""),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidIdentifier
                && failure.source() == FailureSource::TenantSlug
    ));
    assert!(matches!(
        TenantSlug::parse_canonical(&"a".repeat(64)),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidIdentifier
                && failure.source() == FailureSource::TenantSlug
    ));

    Ok(())
}

#[test]
fn tenant_slug_rejects_an_oversized_input_before_scanning_its_characters() {
    let oversized = "a".repeat(16 * 1_024 * 1_024);
    let started = Instant::now();

    let result = TenantSlug::parse_canonical(&oversized);

    assert!(matches!(
        result,
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidIdentifier
                && failure.source() == FailureSource::TenantSlug
    ));
    assert!(
        started.elapsed() < Duration::from_millis(1),
        "an input above the byte limit must be rejected before character scanning"
    );
}

#[test]
fn tenant_slug_preserves_canonical_ascii_digits() -> Result<(), DomainFailure> {
    let slug = TenantSlug::parse_canonical("region-1")?;

    assert_eq!(slug.as_str(), "region-1");

    Ok(())
}

#[test]
fn principal_identity_is_a_distinct_canonical_domain_value() -> Result<(), DomainFailure> {
    let principal = PrincipalId::from_bytes([
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
        0x01,
    ])?;

    assert_eq!(
        principal.to_canonical_text(),
        "fedcba98-7654-3210-efcd-ab8967452301"
    );
    assert_eq!(
        PrincipalId::parse_canonical(&principal.to_canonical_text())?,
        principal
    );
    assert!(matches!(
        PrincipalId::from_bytes([0; 16]),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidIdentifier
                && failure.source() == FailureSource::PrincipalId
    ));

    Ok(())
}

#[test]
fn tenant_attribution_rejects_system_administrator_data_plane_impersonation()
-> Result<(), DomainFailure> {
    let tenant = TenantId::from_bytes([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
        0xfe,
    ])?;
    let principal = PrincipalId::from_bytes([
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
        0x01,
    ])?;
    let attribution = TenantAttribution::new(principal, Scope::Ingest, tenant)?;

    assert_eq!(attribution.tenant_id(), tenant);
    assert_eq!(attribution.principal_id(), principal);
    assert_eq!(attribution.scope(), Scope::Ingest);
    assert!(matches!(
        TenantAttribution::new(principal, Scope::SystemAdministration, tenant),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidAttribution
                && failure.retry_class() == RetryClass::Never
                && failure.source() == FailureSource::TenantAttribution
    ));

    Ok(())
}

#[test]
fn tenant_lifecycle_makes_purge_one_way() -> Result<(), DomainFailure> {
    let read_only = TenantLifecycle::active().to_read_only()?;
    let suspended = read_only.to_suspended()?;
    let purging = suspended.begin_purge()?;

    assert!(matches!(
        purging.to_active(),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidLifecycleTransition
                && failure.source() == FailureSource::TenantLifecycle
    ));

    let purged = purging.complete_purge()?;
    assert_eq!(read_only.state(), TenantLifecycleState::ReadOnly);
    assert_eq!(suspended.state(), TenantLifecycleState::Suspended);
    assert_eq!(purged.state(), TenantLifecycleState::Purged);
    assert!(matches!(
        purged.to_read_only(),
        Err(failure) if failure.code() == DomainFailureCode::InvalidLifecycleTransition
    ));

    Ok(())
}

#[test]
fn log_query_time_preserves_source_values_and_exposes_fallback_provenance()
-> Result<(), DomainFailure> {
    let event = EventTime::received(UnixNanoseconds::new(100), SourceTimeQuality::Usable)?;
    let observed = ObservedTime::received(UnixNanoseconds::new(200), SourceTimeQuality::Usable)?;
    let ingest = IngestTimeCandidate::new(UnixNanoseconds::new(300));

    let direct = QueryTime::for_log(&event, Some(&observed), ingest);
    assert_eq!(direct.instant(), UnixNanoseconds::new(100));
    assert_eq!(direct.provenance(), QueryTimeProvenance::Event);

    let unusable_event = EventTime::received(UnixNanoseconds::new(0), SourceTimeQuality::Zero)?;
    let observed_fallback = QueryTime::for_log(&unusable_event, Some(&observed), ingest);
    assert_eq!(observed_fallback.instant(), UnixNanoseconds::new(200));
    assert_eq!(
        observed_fallback.provenance(),
        QueryTimeProvenance::Observed
    );
    assert_eq!(unusable_event.instant(), Some(UnixNanoseconds::new(0)));
    assert_eq!(unusable_event.quality(), SourceTimeQuality::Zero);

    let ingest_fallback = QueryTime::for_log(&unusable_event, None, ingest);
    assert_eq!(ingest_fallback.instant(), UnixNanoseconds::new(300));
    assert_eq!(ingest_fallback.provenance(), QueryTimeProvenance::Ingest);

    Ok(())
}

#[test]
fn observed_time_retains_its_exact_value_when_log_selection_uses_it() -> Result<(), DomainFailure> {
    let observed = ObservedTime::received(UnixNanoseconds::new(200), SourceTimeQuality::Usable)?;
    let selected = QueryTime::for_log(
        &EventTime::missing(),
        Some(&observed),
        IngestTimeCandidate::new(UnixNanoseconds::new(300)),
    );

    assert_eq!(observed.instant(), Some(UnixNanoseconds::new(200)));
    assert_eq!(observed.quality(), SourceTimeQuality::Usable);
    assert_eq!(selected.instant(), UnixNanoseconds::new(200));
    assert_eq!(selected.provenance(), QueryTimeProvenance::Observed);

    Ok(())
}

#[test]
fn unusable_observed_time_cannot_replace_log_ingest_time() -> Result<(), DomainFailure> {
    let observed = ObservedTime::received(UnixNanoseconds::new(0), SourceTimeQuality::Zero)?;
    let selected = QueryTime::for_log(
        &EventTime::missing(),
        Some(&observed),
        IngestTimeCandidate::new(UnixNanoseconds::new(300)),
    );

    assert_eq!(observed.instant(), Some(UnixNanoseconds::new(0)));
    assert_eq!(observed.quality(), SourceTimeQuality::Zero);
    assert_eq!(selected.instant(), UnixNanoseconds::new(300));
    assert_eq!(selected.provenance(), QueryTimeProvenance::Ingest);

    Ok(())
}

#[test]
fn present_source_time_cannot_claim_to_be_missing() {
    assert!(matches!(
        EventTime::received(UnixNanoseconds::new(100), SourceTimeQuality::Missing),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidTimeAnnotation
                && failure.source() == FailureSource::SourceTime
    ));
}

#[test]
fn zero_source_time_quality_requires_the_exact_zero_instant() {
    assert!(matches!(
        EventTime::received(UnixNanoseconds::new(1), SourceTimeQuality::Zero),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidTimeAnnotation
                && failure.source() == FailureSource::SourceTime
    ));
}

#[test]
fn zero_source_time_accepts_only_the_non_usable_zero_annotation() {
    for result in [
        EventTime::received(UnixNanoseconds::new(0), SourceTimeQuality::Usable).map(|_| ()),
        ObservedTime::received(UnixNanoseconds::new(0), SourceTimeQuality::Usable).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(failure)
                if failure.code() == DomainFailureCode::InvalidTimeAnnotation
                    && failure.source() == FailureSource::SourceTime
        ));
    }
}

#[test]
fn missing_event_time_has_no_fabricated_instant() {
    let missing = EventTime::missing();

    assert_eq!(missing.instant(), None);
    assert_eq!(missing.quality(), SourceTimeQuality::Missing);
}

#[test]
fn span_query_time_uses_start_time_or_ingest_time_only() -> Result<(), DomainFailure> {
    let start = EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable)?;
    let ingest = IngestTimeCandidate::new(UnixNanoseconds::new(20));

    let direct = QueryTime::for_span(&start, ingest);
    assert_eq!(direct.instant(), UnixNanoseconds::new(10));
    assert_eq!(direct.provenance(), QueryTimeProvenance::Event);

    let fallback = QueryTime::for_span(&EventTime::missing(), ingest);
    assert_eq!(fallback.instant(), UnixNanoseconds::new(20));
    assert_eq!(fallback.provenance(), QueryTimeProvenance::Ingest);

    Ok(())
}

#[test]
fn source_time_quality_keeps_outliers_queryable_without_using_contradictions()
-> Result<(), DomainFailure> {
    let ingest = IngestTimeCandidate::new(UnixNanoseconds::new(20));
    let outlier = EventTime::received(UnixNanoseconds::new(i64::MAX), SourceTimeQuality::Outlier)?;
    let contradictory =
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Contradictory)?;

    let outlier_query_time = QueryTime::for_span(&outlier, ingest);
    assert_eq!(outlier_query_time.instant(), UnixNanoseconds::new(i64::MAX));
    assert_eq!(outlier_query_time.provenance(), QueryTimeProvenance::Event);
    assert_eq!(contradictory.instant(), Some(UnixNanoseconds::new(10)));
    assert_eq!(contradictory.quality(), SourceTimeQuality::Contradictory);
    assert_eq!(
        QueryTime::for_span(&contradictory, ingest).provenance(),
        QueryTimeProvenance::Ingest
    );

    Ok(())
}

#[test]
fn virtual_shard_identity_rejects_the_zero_sentinel() -> Result<(), DomainFailure> {
    assert_eq!(VirtualShardId::new(1)?.value(), 1);
    assert!(matches!(
        VirtualShardId::new(0),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidIdentifier
                && failure.source() == FailureSource::VirtualShard
    ));

    Ok(())
}

#[test]
fn assignment_epoch_progression_is_checked_without_wraparound() -> Result<(), DomainFailure> {
    let epoch = AssignmentEpoch::initial().advance_by(NonZeroU64::MAX)?;

    assert!(matches!(
        epoch.next(),
        Err(failure)
            if failure.code() == DomainFailureCode::ArithmeticOverflow
                && failure.retry_class() == RetryClass::Never
                && failure.source() == FailureSource::AssignmentEpoch
    ));

    Ok(())
}

#[test]
fn assignment_epoch_preserves_successful_monotonic_progression() -> Result<(), DomainFailure> {
    let first = AssignmentEpoch::initial();
    let second = first.next()?;

    assert_eq!(second.value(), 1);

    Ok(())
}

#[test]
fn commit_position_advances_without_wrapping_into_timestamp_like_order() -> Result<(), DomainFailure>
{
    let origin = CommitPosition::origin();
    let maximum = origin.advance_by(NonZeroU64::MAX)?;

    assert_eq!(origin.value(), 0);
    assert!(matches!(origin.next(), Ok(position) if position.value() == 1));
    assert!(matches!(
        maximum.next(),
        Err(failure)
            if failure.code() == DomainFailureCode::ArithmeticOverflow
                && failure.source() == FailureSource::CommitPosition
    ));

    Ok(())
}

#[test]
fn attribute_namespaces_remain_distinct() {
    assert_eq!(AttributeNamespace::Resource.as_str(), "resource");
    assert_eq!(
        AttributeNamespace::InstrumentationScope.as_str(),
        "instrumentation-scope"
    );
    assert_eq!(AttributeNamespace::Record.as_str(), "record");
}

#[test]
fn typed_value_limits_reject_the_zero_sentinel() {
    assert!(matches!(
        ByteLimit::new(0),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidLimit
                && failure.source() == FailureSource::ValueLimit
    ));
    assert!(matches!(
        CollectionLimit::new(0),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidLimit
                && failure.source() == FailureSource::ValueLimit
    ));
    assert!(matches!(
        NestingLimit::new(0),
        Err(failure)
            if failure.code() == DomainFailureCode::InvalidLimit
                && failure.source() == FailureSource::ValueLimit
    ));
}

#[test]
fn value_limit_profile_validation_allows_equality_and_tenant_lowering() -> Result<(), DomainFailure>
{
    let system = ValueLimitSet::new(
        ByteLimit::new(32)?,
        ByteLimit::new(64)?,
        CollectionLimit::new(4)?,
        NestingLimit::new(2)?,
    );
    let lowered_tenant = ValueLimitSet::new(
        ByteLimit::new(16)?,
        ByteLimit::new(32)?,
        CollectionLimit::new(2)?,
        NestingLimit::new(1)?,
    );

    let profile = ValueLimitProfileCandidate::new(system, Some(lowered_tenant)).validate()?;
    assert_eq!(profile.system_limits(), system);
    assert_eq!(profile.tenant_limits(), Some(lowered_tenant));

    let equal_profile = ValueLimitProfileCandidate::new(system, Some(system)).validate()?;
    assert_eq!(
        equal_profile.tenant_limits().map(ValueLimitSet::key_bytes),
        Some(system.key_bytes()),
        "tenant key bytes may equal the configured system maximum"
    );
    assert_eq!(
        equal_profile
            .tenant_limits()
            .map(ValueLimitSet::value_bytes),
        Some(system.value_bytes()),
        "tenant value bytes may equal the configured system maximum"
    );
    assert_eq!(
        equal_profile
            .tenant_limits()
            .map(ValueLimitSet::collection_entries),
        Some(system.collection_entries()),
        "tenant collection entries may equal the configured system maximum"
    );
    assert_eq!(
        equal_profile
            .tenant_limits()
            .map(ValueLimitSet::nesting_depth),
        Some(system.nesting_depth()),
        "tenant nesting depth may equal the configured system maximum"
    );

    let raised_tenant = ValueLimitSet::new(
        ByteLimit::new(33)?,
        ByteLimit::new(32)?,
        CollectionLimit::new(2)?,
        NestingLimit::new(1)?,
    );
    assert!(matches!(
        ValueLimitProfileCandidate::new(system, Some(raised_tenant)).validate(),
        Err(failure)
            if failure.code() == DomainFailureCode::LimitExceedsSystem
                && failure.source() == FailureSource::ValueLimitProfile
    ));

    Ok(())
}

#[test]
fn tenant_limit_profile_rejects_an_increase_in_each_independent_dimension()
-> Result<(), DomainFailure> {
    let system = ValueLimitSet::new(
        ByteLimit::new(16)?,
        ByteLimit::new(32)?,
        CollectionLimit::new(4)?,
        NestingLimit::new(2)?,
    );
    let raised_value_bytes = ValueLimitSet::new(
        ByteLimit::new(16)?,
        ByteLimit::new(33)?,
        CollectionLimit::new(4)?,
        NestingLimit::new(2)?,
    );
    let raised_collection_entries = ValueLimitSet::new(
        ByteLimit::new(16)?,
        ByteLimit::new(32)?,
        CollectionLimit::new(5)?,
        NestingLimit::new(2)?,
    );
    let raised_nesting_depth = ValueLimitSet::new(
        ByteLimit::new(16)?,
        ByteLimit::new(32)?,
        CollectionLimit::new(4)?,
        NestingLimit::new(3)?,
    );

    for tenant in [
        raised_value_bytes,
        raised_collection_entries,
        raised_nesting_depth,
    ] {
        assert!(matches!(
            ValueLimitProfileCandidate::new(system, Some(tenant)).validate(),
            Err(failure)
                if failure.code() == DomainFailureCode::LimitExceedsSystem
                    && failure.source() == FailureSource::ValueLimitProfile
        ));
    }

    Ok(())
}

#[test]
fn validated_profile_applies_tenant_lowered_limits_as_effective_limits() -> Result<(), DomainFailure>
{
    let system = ValueLimitSet::new(
        ByteLimit::new(32)?,
        ByteLimit::new(64)?,
        CollectionLimit::new(4)?,
        NestingLimit::new(2)?,
    );
    let tenant = ValueLimitSet::new(
        ByteLimit::new(16)?,
        ByteLimit::new(32)?,
        CollectionLimit::new(2)?,
        NestingLimit::new(1)?,
    );
    let effective = ValueLimitProfileCandidate::new(system, Some(tenant))
        .validate()?
        .effective_limits();

    assert_eq!(effective, tenant);

    Ok(())
}

#[test]
fn validated_attribute_occurrences_preserve_order_and_typed_variants() -> Result<(), DomainFailure>
{
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(2)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;
    let occurrences = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "status".to_owned(),
        vec![
            CandidateAttributeValue::signed_integer(42),
            CandidateAttributeValue::string("42".to_owned()),
        ],
    )
    .validate(profile)?;

    assert_eq!(occurrences.namespace(), AttributeNamespace::Record);
    assert_eq!(occurrences.key(), "status");
    assert_eq!(occurrences.len(), 2);
    assert_eq!(
        occurrences.occurrence(0).map(|value| value.kind()),
        Some(AttributeValueKind::SignedInteger)
    );
    assert_eq!(
        occurrences
            .occurrence(0)
            .and_then(|value| value.as_signed_integer()),
        Some(42)
    );
    assert_eq!(
        occurrences.occurrence(1).map(|value| value.kind()),
        Some(AttributeValueKind::String)
    );
    assert_eq!(
        occurrences.occurrence(1).and_then(|value| value.as_str()),
        Some("42")
    );

    Ok(())
}

#[test]
fn validated_attribute_occurrence_sets_are_never_empty() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;
    let occurrences = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "status".to_owned(),
        vec![CandidateAttributeValue::null()],
    )
    .validate(profile)?;

    assert!(!occurrences.is_empty());
    assert!(occurrences.occurrence(1).is_none());

    Ok(())
}

#[test]
fn empty_attribute_occurrence_sets_are_rejected() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;

    assert!(matches!(
        AttributeOccurrenceSetCandidate::new(AttributeNamespace::Record, "status".to_owned(), vec![])
            .validate(profile),
        Err(failure)
            if failure.code() == DomainFailureCode::ValueLimitExceeded
                && failure.source() == FailureSource::AttributeValue
    ));

    Ok(())
}

#[test]
fn attribute_occurrence_keys_cannot_exceed_the_profile_byte_limit() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(4)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;

    assert!(matches!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "bytes".to_owned(),
            vec![CandidateAttributeValue::null()],
        )
        .validate(profile),
        Err(failure)
            if failure.code() == DomainFailureCode::ValueLimitExceeded
                && failure.source() == FailureSource::AttributeValue
    ));

    Ok(())
}

#[test]
fn attribute_occurrence_count_cannot_exceed_the_profile_limit() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;

    assert!(matches!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "status".to_owned(),
            vec![CandidateAttributeValue::null(), CandidateAttributeValue::null()],
        )
        .validate(profile),
        Err(failure)
            if failure.code() == DomainFailureCode::ValueLimitExceeded
                && failure.source() == FailureSource::AttributeValue
    ));

    Ok(())
}

#[test]
fn validated_attribute_values_preserve_non_string_scalar_kinds() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(3)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;
    let occurrences = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "kind".to_owned(),
        vec![
            CandidateAttributeValue::null(),
            CandidateAttributeValue::boolean(true),
            CandidateAttributeValue::floating_point_bits(0x7ff8_0000_0000_0001),
        ],
    )
    .validate(profile)?;

    assert_eq!(
        occurrences.occurrence(0).map(|value| value.kind()),
        Some(AttributeValueKind::Null)
    );
    assert!(
        occurrences
            .occurrence(0)
            .is_some_and(|value| value.is_null())
    );
    assert_eq!(
        occurrences
            .occurrence(1)
            .and_then(|value| value.as_boolean()),
        Some(true)
    );
    assert_eq!(
        occurrences
            .occurrence(2)
            .and_then(|value| value.as_floating_point_bits()),
        Some(0x7ff8_0000_0000_0001)
    );

    Ok(())
}

#[test]
fn validated_attribute_values_preserve_every_declared_kind() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(8)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;
    let occurrences = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "kind".to_owned(),
        vec![
            CandidateAttributeValue::null(),
            CandidateAttributeValue::boolean(true),
            CandidateAttributeValue::signed_integer(7),
            CandidateAttributeValue::floating_point_bits(0x3ff0_0000_0000_0000),
            CandidateAttributeValue::string("seven".to_owned()),
            CandidateAttributeValue::bytes(vec![7]),
            CandidateAttributeValue::array(vec![CandidateAttributeValue::null()]),
            CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                "value".to_owned(),
                CandidateAttributeValue::null(),
            )]),
        ],
    )
    .validate(profile)?;

    assert_eq!(
        occurrences.occurrence(0).map(|value| value.kind()),
        Some(AttributeValueKind::Null)
    );
    assert_eq!(
        occurrences.occurrence(1).map(|value| value.kind()),
        Some(AttributeValueKind::Boolean)
    );
    assert_eq!(
        occurrences.occurrence(2).map(|value| value.kind()),
        Some(AttributeValueKind::SignedInteger)
    );
    assert_eq!(
        occurrences.occurrence(3).map(|value| value.kind()),
        Some(AttributeValueKind::FloatingPoint)
    );
    assert_eq!(
        occurrences.occurrence(4).map(|value| value.kind()),
        Some(AttributeValueKind::String)
    );
    assert_eq!(
        occurrences.occurrence(5).map(|value| value.kind()),
        Some(AttributeValueKind::Bytes)
    );
    assert_eq!(
        occurrences.occurrence(6).map(|value| value.kind()),
        Some(AttributeValueKind::Array)
    );
    assert_eq!(
        occurrences.occurrence(7).map(|value| value.kind()),
        Some(AttributeValueKind::KeyValueList)
    );

    Ok(())
}

#[test]
fn typed_value_accessors_never_coerce_across_dynamic_value_kinds() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(7)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;
    let occurrences = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "kind".to_owned(),
        vec![
            CandidateAttributeValue::boolean(true),
            CandidateAttributeValue::signed_integer(7),
            CandidateAttributeValue::string("seven".to_owned()),
            CandidateAttributeValue::bytes(vec![7]),
            CandidateAttributeValue::array(vec![CandidateAttributeValue::null()]),
            CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                "value".to_owned(),
                CandidateAttributeValue::null(),
            )]),
            CandidateAttributeValue::null(),
        ],
    )
    .validate(profile)?;

    assert_eq!(
        occurrences
            .occurrence(0)
            .and_then(|value| value.as_signed_integer()),
        None
    );
    assert_eq!(
        occurrences
            .occurrence(1)
            .and_then(|value| value.as_boolean()),
        None
    );
    assert_eq!(
        occurrences
            .occurrence(2)
            .and_then(|value| value.as_floating_point_bits()),
        None
    );
    assert_eq!(
        occurrences.occurrence(6).and_then(|value| value.as_str()),
        None
    );
    assert_eq!(
        occurrences.occurrence(2).and_then(|value| value.as_bytes()),
        None
    );
    assert_eq!(
        occurrences
            .occurrence(3)
            .and_then(|value| value.array_len()),
        None
    );
    assert_eq!(
        occurrences
            .occurrence(4)
            .and_then(|value| value.key_value_list_len()),
        None
    );
    assert!(
        occurrences
            .occurrence(4)
            .and_then(|value| value.key_value_entry(0))
            .is_none()
    );

    Ok(())
}

#[test]
fn bytes_attribute_value_is_bounded_without_silent_truncation() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(2)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;

    let accepted = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "blob".to_owned(),
        vec![CandidateAttributeValue::bytes(vec![0, 1])],
    )
    .validate(profile)?;
    assert_eq!(
        accepted.occurrence(0).and_then(|value| value.as_bytes()),
        Some(&[0, 1][..])
    );

    assert!(matches!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "blob".to_owned(),
            vec![CandidateAttributeValue::bytes(vec![0, 1, 2])],
        )
        .validate(profile),
        Err(failure)
            if failure.code() == DomainFailureCode::ValueLimitExceeded
                && failure.source() == FailureSource::AttributeValue
    ));

    Ok(())
}

#[test]
fn string_attribute_value_is_bounded_without_silent_truncation() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(2)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;

    assert!(matches!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "label".to_owned(),
            vec![CandidateAttributeValue::string("abc".to_owned())],
        )
        .validate(profile),
        Err(failure)
            if failure.code() == DomainFailureCode::ValueLimitExceeded
                && failure.source() == FailureSource::AttributeValue
    ));

    Ok(())
}

#[test]
fn nested_attribute_arrays_stop_at_the_profile_depth() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;
    let accepted = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "nested".to_owned(),
        vec![CandidateAttributeValue::array(vec![
            CandidateAttributeValue::signed_integer(7),
        ])],
    )
    .validate(profile)?;
    assert_eq!(
        accepted.occurrence(0).and_then(|value| value.array_len()),
        Some(1)
    );

    let over_deep = CandidateAttributeValue::array(vec![CandidateAttributeValue::array(vec![
        CandidateAttributeValue::signed_integer(7),
    ])]);
    assert!(matches!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "nested".to_owned(),
            vec![over_deep],
        )
        .validate(profile),
        Err(failure)
            if failure.code() == DomainFailureCode::ValueLimitExceeded
                && failure.source() == FailureSource::AttributeValue
    ));

    Ok(())
}

#[test]
fn attribute_arrays_reject_more_entries_than_the_profile_allows() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;

    assert!(matches!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "array".to_owned(),
            vec![CandidateAttributeValue::array(vec![
                CandidateAttributeValue::signed_integer(1),
                CandidateAttributeValue::signed_integer(2),
            ])],
        )
        .validate(profile),
        Err(failure)
            if failure.code() == DomainFailureCode::ValueLimitExceeded
                && failure.source() == FailureSource::AttributeValue
    ));

    Ok(())
}

#[test]
fn key_value_list_preserves_ordered_typed_entries() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(2)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;
    let list = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "metadata".to_owned(),
        vec![CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new(
                "first".to_owned(),
                CandidateAttributeValue::signed_integer(1),
            ),
            CandidateKeyValue::new(
                "first".to_owned(),
                CandidateAttributeValue::string("one".to_owned()),
            ),
        ])],
    )
    .validate(profile)?;

    let value = list.occurrence(0).ok_or_else(|| {
        std::io::Error::other("a validated non-empty candidate did not retain its first occurrence")
    })?;
    assert_eq!(value.key_value_list_len(), Some(2));
    assert_eq!(
        value.key_value_entry(0).map(|entry| entry.key()),
        Some("first")
    );
    assert_eq!(
        value.key_value_entry(1).map(|entry| entry.value().kind()),
        Some(AttributeValueKind::String)
    );

    Ok(())
}

#[test]
fn key_value_lists_reject_more_entries_than_the_profile_allows() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;

    assert!(matches!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "metadata".to_owned(),
            vec![CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new("first".to_owned(), CandidateAttributeValue::signed_integer(1)),
                CandidateKeyValue::new("second".to_owned(), CandidateAttributeValue::signed_integer(2)),
            ])],
        )
        .validate(profile),
        Err(failure)
            if failure.code() == DomainFailureCode::ValueLimitExceeded
                && failure.source() == FailureSource::AttributeValue
    ));

    Ok(())
}

#[test]
fn key_value_lists_reject_empty_entry_keys() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;

    assert!(matches!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "metadata".to_owned(),
            vec![CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                String::new(),
                CandidateAttributeValue::signed_integer(1),
            )])],
        )
        .validate(profile),
        Err(failure)
            if failure.code() == DomainFailureCode::ValueLimitExceeded
                && failure.source() == FailureSource::AttributeValue
    ));

    Ok(())
}

#[test]
fn nested_key_value_lists_stop_at_the_profile_depth() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(16)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;
    let nested = CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
        "outer".to_owned(),
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "inner".to_owned(),
            CandidateAttributeValue::null(),
        )]),
    )]);

    assert!(matches!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "metadata".to_owned(),
            vec![nested],
        )
        .validate(profile),
        Err(failure)
            if failure.code() == DomainFailureCode::ValueLimitExceeded
                && failure.source() == FailureSource::AttributeValue
    ));

    Ok(())
}

#[test]
fn key_value_entry_keys_cannot_exceed_the_profile_byte_limit() -> Result<(), DomainFailure> {
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            ByteLimit::new(4)?,
            ByteLimit::new(16)?,
            CollectionLimit::new(1)?,
            NestingLimit::new(1)?,
        ),
        None,
    )
    .validate()?;

    assert!(matches!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "meta".to_owned(),
            vec![CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                "bytes".to_owned(),
                CandidateAttributeValue::null(),
            )])],
        )
        .validate(profile),
        Err(failure)
            if failure.code() == DomainFailureCode::ValueLimitExceeded
                && failure.source() == FailureSource::AttributeValue
    ));

    Ok(())
}

#[test]
fn signal_kind_is_closed_to_release_one_logs_and_traces() {
    assert_eq!(SignalKind::Logs.as_str(), "logs");
    assert_eq!(SignalKind::Traces.as_str(), "traces");
}
