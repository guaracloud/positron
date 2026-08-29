use std::{cell::Cell, error::Error};

use crate::log_store::{ScanObservationFailureCode, ScanObserver};
use positron_domain::identity::TenantId;
use positron_domain::value::{
    AttributeNamespace, AttributeValueKind, CandidateAttributeValue, CandidateKeyValue,
};
use positron_kernel::StoreBlockIdentity;

use super::*;

#[test]
fn root_overflows_before_append_when_block_index_ceiling_is_reached() -> Result<(), Box<dyn Error>>
{
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "indexed"))?;

    for sequence in 1_u128..=4_096 {
        let (delta, index) = staged_index(&catalog, tenant, &attribute, sequence)?;
        catalog.apply_delta(delta, index)?;
    }
    let mut excess = super::super::SchemaDelta::empty(tenant, true);
    let observation = catalog.stage_record(
        std::slice::from_ref(&attribute),
        &mut excess,
        &mut super::super::delta::DiscoveryMeter::new(),
    )?;
    assert_eq!(
        observation.representation(&path(AttributeNamespace::Record, "indexed")),
        Some(super::super::SchemaRepresentation::Overflow)
    );
    let (excess, index) = excess.into_block_index(
        StoreBlockIdentity::new(4_097_u128.to_be_bytes())?,
        [0x61; 32],
    );
    assert!(index.is_none(), "overflow must not create a sidecar");
    catalog.apply_delta(excess, index)?;
    assert_eq!(catalog.overflow_record_count(), 1);
    Ok(())
}

fn staged_index(
    catalog: &SchemaCatalog,
    tenant: positron_domain::identity::TenantId,
    attribute: &positron_domain::value::AttributeOccurrenceSet,
    sequence: u128,
) -> Result<
    (
        super::super::SchemaDelta,
        Option<super::super::index::SchemaBlockIndex>,
    ),
    Box<dyn Error>,
> {
    let mut delta = super::super::SchemaDelta::empty(tenant, true);
    catalog.stage_record(
        std::slice::from_ref(attribute),
        &mut delta,
        &mut super::super::delta::DiscoveryMeter::new(),
    )?;
    let identity = StoreBlockIdentity::new(sequence.to_be_bytes())?;
    Ok(delta.into_block_index(identity, [0x61; 32]))
}

#[test]
fn replay_apply_charges_many_block_mutations_at_the_exact_boundary() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "indexed"))?;
    let meter = ReplayMeter::bounded(64);
    for sequence in 1_u128..=65 {
        let (delta, index) = staged_index(&catalog, tenant, &attribute, sequence)?;
        let result = catalog.apply_replay_delta(delta, index, &meter);
        if sequence == 65 {
            assert_eq!(
                result,
                Err(super::super::SchemaFailure::Observed(
                    ScanObservationFailureCode::BudgetExhausted,
                ))
            );
        } else {
            result?;
        }
    }
    assert_eq!(meter.consumed.get(), 65);
    assert_eq!(catalog.replay_clone_work_units()?, 2);
    assert_eq!(catalog.replay_mutation_setup_work_units()?, 2);
    let clone_meter = ReplayMeter::bounded(4);
    let mut clone = catalog.try_clone_observed(&clone_meter)?;
    clone.prepare_replay_mutation_observed(&clone_meter)?;
    assert_eq!(clone_meter.consumed.get(), 4);
    let cancelled = ReplayMeter::bounded(0);
    assert_eq!(
        catalog.try_clone_observed(&cancelled),
        Err(super::super::SchemaFailure::Observed(
            ScanObservationFailureCode::BudgetExhausted,
        ))
    );
    let mut unobserved_clone = catalog.try_clone()?;
    assert_eq!(
        unobserved_clone.prepare_replay_mutation_observed(&cancelled),
        Err(super::super::SchemaFailure::Observed(
            ScanObservationFailureCode::BudgetExhausted,
        ))
    );
    Ok(())
}

#[test]
fn replay_mutation_rejects_framing_upgrade_at_the_persistent_boundary() -> Result<(), Box<dyn Error>>
{
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "indexed"))?;
    let (delta, index) = staged_index(&catalog, tenant, &attribute, 1)?;
    catalog.apply_replay_delta(delta, index, &ReplayMeter::bounded(u64::MAX))?;
    let block = catalog.block_indexes.first_mut().ok_or("replay block")?;
    block.text_summary = Some(super::super::text_index::TextBlockSummary::from_bodies([
        Some("abc"),
    ])?);
    block.text_framing = super::super::index::TextIndexFraming::LegacyV2;
    let budget = catalog.budget();
    catalog.budget = SchemaBudget::new(
        budget.max_entries(),
        budget.max_memory_bytes(),
        catalog.persistent_bytes(),
        catalog.index_bytes(),
    )?;
    let before = (catalog.persistent_bytes(), catalog.index_bytes());
    assert_eq!(
        catalog.prepare_replay_mutation_observed(&ReplayMeter::bounded(u64::MAX)),
        Err(super::super::SchemaFailure::LimitExceeded)
    );
    assert_eq!((catalog.persistent_bytes(), catalog.index_bytes()), before);
    Ok(())
}

#[test]
fn replay_apply_accounts_sorted_block_index_shifts() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "indexed"))?;

    let meter = ReplayMeter::bounded(u64::MAX);
    for sequence in [2_u128, 3] {
        let (delta, index) = staged_index(&catalog, tenant, &attribute, sequence)?;
        catalog.apply_replay_delta(delta, index, &meter)?;
    }
    let before = meter.consumed.get();
    let (delta, index) = staged_index(&catalog, tenant, &attribute, 1)?;
    let limited = ReplayMeter::bounded(2);
    assert_eq!(
        catalog.apply_replay_delta(delta, index, &limited),
        Err(super::super::SchemaFailure::Observed(
            ScanObservationFailureCode::BudgetExhausted,
        ))
    );
    assert!(
        !catalog.has_verified_block(StoreBlockIdentity::new(1_u128.to_be_bytes())?, [0x61; 32])
    );

    let (delta, index) = staged_index(&catalog, tenant, &attribute, 1)?;
    catalog.apply_replay_delta(delta, index, &meter)?;

    assert_eq!(meter.consumed.get(), before + 3);
    Ok(())
}

#[test]
fn replay_reconciliation_capacity_includes_catalog_entry_shifts() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    for index in 0..4_095 {
        let attribute = occurrence(
            AttributeNamespace::Record,
            &format!("key-{index:04}"),
            CandidateAttributeValue::string("value".to_owned()),
        )?;
        catalog.observe(std::slice::from_ref(&attribute))?;
    }

    assert_eq!(
        catalog.replay_reconciliation_work_units(1)?,
        12_298,
        "replay admission must cover a first-path insertion across the catalog"
    );
    Ok(())
}

#[test]
fn replay_reconciliation_capacity_includes_all_staged_entry_shifts() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    for index in 2..4_096 {
        let attribute = occurrence(
            AttributeNamespace::Record,
            &format!("key-{index:04}"),
            CandidateAttributeValue::string("value".to_owned()),
        )?;
        catalog.observe(std::slice::from_ref(&attribute))?;
    }

    assert!(
        catalog.replay_reconciliation_work_units(1)? >= 8_191,
        "one block must admit two first-path staged entries"
    );
    assert!(
        catalog.replay_reconciliation_work_units(2)? >= 16_386,
        "multiple blocks must admit every staged entry shift"
    );
    Ok(())
}

#[test]
fn replay_reconciliation_rejects_an_unbounded_staged_entry_claim() {
    let catalog =
        SchemaCatalog::new(tenant(), SchemaBudget::release_1().expect("budget")).expect("catalog");
    assert_eq!(
        catalog.replay_reconciliation_work_units_with_staged_entries(
            1,
            super::super::model::MAX_DISCOVERY_NODES + 1,
        ),
        Err(super::super::SchemaFailure::LimitExceeded)
    );
}

#[test]
fn replay_delta_work_units_matches_existing_and_new_identity_paths() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "indexed"))?;
    let identity = StoreBlockIdentity::new(1_u128.to_be_bytes())?;
    let (delta, index) = staged_index(&catalog, tenant, &attribute, 1)?;
    let unchanged = delta.try_clone()?;
    assert!(catalog.replay_delta_work_units(&delta, Some(identity))? > 0);
    catalog.apply_replay_delta(delta, index, &ReplayMeter::bounded(u64::MAX))?;
    assert_eq!(
        catalog.replay_delta_work_units(&unchanged, Some(identity))?,
        catalog.replay_delta_work_units(&unchanged, None)?
    );
    Ok(())
}

#[test]
fn replay_apply_accounts_multiple_entry_shifts_atomically() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    for index in 2..4_096 {
        let attribute = occurrence(
            AttributeNamespace::Record,
            &format!("key-{index:04}"),
            CandidateAttributeValue::string("value".to_owned()),
        )?;
        catalog.observe(std::slice::from_ref(&attribute))?;
    }
    let first = occurrence(
        AttributeNamespace::Record,
        "key-0000",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    let second = occurrence(
        AttributeNamespace::Record,
        "key-0001",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    let mut delta = super::super::SchemaDelta::empty(tenant, true);
    catalog.stage_record(
        &[first, second],
        &mut delta,
        &mut super::super::delta::DiscoveryMeter::new(),
    )?;
    let (delta, index) =
        delta.into_block_index(StoreBlockIdentity::new(1_u128.to_be_bytes())?, [0x61; 32]);
    assert!(index.is_none());
    let before = catalog.encode_catalog_object()?;
    let under = ReplayMeter::bounded(8_190);
    assert_eq!(
        catalog.apply_replay_delta(delta.try_clone()?, None, &under),
        Err(super::super::SchemaFailure::Observed(
            ScanObservationFailureCode::BudgetExhausted,
        ))
    );
    assert_eq!(catalog.encode_catalog_object()?, before);

    let exact = ReplayMeter::bounded(8_191);
    catalog.apply_replay_delta(delta, None, &exact)?;
    assert_eq!(exact.consumed.get(), 8_191);
    assert_ne!(catalog.encode_catalog_object()?, before);
    Ok(())
}

#[test]
fn replay_reconcile_observes_before_cloning_stale_indexes() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "indexed"))?;
    let meter = ReplayMeter::bounded(u64::MAX);
    for sequence in 1_u128..=65 {
        let (delta, index) = staged_index(&catalog, tenant, &attribute, sequence)?;
        catalog.apply_replay_delta(delta, index, &meter)?;
    }
    let before = catalog.encode_catalog_object()?;
    let identity = StoreBlockIdentity::new(1_u128.to_be_bytes())?;
    let result =
        catalog.reconcile_block_identity_observed(identity, [0x62; 32], &ReplayMeter::bounded(0));
    assert_eq!(
        result,
        Err(super::super::SchemaFailure::Observed(
            ScanObservationFailureCode::BudgetExhausted,
        ))
    );
    assert_eq!(catalog.encode_catalog_object()?, before);

    let result = catalog.reconcile_block_identity_observed(
        identity,
        [0x62; 32],
        &ReplayMeter::bounded(65 + 65 * 2 + 64 * 7 + 1),
    );
    assert!(result.is_ok());
    assert!(!catalog.has_verified_block(identity, [0x61; 32]));
    Ok(())
}

#[test]
fn observed_replay_noops_and_retains_only_admitted_indexes() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "indexed"))?;
    let (delta, index) = staged_index(&catalog, tenant, &attribute, 1)?;
    catalog.apply_replay_delta(delta, index, &ReplayMeter::bounded(u64::MAX))?;
    let (delta, index) = staged_index(&catalog, tenant, &attribute, 2)?;
    catalog.apply_replay_delta(delta, index, &ReplayMeter::bounded(u64::MAX))?;
    let identity = StoreBlockIdentity::new(1_u128.to_be_bytes())?;
    let second_identity = StoreBlockIdentity::new(2_u128.to_be_bytes())?;
    let digest = [0x61; 32];

    let meter = ReplayMeter::bounded(0);
    catalog.reconcile_block_identity_observed(identity, digest, &meter)?;
    catalog.reconcile_block_identity_observed(
        StoreBlockIdentity::new(3_u128.to_be_bytes())?,
        [0x62; 32],
        &meter,
    )?;
    assert_eq!(meter.consumed.get(), 0);

    assert_eq!(
        catalog.retain_reachable_indexes_observed(&[], &ReplayMeter::bounded(0)),
        Err(super::super::SchemaFailure::Observed(
            ScanObservationFailureCode::BudgetExhausted,
        ))
    );
    catalog.retain_reachable_indexes_observed(
        &[(identity, digest)],
        &ReplayMeter::bounded(u64::MAX),
    )?;
    assert!(catalog.has_verified_block(identity, digest));
    assert!(!catalog.has_verified_block(second_identity, digest));
    Ok(())
}

#[test]
fn replay_apply_rejects_cross_tenant_and_invalid_or_duplicate_indexes() -> Result<(), Box<dyn Error>>
{
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "indexed"))?;
    let meter = ReplayMeter::bounded(u64::MAX);

    let (wrong_tenant_delta, _) =
        staged_index(&catalog, TenantId::from_bytes([0x72; 16])?, &attribute, 1)?;
    assert_eq!(
        catalog.apply_replay_delta(wrong_tenant_delta, None, &meter),
        Err(super::super::SchemaFailure::InvalidValue)
    );

    let (delta, index) = staged_index(&catalog, tenant, &attribute, 2)?;
    catalog.apply_replay_delta(delta, index, &meter)?;
    let (duplicate_delta, duplicate) = staged_index(&catalog, tenant, &attribute, 2)?;
    assert_eq!(
        catalog.apply_replay_delta(duplicate_delta, duplicate, &meter),
        Ok(())
    );

    let (invalid_delta, _) = staged_index(&catalog, tenant, &attribute, 3)?;
    let invalid_index = super::super::index::SchemaBlockIndex::one(
        StoreBlockIdentity::new(3_u128.to_be_bytes())?,
        [0x61; 32],
        super::super::index::SchemaIndexPath {
            path: path(AttributeNamespace::Record, "not-indexed"),
            kind_mask: 1,
            values: Vec::new(),
        },
    )?;
    assert_eq!(
        catalog.apply_replay_delta(invalid_delta, Some(invalid_index), &meter),
        Err(super::super::SchemaFailure::InvalidValue)
    );
    Ok(())
}

#[test]
fn ordinary_apply_rejects_capacity_budget_and_conflicting_identity() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let source_budget = SchemaBudget::new(2, 512, 512, 256)?;
    let source = SchemaCatalog::new(tenant, source_budget)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "new",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    let mut delta = super::super::SchemaDelta::empty(tenant, true);
    source.stage_record(
        std::slice::from_ref(&attribute),
        &mut delta,
        &mut super::super::delta::DiscoveryMeter::new(),
    )?;

    let mut full = SchemaCatalog::new(tenant, SchemaBudget::new(1, 512, 512, 256)?)?;
    let existing = occurrence(
        AttributeNamespace::Record,
        "existing",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    full.observe(std::slice::from_ref(&existing))?;
    assert_eq!(
        full.apply_replay_delta(delta.try_clone()?, None, &ReplayMeter::bounded(u64::MAX)),
        Err(super::super::SchemaFailure::AllocationUnavailable)
    );

    let mut tight = SchemaCatalog::new(tenant, SchemaBudget::new(2, 512, 82, 256)?)?;
    assert_eq!(
        tight.apply_replay_delta(delta.try_clone()?, None, &ReplayMeter::bounded(u64::MAX)),
        Err(super::super::SchemaFailure::LimitExceeded)
    );

    let mut indexed = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    indexed.observe(std::slice::from_ref(&attribute))?;
    indexed.record_query_use(&path(AttributeNamespace::Record, "new"))?;
    let (delta, index) = staged_index(&indexed, tenant, &attribute, 1)?;
    indexed.apply_delta(delta, index)?;
    let (delta, mut conflicting) = staged_index(&indexed, tenant, &attribute, 1)?;
    conflicting.as_mut().ok_or("conflicting index")?.digest = [0x62; 32];
    assert_eq!(
        indexed.apply_replay_delta(delta, conflicting, &ReplayMeter::bounded(u64::MAX)),
        Err(super::super::SchemaFailure::InvalidValue)
    );
    Ok(())
}

struct ReplayMeter {
    consumed: Cell<u64>,
    limit: u64,
}

impl ReplayMeter {
    const fn bounded(limit: u64) -> Self {
        Self {
            consumed: Cell::new(0),
            limit,
        }
    }
}

impl ScanObserver for ReplayMeter {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let consumed = self.consumed.get().saturating_add(units);
        self.consumed.set(consumed);
        if consumed > self.limit {
            Err(ScanObservationFailureCode::BudgetExhausted)
        } else {
            Ok(())
        }
    }
}

#[test]
fn query_indexes_merge_idempotently_and_reconcile_reachability() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::new(8, 32_768, 32_768, 8_192)?)?;
    for key in ["alpha", "beta"] {
        catalog.observe(&[occurrence(
            AttributeNamespace::Record,
            key,
            CandidateAttributeValue::string(key.to_owned()),
        )?])?;
        catalog.record_query_use(&path(AttributeNamespace::Record, key))?;
    }
    catalog.record_query_use(&path(AttributeNamespace::Record, "alpha"))?;
    assert_eq!(
        catalog
            .entry(&path(AttributeNamespace::Record, "alpha"))
            .ok_or("alpha")?
            .query_uses(),
        2
    );
    assert_eq!(
        catalog.record_query_use(&path(AttributeNamespace::Record, "missing")),
        Err(super::super::SchemaFailure::InvalidPath)
    );

    let first = StoreBlockIdentity::new(1_u128.to_be_bytes())?;
    let second = StoreBlockIdentity::new(2_u128.to_be_bytes())?;
    let digest = [0x62; 32];
    let forged = super::super::index::SchemaBlockIndex::one(
        StoreBlockIdentity::new(9_u128.to_be_bytes())?,
        digest,
        super::super::index::SchemaIndexPath {
            path: path(AttributeNamespace::Record, "missing"),
            kind_mask: 1,
            values: Vec::new(),
        },
    )?;
    assert_eq!(
        catalog.install_query_index(forged),
        Err(super::super::SchemaFailure::InvalidValue)
    );
    catalog.install_query_index(index_for(&catalog, first, digest, "alpha")?)?;
    catalog.install_query_index(index_for(&catalog, first, digest, "alpha")?)?;
    catalog.install_query_index(index_for(&catalog, first, digest, "beta")?)?;
    catalog.install_query_index(index_for(&catalog, first, digest, "beta")?)?;
    assert_eq!(
        catalog.install_query_index(index_for(&catalog, first, [0x63; 32], "alpha")?),
        Err(super::super::SchemaFailure::InvalidValue)
    );
    catalog.install_query_index(index_for(&catalog, second, digest, "alpha")?)?;

    let before = catalog.index_bytes();
    catalog.reconcile_block_identity(first, digest)?;
    assert_eq!(catalog.index_bytes(), before);
    catalog.retain_reachable_indexes(&[(first, digest)])?;
    assert!(catalog.has_verified_block(first, digest));
    assert!(!catalog.has_verified_block(second, digest));
    catalog.reconcile_block_identity(first, [0x64; 32])?;
    assert!(!catalog.has_verified_block(first, digest));
    Ok(())
}

#[test]
fn demotion_removes_only_its_paths_and_sidecar_budget_is_exact() -> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(8, 32_768, 32_768, 8_192)?)?;
    for key in ["alpha", "beta"] {
        catalog.observe(&[occurrence(
            AttributeNamespace::Record,
            key,
            CandidateAttributeValue::signed_integer(7),
        )?])?;
        catalog.record_query_use(&path(AttributeNamespace::Record, key))?;
    }
    let identity = StoreBlockIdentity::new(3_u128.to_be_bytes())?;
    let digest = [0x65; 32];
    catalog.install_query_index(index_for(&catalog, identity, digest, "alpha")?)?;
    catalog.install_query_index(index_for(&catalog, identity, digest, "beta")?)?;

    catalog.remove_query_evidence(&path(AttributeNamespace::Record, "alpha"))?;
    assert!(
        !catalog
            .entry(&path(AttributeNamespace::Record, "alpha"))
            .ok_or("alpha")?
            .promoted()
    );
    assert!(catalog.has_verified_block(identity, digest));
    catalog.remove_query_evidence(&path(AttributeNamespace::Record, "beta"))?;
    assert!(!catalog.has_verified_block(identity, digest));
    catalog.remove_query_evidence(&path(AttributeNamespace::Record, "beta"))?;

    let mut tight = SchemaCatalog::new(tenant(), SchemaBudget::new(2, 8_192, 8_192, 3)?)?;
    tight.observe(&[occurrence(
        AttributeNamespace::Record,
        "tight",
        CandidateAttributeValue::signed_integer(1),
    )?])?;
    tight.record_query_use(&path(AttributeNamespace::Record, "tight"))?;
    assert_eq!(
        tight.install_query_index(index_for(&tight, identity, digest, "tight")?),
        Err(super::super::SchemaFailure::LimitExceeded)
    );
    Ok(())
}

#[test]
fn composite_kinds_always_fall_back_while_scalar_kinds_remain_prunable()
-> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let scalar = occurrence(
        AttributeNamespace::Record,
        "mixed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    let composite = occurrence(
        AttributeNamespace::Record,
        "mixed",
        CandidateAttributeValue::array(vec![CandidateAttributeValue::boolean(true)]),
    )?;
    catalog.observe(std::slice::from_ref(&scalar))?;
    catalog.observe(std::slice::from_ref(&composite))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "mixed"))?;

    let identity = StoreBlockIdentity::new(5_u128.to_be_bytes())?;
    let digest = [0x61; 32];
    let (delta, index) = staged_index(&catalog, tenant, &scalar, 5)?;
    catalog.apply_delta(delta, index)?;

    let indexed_path = path(AttributeNamespace::Record, "mixed");
    assert_eq!(
        catalog.verified_block_kind(
            identity,
            digest,
            &indexed_path,
            positron_domain::value::AttributeValueKind::String,
        ),
        Some(true)
    );
    assert_eq!(
        catalog.verified_block_kind(
            identity,
            digest,
            &indexed_path,
            positron_domain::value::AttributeValueKind::Boolean,
        ),
        Some(false)
    );
    for kind in [
        positron_domain::value::AttributeValueKind::Array,
        positron_domain::value::AttributeValueKind::KeyValueList,
    ] {
        assert_eq!(
            catalog.verified_block_kind(identity, digest, &indexed_path, kind),
            None
        );
    }
    Ok(())
}

#[test]
fn nested_index_evidence_falls_back_at_the_value_ceiling() -> Result<(), Box<dyn Error>> {
    let indexed_path = path(AttributeNamespace::Record, "nested.child");
    let variants = [AttributeValueKind::SignedInteger];
    let sets = (0..=super::super::index::MAX_INDEX_VALUES)
        .map(|value| {
            occurrence(
                AttributeNamespace::Record,
                "nested",
                CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                    "child".to_owned(),
                    CandidateAttributeValue::signed_integer(
                        i64::try_from(value).expect("test value fits signed integer"),
                    ),
                )]),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fallback = super::super::index::SchemaIndexPath::from_variants_and_attributes(
        &indexed_path,
        &variants,
        &sets.iter().collect::<Vec<_>>(),
    )?;
    assert!(fallback.values.is_empty());

    let scalar = occurrence(
        AttributeNamespace::Record,
        "nested",
        CandidateAttributeValue::string("not-a-list".to_owned()),
    )?;
    let scalar_fallback = super::super::index::SchemaIndexPath::from_variants_and_attributes(
        &indexed_path,
        &variants,
        &[&scalar],
    )?;
    assert!(scalar_fallback.values.is_empty());

    let complete = occurrence(
        AttributeNamespace::Record,
        "nested",
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "child".to_owned(),
            CandidateAttributeValue::signed_integer(7),
        )]),
    )?;
    let complete_index = super::super::index::SchemaIndexPath::from_variants_and_attributes(
        &indexed_path,
        &variants,
        &[&complete],
    )?;
    assert_eq!(complete_index.values, vec![SchemaValue::signed_integer(7)]);
    assert!(complete_index.encoded_bytes()? > 0);

    assert_eq!(
        super::super::index::SchemaIndexPath::from_variants_and_values(
            &indexed_path,
            &variants,
            &[SchemaValue::kind(AttributeValueKind::String)],
        ),
        Err(super::super::SchemaFailure::InvalidValue)
    );
    let too_many = (0..=super::super::index::MAX_INDEX_VALUES)
        .map(|value| SchemaValue::signed_integer(i64::try_from(value).expect("bounded value")))
        .collect::<Vec<_>>();
    assert_eq!(
        super::super::index::SchemaIndexPath::from_variants_and_values(
            &indexed_path,
            &variants,
            &too_many,
        ),
        Err(super::super::SchemaFailure::LimitExceeded)
    );
    Ok(())
}

fn index_for(
    catalog: &SchemaCatalog,
    identity: StoreBlockIdentity,
    digest: [u8; 32],
    key: &str,
) -> Result<super::super::index::SchemaBlockIndex, Box<dyn Error>> {
    let path = path(AttributeNamespace::Record, key);
    let variants = catalog.entry(&path).ok_or("entry")?.variants();
    let indexed = super::super::index::SchemaIndexPath::from_variants(&path, variants)?;
    Ok(super::super::index::SchemaBlockIndex::one(
        identity, digest, indexed,
    )?)
}
