use positron_domain::identity::TenantId;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_kernel::ResourceDimension;
use positron_policy::IngestPolicy;
use positron_policy::{NativeLogAttribute, NativeLogCandidate, PolicyEvaluation, PolicyReceiver};
use positron_signals::{LogRecord, LogStore, SchemaBudget};

use super::{
    SchemaAdmissionEstimate, group_work_amounts, schema_admission_estimate,
    schema_discovery_cpu_work_units, schema_stage_ceiling_bytes,
};

mod admission_boundary;

fn schema(memory: u64) -> SchemaAdmissionEstimate {
    SchemaAdmissionEstimate {
        staging_memory_bytes: memory,
        retained_memory_bytes: memory,
        discovery_nodes: 1,
    }
}

#[test]
fn group_capacity_includes_schema_memory_before_policy() {
    let policy = IngestPolicy::preserving(1).expect("policy");
    let amount = group_work_amounts(2, policy.budget(), schema(4_096)).expect("amount");
    let policy_memory = policy
        .budget()
        .reserved_memory_bytes()
        .expect("bounded memory");
    assert_eq!(
        amount.get(ResourceDimension::MemoryBytes),
        1_048_576 + 2 * policy_memory + 4_096
    );
}

#[test]
fn cumulative_discovery_work_is_reserved_at_the_exact_boundary() {
    let policy = IngestPolicy::preserving(1).expect("policy");
    let amount = group_work_amounts(2, policy.budget(), schema(1)).expect("amount");
    assert_eq!(amount.get(ResourceDimension::CpuWorkUnits), 1);
    assert_eq!(schema_discovery_cpu_work_units(1), Some(1));
    assert_eq!(
        positron_signals::SchemaBudget::system_max_discovery_nodes(),
        4_096
    );
}

#[test]
fn discovery_cpu_uses_actual_bounded_candidate_nodes() {
    let maximum = SchemaBudget::system_max_discovery_nodes();
    for (nodes, expected_nodes, expected_quanta) in [
        (1, 1, 1),
        (64, 64, 1),
        (65, 65, 2),
        (maximum, maximum, 64),
        (maximum + 1, maximum, 64),
    ] {
        let candidate = candidate_with_occurrences(nodes);
        let estimate =
            schema_admission_estimate(std::slice::from_ref(&candidate)).expect("bounded estimate");
        assert_eq!(
            estimate.discovery_nodes(),
            u64::try_from(expected_nodes).expect("nodes")
        );
        assert_eq!(
            schema_discovery_cpu_work_units(estimate.discovery_nodes()),
            Some(expected_quanta),
            "node count {nodes}"
        );
    }
}

#[test]
fn staging_ceiling_is_derived_from_catalog_and_delta_slot_maxima() {
    let expected = positron_signals::SchemaBudget::system_max_memory_bytes()
        + positron_signals::SchemaBudget::system_max_entries()
            * std::mem::size_of::<positron_signals::SchemaEntry>()
        + std::mem::size_of::<Vec<positron_signals::SchemaEntry>>();
    assert_eq!(schema_stage_ceiling_bytes(), u64::try_from(expected).ok());
    assert_eq!(positron_signals::SchemaPath::system_max_segments(), 128);
}

#[test]
fn checked_schema_accounting_overflow_fails_closed() {
    let policy = IngestPolicy::preserving(1).expect("policy");
    assert!(group_work_amounts(1, policy.budget(), schema(u64::MAX)).is_none());
    assert!(group_work_amounts(u64::MAX, policy.budget(), schema(1)).is_none());
}

#[test]
fn valid_loki_stream_attribute_fits_the_conservative_schema_estimate() {
    let candidate = NativeLogCandidate::new(
        Some(42),
        None,
        Some(CandidateAttributeValue::string("loki-shared".to_owned())),
        vec![NativeLogAttribute::new(
            AttributeNamespace::Stream,
            "app".to_owned(),
            vec![CandidateAttributeValue::string("shared".to_owned())],
        )],
        crate::LogMetadata::new(
            0,
            String::new(),
            None,
            None,
            0,
            0,
            0,
            String::new(),
            String::new(),
            String::new(),
            0,
            String::new(),
        ),
    );
    let estimate = schema_admission_estimate(std::slice::from_ref(&candidate)).expect("estimate");
    let policy = IngestPolicy::preserving(1).expect("policy");
    let PolicyEvaluation::Accepted(evaluated) = policy
        .evaluate(candidate, PolicyReceiver::LokiPushJson)
        .expect("evaluation")
    else {
        panic!("preserving policy rejected valid Loki record");
    };
    let mut records = vec![
        LogRecord::checked_evaluated(LogStore::value_limit_profile(), *evaluated)
            .expect("valid record"),
    ];
    let catalog = positron_signals::TenantSchemaState::new(
        TenantId::from_bytes([0xb1; 16]).expect("tenant"),
        SchemaBudget::release_1().expect("budget"),
    )
    .expect("catalog");
    let delta = catalog.stage_group(&mut records).expect("schema stage");
    assert!(
        u64::try_from(delta.staged_memory_bytes()).expect("staged bytes")
            <= estimate.staging_memory_bytes(),
        "staged actual={} allowed={}",
        delta.staged_memory_bytes(),
        estimate.staging_memory_bytes()
    );
    assert!(
        u64::try_from(delta.retained_memory_bytes()).expect("retained bytes")
            <= estimate.retained_memory_bytes(),
        "retained actual={} allowed={}",
        delta.retained_memory_bytes(),
        estimate.retained_memory_bytes()
    );
}

fn candidate_with_occurrences(nodes: usize) -> NativeLogCandidate {
    NativeLogCandidate::new(
        Some(42),
        None,
        None,
        vec![NativeLogAttribute::new(
            AttributeNamespace::Record,
            "node".to_owned(),
            vec![CandidateAttributeValue::Boolean(true); nodes],
        )],
        crate::LogMetadata::new(
            0,
            String::new(),
            None,
            None,
            0,
            0,
            0,
            String::new(),
            String::new(),
            String::new(),
            0,
            String::new(),
        ),
    )
}
