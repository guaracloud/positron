#![no_main]

use libfuzzer_sys::fuzz_target;
use positron_domain::identity::TenantId;
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, AttributeValueKind,
    CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};
use positron_signals::{
    LogRecord, OccurrenceSelector, SchemaBudget, SchemaCatalog, SchemaPath, SchemaQuery,
    SchemaValue, TenantSchemaState,
};
use positron_kernel::StoreBlockIdentity;

const MAX_INPUT_BYTES: usize = 4_096;
const MAX_ATTRIBUTES: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }
    let entry_budget = usize::from(data[0] % 8) + 1;
    let index_budget = usize::from(data.get(1).copied().unwrap_or(1))
        .saturating_mul(16)
        .saturating_add(128);
    let Ok(budget) = SchemaBudget::new(entry_budget, 16_384, 16_384, index_budget) else {
        return;
    };
    let Ok(tenant) = TenantId::from_bytes([0x63; 16]) else {
        return;
    };
    let Ok(mut state) = TenantSchemaState::new(tenant, budget) else {
        return;
    };
    let profile = ValueLimitProfile::release_1_system_maximum();
    let mut attributes = Vec::new();
    let mut native_attributes = Vec::new();
    if attributes.try_reserve_exact(MAX_ATTRIBUTES).is_err() {
        return;
    }
    for (ordinal, chunk) in data[1..].chunks(4).take(MAX_ATTRIBUTES).enumerate() {
        let discriminator = chunk.first().copied().unwrap_or_default();
        let key = format!("k{ordinal:02x}");
        let value = match discriminator % 5 {
            0 => CandidateAttributeValue::signed_integer(i64::from(discriminator)),
            1 => CandidateAttributeValue::string(format!("v{discriminator:02x}")),
            2 => CandidateAttributeValue::boolean(discriminator & 1 == 1),
            3 => CandidateAttributeValue::bytes(chunk.to_vec()),
            _ => CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new(
                    "child".to_owned(),
                    CandidateAttributeValue::signed_integer(i64::from(discriminator)),
                ),
                CandidateKeyValue::new(
                    "child".to_owned(),
                    CandidateAttributeValue::signed_integer(i64::from(discriminator) + 1),
                ),
            ]),
        };
        native_attributes.push(NativeLogAttribute::new(
            AttributeNamespace::Record,
            key.clone(),
            vec![value.clone()],
        ));
        let candidate = AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            key,
            vec![value],
        );
        if let Ok(attribute) = candidate.clone().validate(profile) {
            attributes.push(attribute);
        }
    }
    let candidate = NativeLogCandidate::new(
        None,
        None,
        None,
        native_attributes,
        LogMetadata::empty(),
    );
    let Ok(policy) = IngestPolicy::preserving(1) else {
        return;
    };
    let Ok(PolicyEvaluation::Accepted(evaluated)) =
        policy.evaluate(candidate, PolicyReceiver::OtlpGrpc)
    else {
        return;
    };
    let Ok(record) = LogRecord::checked_evaluated(profile, *evaluated) else {
        return;
    };
    let mut records = vec![record];
    let Ok(delta) = state.stage_group(&mut records) else {
        return;
    };
    let Ok(identity) = StoreBlockIdentity::new([0x65; 16]) else {
        return;
    };
    if state.commit(delta, identity, [0x66; 32]).is_err() {
        return;
    }
    let Ok(observation) = state.observe(&attributes) else {
        return;
    };
    for (ordinal, attribute) in attributes.iter().enumerate() {
        let root = format!("k{ordinal:02x}");
        let nested = attribute
            .occurrence(0)
            .is_some_and(|value| value.kind() == AttributeValueKind::KeyValueList);
        let source = if nested { format!("{root}.child") } else { root };
        let Ok(path) = SchemaPath::new(AttributeNamespace::Record, source) else {
            continue;
        };
        for selector in [
            OccurrenceSelector::Index(0),
            OccurrenceSelector::Index(1),
            OccurrenceSelector::Any,
            OccurrenceSelector::All,
        ] {
            let query = SchemaQuery::value(
                path.clone(),
                selector,
                SchemaValue::kind(if nested {
                    AttributeValueKind::SignedInteger
                } else {
                    attribute
                        .occurrence(0)
                        .map_or(AttributeValueKind::Null, |value| value.kind())
                }),
            );
            let _ = state.catalog().query(&observation, &query);
        }
    }
    if let Ok(encoded) = state.catalog().encode_catalog_object() {
        let _ = SchemaCatalog::decode_catalog_object(&encoded);
    }
});
