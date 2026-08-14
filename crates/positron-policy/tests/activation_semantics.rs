use positron_domain::identity::TenantId;
use positron_domain::routing::SignalKind;
use positron_domain::value::{AttributeNamespace, AttributeValueKind};
use positron_policy::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyPredicate, PolicyReceiver, PolicyRule,
    PolicyTarget,
};

const ACTIVATION_MAGIC: &[u8] = b"PIPACT01";
const POLICY_MAGIC: &[u8] = b"positron-ingest-policy-v1\0";

#[test]
fn catalog_activation_round_trips_every_closed_semantic_variant() {
    let tenant = tenant(11);
    let paths = [
        PolicyAttributePath::new(AttributeNamespace::Stream, "stream")
            .expect("path")
            .key("child")
            .expect("key"),
        PolicyAttributePath::new(AttributeNamespace::Resource, "resource")
            .expect("path")
            .at_occurrence(2)
            .array_index(1)
            .expect("index"),
        PolicyAttributePath::new(AttributeNamespace::InstrumentationScope, "scope").expect("path"),
        PolicyAttributePath::new(AttributeNamespace::Record, "record").expect("path"),
    ];
    let receivers = [
        PolicyReceiver::OtlpGrpc,
        PolicyReceiver::OtlpHttpProtobuf,
        PolicyReceiver::OtlpHttpJson,
        PolicyReceiver::LokiPushJson,
        PolicyReceiver::LokiPushProtobuf,
        PolicyReceiver::LokiOtlpProtobuf,
        PolicyReceiver::LokiOtlpJson,
    ];
    let kinds = [
        AttributeValueKind::Null,
        AttributeValueKind::Boolean,
        AttributeValueKind::SignedInteger,
        AttributeValueKind::FloatingPoint,
        AttributeValueKind::String,
        AttributeValueKind::Bytes,
        AttributeValueKind::Array,
        AttributeValueKind::KeyValueList,
    ];
    let actions = [
        PolicyAction::Accept,
        PolicyAction::Reject,
        PolicyAction::Remove(PolicyTarget::body()),
        PolicyAction::Redact(PolicyTarget::attribute(paths[0].clone())),
        PolicyAction::TruncateBytes(PolicyTarget::body(), 17),
        PolicyAction::TruncateElements(PolicyTarget::attribute(paths[1].clone()), 3),
        PolicyAction::Remove(PolicyTarget::attribute(paths[2].clone())),
        PolicyAction::TruncateElements(PolicyTarget::body(), 2),
    ];
    let mut rules = Vec::new();
    for index in 0..8 {
        let mut predicates = vec![PolicyPredicate::attribute_type(
            paths[index % paths.len()].clone(),
            kinds[index],
        )];
        if let Some(receiver) = receivers.get(index).copied() {
            predicates.push(PolicyPredicate::receiver(receiver));
        }
        predicates.push(PolicyPredicate::signal_store(if index == 0 {
            SignalKind::Traces
        } else {
            SignalKind::Logs
        }));
        if index == 1 {
            predicates.push(PolicyPredicate::attribute_exists(paths[0].clone()));
            predicates.push(PolicyPredicate::body_exact_text("body").expect("predicate"));
            predicates.push(PolicyPredicate::service_identity("checkout").expect("predicate"));
            predicates.push(PolicyPredicate::log_severity(13));
        }
        rules.push(
            PolicyRule::new(format!("rule-{index}"), predicates, actions[index].clone())
                .expect("rule"),
        );
    }
    let policy = IngestPolicy::compile(42, rules).expect("policy");
    let bytes = policy
        .activated_object(tenant)
        .expect("activation")
        .into_bytes();
    let decoded = IngestPolicy::decode_activated_object(tenant, &bytes)
        .expect("valid activation")
        .expect("tenant match");

    assert_eq!(decoded.generation(), 42);
    assert_eq!(decoded.digest(), policy.digest());
    assert_eq!(
        decoded
            .activated_object(tenant)
            .expect("re-encode")
            .into_bytes(),
        bytes
    );
}

#[test]
fn activation_decoder_fails_closed_for_version_tags_lengths_and_trailing_bytes() {
    let tenant = tenant(12);
    assert!(
        IngestPolicy::decode_activated_object(tenant, b"unrelated catalog object")
            .expect("not an activation")
            .is_none()
    );

    let valid = minimal_object(tenant, &[], &[1]);
    for length in [8, 23, 31, 32, 40, valid.len() - 1] {
        assert!(IngestPolicy::decode_activated_object(tenant, &valid[..length]).is_err());
    }
    let mut wrong_version = valid.clone();
    wrong_version[32] ^= 1;
    assert!(IngestPolicy::decode_activated_object(tenant, &wrong_version).is_err());

    for bytes in [
        minimal_object(tenant, &[0], &[1]),
        minimal_object(tenant, &[3, 0], &[1]),
        minimal_object(tenant, &[4, 0], &[1]),
        minimal_object(tenant, &[5, 0], &[1]),
        minimal_object(tenant, &[], &[0]),
        minimal_object(tenant, &[], &[3, 0]),
    ] {
        assert!(IngestPolicy::decode_activated_object(tenant, &bytes).is_err());
    }

    let mut trailing = valid;
    trailing.push(0);
    assert!(IngestPolicy::decode_activated_object(tenant, &trailing).is_err());
}

#[test]
fn provenance_reconstruction_requires_the_exact_activation_and_rule_order() {
    let policy = IngestPolicy::compile(
        7,
        vec![
            PolicyRule::new("first", Vec::new(), PolicyAction::Accept).expect("rule"),
            PolicyRule::new("second", Vec::new(), PolicyAction::Reject).expect("rule"),
        ],
    )
    .expect("policy");
    let ids = vec!["first".to_owned(), "second".to_owned()];
    assert_eq!(
        policy
            .reconstruct_actions(7, policy.digest(), &ids)
            .expect("exact activation")
            .len(),
        2
    );
    assert!(
        policy
            .reconstruct_actions(8, policy.digest(), &ids)
            .is_err()
    );
    assert!(policy.reconstruct_actions(7, [0; 32], &ids).is_err());
    assert!(
        policy
            .reconstruct_actions(7, policy.digest(), &["second".into(), "first".into()])
            .is_err()
    );
    assert!(
        policy
            .reconstruct_actions(7, policy.digest(), &["missing".into()])
            .is_err()
    );
    assert!(
        policy
            .reconstruct_actions(
                7,
                policy.digest(),
                &["first".into(), "first".into(), "first".into()],
            )
            .is_err()
    );
}

fn tenant(byte: u8) -> TenantId {
    TenantId::from_bytes([byte; 16]).expect("tenant")
}

fn minimal_object(tenant: TenantId, predicates: &[u8], action: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ACTIVATION_MAGIC);
    bytes.extend_from_slice(&tenant.to_bytes());
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(POLICY_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.push(b'r');
    bytes.extend_from_slice(&(u16::from(!predicates.is_empty())).to_be_bytes());
    bytes.extend_from_slice(predicates);
    bytes.extend_from_slice(action);
    bytes
}
