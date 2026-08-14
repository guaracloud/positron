use sha2::{Digest, Sha256};

use super::{
    PolicyAction, PolicyAttributePath, PolicyCompileFailure, PolicyOccurrence, PolicyPathSegment,
    PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
};

pub(crate) const MAGIC: &[u8] = b"positron-ingest-policy-v1\0";

pub(super) fn digest_encoded(encoded: &[u8]) -> [u8; 32] {
    Sha256::digest(encoded).into()
}

pub(crate) fn encode(rules: &[PolicyRule]) -> Result<Vec<u8>, PolicyCompileFailure> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    push_u16(&mut bytes, rules.len())?;
    for rule in rules {
        push_text(&mut bytes, &rule.id)?;
        push_u16(&mut bytes, rule.predicates.len())?;
        for predicate in &rule.predicates {
            encode_predicate(&mut bytes, predicate)?;
        }
        encode_action(&mut bytes, &rule.action)?;
    }
    Ok(bytes)
}

fn encode_predicate(
    bytes: &mut Vec<u8>,
    predicate: &PolicyPredicate,
) -> Result<(), PolicyCompileFailure> {
    match predicate {
        PolicyPredicate::AttributeExists(path) => {
            bytes.push(1);
            encode_path(bytes, path)?;
        },
        PolicyPredicate::BodyExactText(value) => {
            bytes.push(2);
            push_text(bytes, value)?;
        },
        PolicyPredicate::SignalStore(signal) => bytes.extend_from_slice(&[
            3,
            match signal {
                positron_domain::routing::SignalKind::Logs => 1,
                positron_domain::routing::SignalKind::Traces => 2,
            },
        ]),
        PolicyPredicate::Receiver(receiver) => {
            bytes.extend_from_slice(&[4, receiver_tag(*receiver)]);
        },
        PolicyPredicate::AttributeType(path, kind) => {
            bytes.push(5);
            encode_path(bytes, path)?;
            bytes.push(match kind {
                positron_domain::value::AttributeValueKind::Null => 1,
                positron_domain::value::AttributeValueKind::Boolean => 2,
                positron_domain::value::AttributeValueKind::SignedInteger => 3,
                positron_domain::value::AttributeValueKind::FloatingPoint => 4,
                positron_domain::value::AttributeValueKind::String => 5,
                positron_domain::value::AttributeValueKind::Bytes => 6,
                positron_domain::value::AttributeValueKind::Array => 7,
                positron_domain::value::AttributeValueKind::KeyValueList => 8,
            });
        },
        PolicyPredicate::ServiceIdentity(value) => {
            bytes.push(6);
            push_text(bytes, value)?;
        },
        PolicyPredicate::LogSeverity(value) => {
            bytes.push(7);
            bytes.extend_from_slice(&value.to_be_bytes());
        },
    }
    Ok(())
}

fn encode_action(bytes: &mut Vec<u8>, action: &PolicyAction) -> Result<(), PolicyCompileFailure> {
    match action {
        PolicyAction::Accept => bytes.push(1),
        PolicyAction::Reject => bytes.push(2),
        PolicyAction::Remove(target) => {
            bytes.push(3);
            encode_target(bytes, target)?;
        },
        PolicyAction::Redact(target) => {
            bytes.push(4);
            encode_target(bytes, target)?;
        },
        PolicyAction::TruncateBytes(target, limit) => {
            bytes.push(5);
            encode_target(bytes, target)?;
            bytes.extend_from_slice(&limit.to_be_bytes());
        },
        PolicyAction::TruncateElements(target, limit) => {
            bytes.push(6);
            encode_target(bytes, target)?;
            bytes.extend_from_slice(&limit.to_be_bytes());
        },
    }
    Ok(())
}

fn encode_target(bytes: &mut Vec<u8>, target: &PolicyTarget) -> Result<(), PolicyCompileFailure> {
    match target {
        PolicyTarget::Body => bytes.push(1),
        PolicyTarget::Attribute(path) => {
            bytes.push(2);
            encode_path(bytes, path)?;
        },
    }
    Ok(())
}

fn encode_path(
    bytes: &mut Vec<u8>,
    path: &PolicyAttributePath,
) -> Result<(), PolicyCompileFailure> {
    bytes.push(match path.namespace {
        positron_domain::value::AttributeNamespace::Stream => 1,
        positron_domain::value::AttributeNamespace::Resource => 2,
        positron_domain::value::AttributeNamespace::InstrumentationScope => 3,
        positron_domain::value::AttributeNamespace::Record => 4,
    });
    push_text(bytes, &path.key)?;
    match path.occurrence {
        PolicyOccurrence::All => bytes.push(0),
        PolicyOccurrence::Index(index) => {
            bytes.push(1);
            bytes.extend_from_slice(&index.to_be_bytes());
        },
    }
    push_u16(bytes, path.segments.len())?;
    for segment in &path.segments {
        match segment {
            PolicyPathSegment::Key(key) => {
                bytes.push(1);
                push_text(bytes, key)?;
            },
            PolicyPathSegment::ArrayIndex(index) => {
                bytes.push(2);
                bytes.extend_from_slice(&index.to_be_bytes());
            },
        }
    }
    Ok(())
}

fn receiver_tag(receiver: PolicyReceiver) -> u8 {
    match receiver {
        PolicyReceiver::OtlpGrpc => 1,
        PolicyReceiver::OtlpHttpProtobuf => 2,
        PolicyReceiver::OtlpHttpJson => 3,
        PolicyReceiver::LokiPushJson => 4,
        PolicyReceiver::LokiPushProtobuf => 5,
        PolicyReceiver::LokiOtlpProtobuf => 6,
        PolicyReceiver::LokiOtlpJson => 7,
    }
}

fn push_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), PolicyCompileFailure> {
    let length =
        u32::try_from(value.len()).map_err(|_| PolicyCompileFailure::PolicyBytesExceeded)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_u16(bytes: &mut Vec<u8>, value: usize) -> Result<(), PolicyCompileFailure> {
    let value = u16::try_from(value).map_err(|_| PolicyCompileFailure::PolicyBytesExceeded)?;
    bytes.extend_from_slice(&value.to_be_bytes());
    Ok(())
}
