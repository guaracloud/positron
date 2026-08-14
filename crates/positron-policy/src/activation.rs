use positron_domain::identity::TenantId;
use positron_domain::routing::SignalKind;
use positron_domain::value::{AttributeNamespace, AttributeValueKind};

use crate::policy::{MAX_COMPILED_POLICY_BYTES, PolicyOccurrence};
use crate::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyPredicate, PolicyReceiver, PolicyRule,
    PolicyTarget,
};

const ACTIVATION_MAGIC: &[u8; 8] = b"PIPACT01";
const ACTIVATION_HEADER_BYTES: usize = 8 + 16 + 8;
pub const MAX_ACTIVATED_POLICY_OBJECT_BYTES: usize = 1_048_576;

/// Opaque, validated Catalog object bytes for one tenant policy activation.
pub struct ActivatedPolicyObject {
    object: Vec<u8>,
}

impl ActivatedPolicyObject {
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.object
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyActivationFailure;

impl std::fmt::Display for PolicyActivationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Ingest Policy activation is invalid")
    }
}

impl std::error::Error for PolicyActivationFailure {}

impl IngestPolicy {
    pub fn reconstruct_actions<'policy, 'ids>(
        &'policy self,
        generation: u64,
        digest: [u8; 32],
        applied_rule_ids: &'ids [String],
    ) -> Result<Vec<(&'ids str, &'policy PolicyAction)>, PolicyActivationFailure> {
        if generation != self.generation
            || digest != self.digest
            || applied_rule_ids.len() > self.rules.len()
        {
            return Err(PolicyActivationFailure);
        }
        let mut actions = Vec::new();
        actions
            .try_reserve_exact(applied_rule_ids.len())
            .map_err(|_| PolicyActivationFailure)?;
        let mut rule_offset = 0_usize;
        for id in applied_rule_ids {
            let relative = self
                .rules
                .get(rule_offset..)
                .ok_or(PolicyActivationFailure)?
                .iter()
                .position(|rule| rule.id == *id)
                .ok_or(PolicyActivationFailure)?;
            let index = rule_offset
                .checked_add(relative)
                .ok_or(PolicyActivationFailure)?;
            let rule = self.rules.get(index).ok_or(PolicyActivationFailure)?;
            actions.push((id.as_str(), &rule.action));
            rule_offset = index.checked_add(1).ok_or(PolicyActivationFailure)?;
        }
        Ok(actions)
    }

    pub fn activated_object(
        &self,
        tenant: TenantId,
    ) -> Result<ActivatedPolicyObject, PolicyActivationFailure> {
        let definition =
            super::policy::canonical::encode(&self.rules).map_err(|_| PolicyActivationFailure)?;
        let capacity = ACTIVATION_HEADER_BYTES
            .checked_add(definition.len())
            .filter(|bytes| *bytes <= MAX_ACTIVATED_POLICY_OBJECT_BYTES)
            .ok_or(PolicyActivationFailure)?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(ACTIVATION_MAGIC);
        bytes.extend_from_slice(&tenant.to_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&definition);
        Ok(ActivatedPolicyObject { object: bytes })
    }

    pub fn decode_activated_object(
        tenant: TenantId,
        bytes: &[u8],
    ) -> Result<Option<Self>, PolicyActivationFailure> {
        if !bytes.starts_with(ACTIVATION_MAGIC) {
            return Ok(None);
        }
        let mut input = Input::new(bytes);
        input.expect(ACTIVATION_MAGIC)?;
        if input.take(16)? != tenant.to_bytes() {
            return Ok(None);
        }
        let generation = input.u64()?;
        input.expect(super::policy::canonical::MAGIC)?;
        let count = usize::from(input.u16()?);
        let mut rules = Vec::new();
        rules
            .try_reserve_exact(count)
            .map_err(|_| PolicyActivationFailure)?;
        for _ in 0..count {
            rules.push(decode_rule(&mut input)?);
        }
        if !input.is_empty() {
            return Err(PolicyActivationFailure);
        }
        IngestPolicy::compile(generation, rules)
            .map(Some)
            .map_err(|_| PolicyActivationFailure)
    }
}

fn decode_rule(input: &mut Input<'_>) -> Result<PolicyRule, PolicyActivationFailure> {
    let id = input.text()?;
    let count = usize::from(input.u16()?);
    let mut predicates = Vec::new();
    predicates
        .try_reserve_exact(count)
        .map_err(|_| PolicyActivationFailure)?;
    for _ in 0..count {
        predicates.push(decode_predicate(input)?);
    }
    PolicyRule::new(id, predicates, decode_action(input)?).map_err(|_| PolicyActivationFailure)
}

fn decode_predicate(input: &mut Input<'_>) -> Result<PolicyPredicate, PolicyActivationFailure> {
    Ok(match input.u8()? {
        1 => PolicyPredicate::attribute_exists(decode_path(input)?),
        2 => {
            PolicyPredicate::body_exact_text(input.text()?).map_err(|_| PolicyActivationFailure)?
        },
        3 => PolicyPredicate::signal_store(match input.u8()? {
            1 => SignalKind::Logs,
            2 => SignalKind::Traces,
            _ => return Err(PolicyActivationFailure),
        }),
        4 => PolicyPredicate::receiver(decode_receiver(input.u8()?)?),
        5 => PolicyPredicate::attribute_type(decode_path(input)?, decode_kind(input.u8()?)?),
        6 => {
            PolicyPredicate::service_identity(input.text()?).map_err(|_| PolicyActivationFailure)?
        },
        7 => PolicyPredicate::log_severity(input.i32()?),
        _ => return Err(PolicyActivationFailure),
    })
}

fn decode_action(input: &mut Input<'_>) -> Result<PolicyAction, PolicyActivationFailure> {
    Ok(match input.u8()? {
        1 => PolicyAction::Accept,
        2 => PolicyAction::Reject,
        3 => PolicyAction::Remove(decode_target(input)?),
        4 => PolicyAction::Redact(decode_target(input)?),
        5 => PolicyAction::TruncateBytes(decode_target(input)?, input.u32()?),
        6 => PolicyAction::TruncateElements(decode_target(input)?, input.u16()?),
        _ => return Err(PolicyActivationFailure),
    })
}

fn decode_target(input: &mut Input<'_>) -> Result<PolicyTarget, PolicyActivationFailure> {
    match input.u8()? {
        1 => Ok(PolicyTarget::body()),
        2 => Ok(PolicyTarget::attribute(decode_path(input)?)),
        _ => Err(PolicyActivationFailure),
    }
}

fn decode_path(input: &mut Input<'_>) -> Result<PolicyAttributePath, PolicyActivationFailure> {
    let namespace = match input.u8()? {
        1 => AttributeNamespace::Stream,
        2 => AttributeNamespace::Resource,
        3 => AttributeNamespace::InstrumentationScope,
        4 => AttributeNamespace::Record,
        _ => return Err(PolicyActivationFailure),
    };
    let mut path =
        PolicyAttributePath::new(namespace, input.text()?).map_err(|_| PolicyActivationFailure)?;
    path.occurrence = match input.u8()? {
        0 => PolicyOccurrence::All,
        1 => PolicyOccurrence::Index(input.u16()?),
        _ => return Err(PolicyActivationFailure),
    };
    let count = usize::from(input.u16()?);
    for _ in 0..count {
        path = match input.u8()? {
            1 => path
                .key(input.text()?)
                .map_err(|_| PolicyActivationFailure)?,
            2 => path
                .array_index(input.u16()?)
                .map_err(|_| PolicyActivationFailure)?,
            _ => return Err(PolicyActivationFailure),
        };
    }
    Ok(path)
}

fn decode_receiver(tag: u8) -> Result<PolicyReceiver, PolicyActivationFailure> {
    Ok(match tag {
        1 => PolicyReceiver::OtlpGrpc,
        2 => PolicyReceiver::OtlpHttpProtobuf,
        3 => PolicyReceiver::OtlpHttpJson,
        4 => PolicyReceiver::LokiPushJson,
        5 => PolicyReceiver::LokiPushProtobuf,
        6 => PolicyReceiver::LokiOtlpProtobuf,
        7 => PolicyReceiver::LokiOtlpJson,
        _ => return Err(PolicyActivationFailure),
    })
}

fn decode_kind(tag: u8) -> Result<AttributeValueKind, PolicyActivationFailure> {
    Ok(match tag {
        1 => AttributeValueKind::Null,
        2 => AttributeValueKind::Boolean,
        3 => AttributeValueKind::SignedInteger,
        4 => AttributeValueKind::FloatingPoint,
        5 => AttributeValueKind::String,
        6 => AttributeValueKind::Bytes,
        7 => AttributeValueKind::Array,
        8 => AttributeValueKind::KeyValueList,
        _ => return Err(PolicyActivationFailure),
    })
}

struct Input<'a> {
    remaining: &'a [u8],
}

impl<'a> Input<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], PolicyActivationFailure> {
        let (value, rest) = self
            .remaining
            .split_at_checked(count)
            .ok_or(PolicyActivationFailure)?;
        self.remaining = rest;
        Ok(value)
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), PolicyActivationFailure> {
        (self.take(expected.len())? == expected)
            .then_some(())
            .ok_or(PolicyActivationFailure)
    }

    fn u8(&mut self) -> Result<u8, PolicyActivationFailure> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(PolicyActivationFailure)
    }

    fn u16(&mut self) -> Result<u16, PolicyActivationFailure> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| PolicyActivationFailure)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, PolicyActivationFailure> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PolicyActivationFailure)?,
        ))
    }

    fn i32(&mut self) -> Result<i32, PolicyActivationFailure> {
        Ok(i32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PolicyActivationFailure)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, PolicyActivationFailure> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| PolicyActivationFailure)?,
        ))
    }

    fn text(&mut self) -> Result<String, PolicyActivationFailure> {
        let count = usize::try_from(self.u32()?).map_err(|_| PolicyActivationFailure)?;
        if count > MAX_COMPILED_POLICY_BYTES {
            return Err(PolicyActivationFailure);
        }
        String::from_utf8(self.take(count)?.to_vec()).map_err(|_| PolicyActivationFailure)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
