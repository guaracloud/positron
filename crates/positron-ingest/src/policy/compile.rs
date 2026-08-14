use std::collections::BTreeSet;

use positron_domain::value::AttributeNamespace;
use positron_signals::PolicyProvenance;

use super::{
    IngestPolicy, MAX_COMPILED_POLICY_BYTES, MAX_RULES, PolicyAction, PolicyAttributePath,
    PolicyCompileFailure, PolicyPathSegment, PolicyPredicate, PolicyRule, PolicyTarget,
};

impl IngestPolicy {
    pub fn compile(
        generation: u64,
        digest: [u8; 32],
        rules: Vec<PolicyRule>,
    ) -> Result<Self, PolicyCompileFailure> {
        if generation == 0 || digest.iter().all(|byte| *byte == 0) {
            return Err(PolicyCompileFailure::InvalidIdentity);
        }
        if rules.len() > MAX_RULES {
            return Err(PolicyCompileFailure::RuleBoundExceeded);
        }
        let mut ids = BTreeSet::new();
        let mut policy_bytes = 0_usize;
        for rule in &rules {
            if !ids.insert(rule.id.as_str()) {
                return Err(PolicyCompileFailure::InvalidRuleId);
            }
            policy_bytes = policy_bytes
                .checked_add(rule.bounded_bytes()?)
                .filter(|bytes| *bytes <= MAX_COMPILED_POLICY_BYTES)
                .ok_or(PolicyCompileFailure::PolicyBytesExceeded)?;
            if rule.action.has_protected_target() {
                return Err(PolicyCompileFailure::ProtectedTarget);
            }
        }
        let provenance = PolicyProvenance::new(generation, digest, Vec::new())
            .map_err(|_| PolicyCompileFailure::InvalidIdentity)?;
        Ok(Self { provenance, rules })
    }
}

impl PolicyRule {
    fn bounded_bytes(&self) -> Result<usize, PolicyCompileFailure> {
        let predicate_bytes = self
            .predicates
            .iter()
            .try_fold(0_usize, |bytes, predicate| {
                bytes.checked_add(match predicate {
                    PolicyPredicate::AttributeExists(path) => path.bounded_bytes(),
                    PolicyPredicate::BodyExactText(value) => value.len(),
                    PolicyPredicate::SignalStore(_)
                    | PolicyPredicate::Receiver(_)
                    | PolicyPredicate::LogSeverity(_) => 4,
                    PolicyPredicate::AttributeType(path, _) => {
                        path.bounded_bytes().saturating_add(1)
                    },
                    PolicyPredicate::ServiceIdentity(value) => value.len(),
                })
            });
        let action_bytes = match &self.action {
            PolicyAction::Accept | PolicyAction::Reject => 1,
            PolicyAction::Remove(target) | PolicyAction::Redact(target) => target.bounded_bytes(),
            PolicyAction::TruncateBytes(target, _) => target.bounded_bytes().saturating_add(4),
            PolicyAction::TruncateElements(target, _) => target.bounded_bytes().saturating_add(2),
        };
        predicate_bytes
            .and_then(|bytes| bytes.checked_add(self.id.len()))
            .and_then(|bytes| bytes.checked_add(action_bytes))
            .ok_or(PolicyCompileFailure::PolicyBytesExceeded)
    }
}

impl PolicyAction {
    fn has_protected_target(&self) -> bool {
        match self {
            Self::Accept | Self::Reject => false,
            Self::Remove(target)
            | Self::Redact(target)
            | Self::TruncateBytes(target, _)
            | Self::TruncateElements(target, _) => target.is_protected(),
        }
    }
}

impl PolicyTarget {
    fn bounded_bytes(&self) -> usize {
        match self {
            Self::Body => 1,
            Self::Attribute(path) => path.bounded_bytes(),
        }
    }

    fn is_protected(&self) -> bool {
        matches!(
            self,
            Self::Attribute(PolicyAttributePath {
                namespace: AttributeNamespace::Resource,
                key,
                segments,
                ..
            }) if key == "service.name" && segments.is_empty()
        )
    }
}

impl PolicyAttributePath {
    fn bounded_bytes(&self) -> usize {
        self.segments.iter().fold(self.key.len(), |bytes, segment| {
            bytes.saturating_add(match segment {
                PolicyPathSegment::Key(key) => key.len(),
                PolicyPathSegment::ArrayIndex(_) => std::mem::size_of::<u16>(),
            })
        })
    }
}
