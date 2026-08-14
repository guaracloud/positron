use std::collections::BTreeSet;

use positron_domain::value::AttributeNamespace;

use super::{
    IngestPolicy, MAX_COMPILED_POLICY_BYTES, MAX_EVALUATION_STEPS, MAX_NATIVE_RECORD_BYTES,
    MAX_RULES, PolicyAction, PolicyBudget, PolicyCompileFailure, PolicyPredicate, PolicyRule,
    PolicyTarget,
};
use crate::PolicyProvenance;

impl IngestPolicy {
    pub fn release_1_default() -> Result<Self, PolicyCompileFailure> {
        Self::preserving(1)
    }

    pub fn preserving(generation: u64) -> Result<Self, PolicyCompileFailure> {
        Self::compile(generation, Vec::new())
    }

    pub fn compile(generation: u64, rules: Vec<PolicyRule>) -> Result<Self, PolicyCompileFailure> {
        if generation == 0 {
            return Err(PolicyCompileFailure::InvalidIdentity);
        }
        if rules.len() > MAX_RULES {
            return Err(PolicyCompileFailure::RuleBoundExceeded);
        }
        let mut ids = BTreeSet::new();
        let mut policy_bytes = 0_usize;
        let mut evaluation_steps = 0_u64;
        let mut provenance_bytes = 0_u64;
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
            evaluation_steps = evaluation_steps
                .checked_add(rule.worst_case_steps()?)
                .filter(|steps| *steps <= MAX_EVALUATION_STEPS)
                .ok_or(PolicyCompileFailure::EvaluationBudgetExceeded)?;
            provenance_bytes = provenance_bytes
                .checked_add(
                    u64::try_from(rule.id.len())
                        .map_err(|_| PolicyCompileFailure::PolicyBytesExceeded)?,
                )
                .and_then(|bytes| {
                    bytes.checked_add(u64::try_from(std::mem::size_of::<String>()).ok()?)
                })
                .ok_or(PolicyCompileFailure::PolicyBytesExceeded)?;
        }
        let encoded = super::canonical::encode(&rules)?;
        crate::activation::MAX_ACTIVATED_POLICY_OBJECT_BYTES
            .checked_sub(32)
            .filter(|maximum| encoded.len() <= *maximum)
            .ok_or(PolicyCompileFailure::PolicyBytesExceeded)?;
        let digest = super::canonical::digest_encoded(&encoded);
        let scratch_bytes = u64::try_from(rules.len())
            .ok()
            .and_then(|count| count.checked_mul(u64::try_from(std::mem::size_of::<String>()).ok()?))
            .ok_or(PolicyCompileFailure::PolicyBytesExceeded)?;
        Ok(Self {
            generation,
            digest,
            rules,
            budget: PolicyBudget {
                evaluation_steps,
                retained_bytes: MAX_NATIVE_RECORD_BYTES,
                scratch_bytes,
                provenance_bytes,
                mutation_bytes: u64::try_from(std::mem::size_of::<crate::EvaluatedLogRecord>())
                    .map_err(|_| PolicyCompileFailure::PolicyBytesExceeded)?,
            },
        })
    }

    pub fn reject_exact_text_body(
        generation: u64,
        rule_id: impl Into<String>,
        text: &str,
    ) -> Result<Self, PolicyCompileFailure> {
        Self::compile(
            generation,
            vec![PolicyRule::new(
                rule_id,
                vec![PolicyPredicate::body_exact_text(text)?],
                PolicyAction::Reject,
            )?],
        )
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub fn provenance(&self) -> PolicyProvenance {
        PolicyProvenance::new(self.generation, self.digest, Vec::new())
    }

    #[must_use]
    pub const fn budget(&self) -> PolicyBudget {
        self.budget
    }
}

impl PolicyRule {
    pub(super) fn worst_case_steps(&self) -> Result<u64, PolicyCompileFailure> {
        let predicates = self
            .predicates
            .iter()
            .try_fold(0_u64, |total, predicate| {
                total.checked_add(predicate.worst_case_steps())
            })
            .ok_or(PolicyCompileFailure::EvaluationBudgetExceeded)?;
        predicates
            .checked_add(self.action.worst_case_steps())
            .ok_or(PolicyCompileFailure::EvaluationBudgetExceeded)
    }

    fn bounded_bytes(&self) -> Result<usize, PolicyCompileFailure> {
        let predicates = self
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
            })
            .ok_or(PolicyCompileFailure::PolicyBytesExceeded)?;
        predicates
            .checked_add(self.id.len())
            .and_then(|bytes| bytes.checked_add(self.action.bounded_bytes()))
            .ok_or(PolicyCompileFailure::PolicyBytesExceeded)
    }
}

impl PolicyPredicate {
    fn worst_case_steps(&self) -> u64 {
        match self {
            Self::AttributeExists(path) | Self::AttributeType(path, _) => path.worst_case_steps(),
            Self::ServiceIdentity(_) => MAX_NATIVE_RECORD_BYTES,
            Self::BodyExactText(value) => u64::try_from(value.len()).unwrap_or(u64::MAX).max(1),
            Self::SignalStore(_) | Self::Receiver(_) | Self::LogSeverity(_) => 1,
        }
    }
}

impl PolicyAction {
    fn worst_case_steps(&self) -> u64 {
        match self {
            Self::Accept | Self::Reject => 1,
            Self::Remove(target)
            | Self::Redact(target)
            | Self::TruncateBytes(target, _)
            | Self::TruncateElements(target, _) => target.worst_case_steps(),
        }
    }
}

impl PolicyTarget {
    fn worst_case_steps(&self) -> u64 {
        match self {
            Self::Body => 1,
            Self::Attribute(path) => path.worst_case_steps(),
        }
    }
}

impl super::PolicyAttributePath {
    fn worst_case_steps(&self) -> u64 {
        let depth = u64::try_from(self.segments.len()).unwrap_or(u64::MAX);
        MAX_NATIVE_RECORD_BYTES.saturating_mul(depth.saturating_add(2))
    }
}

impl PolicyAction {
    fn bounded_bytes(&self) -> usize {
        match self {
            Self::Accept | Self::Reject => 1,
            Self::Remove(target) | Self::Redact(target) => target.bounded_bytes(),
            Self::TruncateBytes(target, _) => target.bounded_bytes().saturating_add(4),
            Self::TruncateElements(target, _) => target.bounded_bytes().saturating_add(2),
        }
    }

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
            Self::Attribute(path)
                if path.namespace == AttributeNamespace::Resource
                    && path.key == "service.name"
                    && path.segments.is_empty()
        )
    }
}
