//! Bounded, non-mutating administrative previews for declarative Ingest Policy.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    IngestPolicy, LogMetadata, NativeLogCandidate, NativeTraceCandidate, PolicyAction,
    PolicyPredicate, PolicyReceiver,
};

mod parser;

use parser::{
    action_name, allowed_fields, array, exact_fields, map_compile_failure, object,
    parse_attributes, parse_json, parse_receiver, parse_rule, parse_value, signed, string,
    unsigned,
};

pub const MAX_POLICY_PREVIEW_BYTES: usize = 65_536;
const MAX_PREVIEW_ATTRIBUTES: usize = 1_024;
const MAX_PREVIEW_OCCURRENCES: usize = 1_024;
const MAX_PREVIEW_VALUE_NESTING: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyPreviewFailure {
    RequestTooLarge,
    MalformedCandidate,
    InvalidPolicy,
    EvaluationUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyPreviewOutcome {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPreviewValidation {
    generation: u64,
    digest: [u8; 32],
    rule_count: usize,
    maximum_evaluation_steps: u64,
    maximum_reserved_memory_bytes: u64,
}
impl PolicyPreviewValidation {
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rule_count
    }
    #[must_use]
    pub const fn maximum_evaluation_steps(&self) -> u64 {
        self.maximum_evaluation_steps
    }
    #[must_use]
    pub const fn maximum_reserved_memory_bytes(&self) -> u64 {
        self.maximum_reserved_memory_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPreviewCandidate {
    receiver: PolicyReceiver,
    record: PreviewRecord,
}
#[derive(Clone, Debug, Eq, PartialEq)]
enum PreviewRecord {
    Log(Box<NativeLogCandidate>),
    Trace(NativeTraceCandidate),
}

#[derive(Clone, Debug)]
pub struct PolicyPreviewPolicy {
    compiled: IngestPolicy,
    rules: BTreeMap<String, PreviewRule>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct PreviewRule {
    predicates: Vec<PolicyPredicate>,
    action: PolicyAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPreviewResult {
    outcome: PolicyPreviewOutcome,
    generation: u64,
    digest: [u8; 32],
    applied_rule_ids: Vec<String>,
}
impl PolicyPreviewResult {
    #[must_use]
    pub const fn outcome(&self) -> PolicyPreviewOutcome {
        self.outcome
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
    pub const fn applied_rule_count(&self) -> usize {
        self.applied_rule_ids.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPreview {
    rendered: String,
}
impl PolicyPreview {
    /// Evaluates only an in-memory fixture through the shared policy transition.
    pub fn test(
        policy: &PolicyPreviewPolicy,
        candidate: PolicyPreviewCandidate,
    ) -> Result<PolicyPreviewResult, PolicyPreviewFailure> {
        let (accepted, provenance) = match candidate.record {
            PreviewRecord::Log(record) => policy.compiled.preview_log(*record, candidate.receiver),
            PreviewRecord::Trace(record) => {
                policy.compiled.preview_trace(record, candidate.receiver)
            },
        }
        .map_err(|_| PolicyPreviewFailure::EvaluationUnavailable)?;
        Ok(PolicyPreviewResult {
            outcome: if accepted {
                PolicyPreviewOutcome::Accepted
            } else {
                PolicyPreviewOutcome::Rejected
            },
            generation: provenance.generation(),
            digest: provenance.digest(),
            applied_rule_ids: provenance.applied_rules().to_vec(),
        })
    }

    /// Produces deterministic policy evidence without serializing fixture values.
    pub fn explain(
        policy: &PolicyPreviewPolicy,
        result: PolicyPreviewResult,
    ) -> Result<Self, PolicyPreviewFailure> {
        if result.generation != policy.compiled.generation()
            || result.digest != policy.compiled.digest()
        {
            return Err(PolicyPreviewFailure::InvalidPolicy);
        }
        let mut rendered = match result.outcome {
            PolicyPreviewOutcome::Accepted => String::from("accepted"),
            PolicyPreviewOutcome::Rejected => String::from("rejected"),
        };
        for id in result.applied_rule_ids {
            let rule = policy
                .rules
                .get(&id)
                .ok_or(PolicyPreviewFailure::InvalidPolicy)?;
            rendered.push_str("; matched rule action=");
            rendered.push_str(action_name(&rule.action));
        }
        Ok(Self { rendered })
    }

    pub fn explain_default(
        candidate: PolicyPreviewCandidate,
    ) -> Result<Self, PolicyPreviewFailure> {
        let policy = PolicyPreviewPolicy::from_ingest(
            IngestPolicy::release_1_default()
                .map_err(|_| PolicyPreviewFailure::EvaluationUnavailable)?,
        );
        Self::explain(&policy, Self::test(&policy, candidate)?)
    }
    #[must_use]
    pub fn rendered(&self) -> &str {
        &self.rendered
    }

    #[must_use]
    pub fn diff(before: &PolicyPreviewPolicy, after: &PolicyPreviewPolicy) -> PolicyPreviewDiff {
        let mut changes = Vec::new();
        if before.compiled.generation() != after.compiled.generation() {
            changes.push(PolicyPreviewSemanticChange::GenerationChanged {
                from: before.compiled.generation(),
                to: after.compiled.generation(),
            });
        }
        let ids: BTreeSet<_> = before
            .rules
            .keys()
            .chain(after.rules.keys())
            .cloned()
            .collect();
        for id in ids {
            match (before.rules.get(&id), after.rules.get(&id)) {
                (None, Some(rule)) => changes.push(PolicyPreviewSemanticChange::RuleAdded {
                    rule_id: id,
                    action: action_name(&rule.action),
                }),
                (Some(rule), None) => changes.push(PolicyPreviewSemanticChange::RuleRemoved {
                    rule_id: id,
                    action: action_name(&rule.action),
                }),
                (Some(left), Some(right)) => {
                    if left.predicates != right.predicates {
                        changes.push(PolicyPreviewSemanticChange::RulePredicatesChanged {
                            rule_id: id.clone(),
                        });
                    }
                    if left.action != right.action {
                        changes.push(PolicyPreviewSemanticChange::RuleActionChanged {
                            from: action_name(&left.action),
                            to: action_name(&right.action),
                        });
                    }
                },
                (None, None) => {},
            }
        }
        PolicyPreviewDiff { changes }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPreviewDiff {
    changes: Vec<PolicyPreviewSemanticChange>,
}
impl PolicyPreviewDiff {
    #[must_use]
    pub fn changes(&self) -> &[PolicyPreviewSemanticChange] {
        &self.changes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyPreviewSemanticChange {
    GenerationChanged {
        from: u64,
        to: u64,
    },
    RuleAdded {
        rule_id: String,
        action: &'static str,
    },
    RuleRemoved {
        rule_id: String,
        action: &'static str,
    },
    RulePredicatesChanged {
        rule_id: String,
    },
    RuleActionChanged {
        from: &'static str,
        to: &'static str,
    },
}

impl PolicyPreviewPolicy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, PolicyPreviewFailure> {
        let value = parse_json(bytes)?;
        let object = object(&value, PolicyPreviewFailure::InvalidPolicy)?;
        exact_fields(
            object,
            &["generation", "rules"],
            PolicyPreviewFailure::InvalidPolicy,
        )?;
        let generation = unsigned(
            object.get("generation"),
            PolicyPreviewFailure::InvalidPolicy,
        )?;
        let rules = array(object.get("rules"), PolicyPreviewFailure::InvalidPolicy)?;
        let mut compiled_rules = Vec::with_capacity(rules.len());
        let mut preview_rules = BTreeMap::new();
        for value in rules {
            let (id, rule, preview) = parse_rule(value)?;
            if preview_rules.insert(id.clone(), preview).is_some() {
                return Err(PolicyPreviewFailure::InvalidPolicy);
            }
            compiled_rules.push(rule);
        }
        let compiled =
            IngestPolicy::compile(generation, compiled_rules).map_err(map_compile_failure)?;
        Ok(Self {
            compiled,
            rules: preview_rules,
        })
    }
    fn from_ingest(compiled: IngestPolicy) -> Self {
        Self {
            compiled,
            rules: BTreeMap::new(),
        }
    }
    /// Transfers the bounded candidate to the prospective activation transition.
    /// The external JSON representation never enters the runtime boundary.
    #[must_use]
    pub fn into_ingest_policy(self) -> IngestPolicy {
        self.compiled
    }
    #[must_use]
    pub fn validation(&self) -> PolicyPreviewValidation {
        let budget = self.compiled.budget();
        PolicyPreviewValidation {
            generation: self.compiled.generation(),
            digest: self.compiled.digest(),
            rule_count: self.rules.len(),
            maximum_evaluation_steps: budget.evaluation_steps(),
            maximum_reserved_memory_bytes: budget.reserved_memory_bytes().unwrap_or(u64::MAX),
        }
    }
}

impl PolicyPreviewCandidate {
    pub fn from_json(bytes: &[u8]) -> Result<Self, PolicyPreviewFailure> {
        let value = parse_json(bytes)?;
        let object = object(&value, PolicyPreviewFailure::MalformedCandidate)?;
        let receiver = parse_receiver(string(
            object.get("receiver"),
            PolicyPreviewFailure::MalformedCandidate,
        )?)?;
        let signal = string(
            object.get("signal"),
            PolicyPreviewFailure::MalformedCandidate,
        )?;
        let attributes = parse_attributes(array(
            object.get("attributes"),
            PolicyPreviewFailure::MalformedCandidate,
        )?)?;
        match signal {
            "logs" => {
                allowed_fields(
                    object,
                    &["receiver", "signal", "body", "severity", "attributes"],
                    PolicyPreviewFailure::MalformedCandidate,
                )?;
                let body = object
                    .get("body")
                    .map(|value| parse_value(value, 0))
                    .transpose()?;
                let severity = object
                    .get("severity")
                    .map(|value| signed(Some(value), PolicyPreviewFailure::MalformedCandidate))
                    .transpose()?
                    .unwrap_or(0);
                Ok(Self {
                    receiver,
                    record: PreviewRecord::Log(Box::new(NativeLogCandidate::new(
                        None,
                        None,
                        body,
                        attributes,
                        LogMetadata::new(
                            severity,
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
                    ))),
                })
            },
            "traces" => {
                exact_fields(
                    object,
                    &["receiver", "signal", "attributes"],
                    PolicyPreviewFailure::MalformedCandidate,
                )?;
                Ok(Self {
                    receiver,
                    record: PreviewRecord::Trace(NativeTraceCandidate::new(attributes)),
                })
            },
            _ => Err(PolicyPreviewFailure::MalformedCandidate),
        }
    }
}
