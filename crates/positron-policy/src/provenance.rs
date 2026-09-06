use std::fmt::{Display, Formatter};

use crate::policy::{MAX_RULE_ID_BYTES as POLICY_MAX_RULE_ID_BYTES, MAX_RULES};

/// Exact immutable policy identity and the ordered rules applied to one record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyProvenance {
    generation: u64,
    digest: [u8; 32],
    applied_rules: Vec<String>,
}

impl PolicyProvenance {
    /// Maximum number of applied rule identities retained for one record.
    pub const MAX_APPLIED_RULES: usize = MAX_RULES;

    /// Maximum encoded bytes in one applied rule identity.
    pub const MAX_RULE_ID_BYTES: usize = POLICY_MAX_RULE_ID_BYTES;

    /// Reconstructs checked provenance from authenticated durable parts.
    pub fn new(
        generation: u64,
        digest: [u8; 32],
        applied_rules: Vec<String>,
    ) -> Result<Self, PolicyProvenanceFailure> {
        Self::validate_parts(generation, digest, applied_rules.iter().map(String::as_str))?;
        Ok(Self {
            generation,
            digest,
            applied_rules,
        })
    }

    pub(crate) const fn evaluated(
        generation: u64,
        digest: [u8; 32],
        applied_rules: Vec<String>,
    ) -> Self {
        Self {
            generation,
            digest,
            applied_rules,
        }
    }

    /// Validates borrowed durable parts without allocating owned rule identities.
    pub fn validate_parts<'a>(
        generation: u64,
        digest: [u8; 32],
        applied_rules: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), PolicyProvenanceFailure> {
        if generation == 0 || digest.iter().all(|byte| *byte == 0) {
            return Err(PolicyProvenanceFailure(()));
        }
        let mut count = 0_usize;
        for rule in applied_rules {
            count = count
                .checked_add(1)
                .filter(|count| *count <= Self::MAX_APPLIED_RULES)
                .ok_or(PolicyProvenanceFailure(()))?;
            if rule.is_empty() || rule.len() > Self::MAX_RULE_ID_BYTES {
                return Err(PolicyProvenanceFailure(()));
            }
        }
        Ok(())
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
    pub fn applied_rules(&self) -> &[String] {
        &self.applied_rules
    }

    /// Returns the heap storage retained by the immutable applied-rule list.
    ///
    /// The policy crate owns this representation, so downstream stores do not
    /// need to approximate its vector capacity or string allocations.
    pub fn retained_heap_bytes(&self) -> Result<usize, PolicyProvenanceFailure> {
        let mut retained = self
            .applied_rules
            .capacity()
            .checked_mul(std::mem::size_of::<String>())
            .ok_or(PolicyProvenanceFailure(()))?;
        for rule in &self.applied_rules {
            retained = retained
                .checked_add(rule.capacity())
                .ok_or(PolicyProvenanceFailure(()))?;
        }
        Ok(retained)
    }
}

/// Typed, redacted reason that durable Policy Provenance is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyProvenanceFailure(());

impl Display for PolicyProvenanceFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Policy Provenance validation failed")
    }
}

impl std::error::Error for PolicyProvenanceFailure {}
