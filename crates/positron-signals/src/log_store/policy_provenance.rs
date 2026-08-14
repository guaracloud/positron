use super::LogStoreFailure;

const MAX_POLICY_RULES: usize = 64;
const MAX_RULE_ID_BYTES: usize = 256;

/// Immutable evidence identifying the Ingest Policy applied before persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyProvenance {
    generation: u64,
    digest: [u8; 32],
    applied_rules: Vec<String>,
}

impl PolicyProvenance {
    pub(crate) fn new(
        generation: u64,
        digest: [u8; 32],
        applied_rules: Vec<String>,
    ) -> Result<Self, LogStoreFailure> {
        if generation == 0
            || digest.iter().all(|byte| *byte == 0)
            || applied_rules.len() > MAX_POLICY_RULES
            || applied_rules
                .iter()
                .any(|rule| rule.is_empty() || rule.len() > MAX_RULE_ID_BYTES)
        {
            return Err(LogStoreFailure::invalid_input());
        }
        Ok(Self {
            generation,
            digest,
            applied_rules,
        })
    }

    pub(crate) fn from_evaluated(
        provenance: &positron_policy::PolicyProvenance,
    ) -> Result<Self, LogStoreFailure> {
        Self::new(
            provenance.generation(),
            provenance.digest(),
            provenance.applied_rules().to_vec(),
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
    pub fn applied_rules(&self) -> &[String] {
        &self.applied_rules
    }
}
