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
        Self::validate_parts(generation, digest, applied_rules.iter().map(String::as_str))?;
        Ok(Self {
            generation,
            digest,
            applied_rules,
        })
    }

    pub(super) fn validate_parts<'a>(
        generation: u64,
        digest: [u8; 32],
        applied_rules: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), LogStoreFailure> {
        if generation == 0 || digest.iter().all(|byte| *byte == 0) {
            return Err(LogStoreFailure::invalid_input());
        }
        let mut count = 0_usize;
        for rule in applied_rules {
            count = count
                .checked_add(1)
                .filter(|count| *count <= MAX_POLICY_RULES)
                .ok_or_else(LogStoreFailure::invalid_input)?;
            if rule.is_empty() || rule.len() > MAX_RULE_ID_BYTES {
                return Err(LogStoreFailure::invalid_input());
            }
        }
        Ok(())
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
