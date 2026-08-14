/// Exact immutable policy identity and the ordered rules applied to one record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyProvenance {
    generation: u64,
    digest: [u8; 32],
    applied_rules: Vec<String>,
}

impl PolicyProvenance {
    pub(crate) const fn new(generation: u64, digest: [u8; 32], applied_rules: Vec<String>) -> Self {
        Self {
            generation,
            digest,
            applied_rules,
        }
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
