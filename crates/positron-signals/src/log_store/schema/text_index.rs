#[cfg(test)]
mod tests {
    use super::{TextBlockSummary, TextSearchCandidate};

    #[test]
    fn complete_summary_proves_trigram_absence_without_false_negatives() {
        let summary = TextBlockSummary::from_bodies([Some("alpha"), Some("βeta")])
            .expect("summary construction");
        let present = TextSearchCandidate::literal("pha")
            .expect("candidate construction")
            .expect("literal is long enough");
        let absent = TextSearchCandidate::literal("zzz")
            .expect("candidate construction")
            .expect("literal is long enough");
        assert_eq!(summary.might_contain(&present), Some(true));
        assert_eq!(summary.might_contain(&absent), Some(false));
    }

    #[test]
    fn short_literals_use_generic_fallback() {
        assert!(
            TextSearchCandidate::literal("ab")
                .expect("candidate construction")
                .is_none()
        );
    }

    #[test]
    fn candidate_literals_are_bounded_deduplicated_and_fail_closed() {
        let duplicate = TextSearchCandidate::any_of_bytes(&[
            b"alpha".to_vec(),
            b"alpha".to_vec(),
            b"beta".to_vec(),
        ])
        .expect("duplicate literals are valid")
        .expect("at least one literal remains");
        assert_eq!(duplicate.literals(), &[b"alpha".to_vec(), b"beta".to_vec()]);

        let too_many = (0..=super::MAX_SEARCH_LITERALS)
            .map(|index| format!("{index:03}").into_bytes())
            .collect::<Vec<_>>();
        assert!(
            TextSearchCandidate::any_of_bytes(&too_many)
                .expect("bounded input allocation")
                .is_none()
        );

        assert!(
            TextSearchCandidate::any_of_bytes(&[vec![0xff, 0xfe, 0xfd]])
                .expect("invalid bytes are a supported fallback")
                .is_none()
        );
        assert!(
            TextSearchCandidate::any_of_bytes(&[])
                .expect("empty candidate allocation")
                .is_none()
        );
    }

    #[test]
    fn summary_overflow_is_incomplete() {
        let bodies = (0..super::MAX_TEXT_TRIGRAMS + 1)
            .map(|index| {
                let first = char::from(b'a' + u8::try_from((index / 289) % 17).expect("digit"));
                let second = char::from(b'a' + u8::try_from((index / 17) % 17).expect("digit"));
                let third = char::from(b'a' + u8::try_from(index % 17).expect("digit"));
                format!("a{first}{second}{third}")
            })
            .collect::<Vec<_>>();
        let summary = TextBlockSummary::from_bodies(bodies.iter().map(String::as_str).map(Some))
            .expect("summary construction");
        assert!(!summary.complete());
        assert_eq!(
            summary.might_contain(
                &TextSearchCandidate::literal("000")
                    .expect("candidate")
                    .expect("candidate")
            ),
            None
        );
    }
}
use super::failure::SchemaFailure;

pub(crate) const MAX_TEXT_TRIGRAMS: usize = 4_096;
/// Text coverage is an optional physical optimization. Keep its retained
/// reservation count bounded so normal ingest retains room for the existing
/// governor's in-flight and ledger reservations; later blocks use decoding
/// fallback without changing logical results.
pub(crate) const MAX_TEXT_SUMMARY_BLOCKS: usize = 4;
/// Tiny schema index budgets reserve their bounded bytes for typed scalar
/// evidence; text search falls back to authenticated decoding in that case.
pub(crate) const MIN_TEXT_INDEX_BUDGET_BYTES: usize = 256;
const TRIGRAM_BYTES: usize = 3;
const MAX_SEARCH_LITERALS: usize = 32;
const MAX_SEARCH_LITERAL_BYTES: usize = 1_024;

/// A bounded set of byte literals that every matching body contains at least
/// one of. Query owns the parser; this type is only the storage pruning input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextSearchCandidate {
    literals: Vec<Vec<u8>>,
}

impl TextSearchCandidate {
    pub fn literal(value: &str) -> Result<Option<Self>, SchemaFailure> {
        Self::from_literals([value.as_bytes()])
    }

    pub fn any_of_bytes(values: &[Vec<u8>]) -> Result<Option<Self>, SchemaFailure> {
        Self::from_literals(values.iter().map(Vec::as_slice))
    }

    pub(crate) fn literals(&self) -> &[Vec<u8>] {
        &self.literals
    }

    fn from_literals<'a>(
        values: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Option<Self>, SchemaFailure> {
        let values = values.into_iter();
        let mut literals = Vec::new();
        literals
            .try_reserve_exact(MAX_SEARCH_LITERALS.min(values.size_hint().0))
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for value in values {
            if value.len() < TRIGRAM_BYTES
                || value.len() > MAX_SEARCH_LITERAL_BYTES
                || std::str::from_utf8(value).is_err()
            {
                return Ok(None);
            }
            if literals
                .iter()
                .any(|known: &Vec<u8>| known.as_slice() == value)
            {
                continue;
            }
            if literals.len() == MAX_SEARCH_LITERALS {
                return Ok(None);
            }
            let mut literal = Vec::new();
            literal
                .try_reserve_exact(value.len())
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            literal.extend_from_slice(value);
            literals.push(literal);
        }
        if literals.is_empty() {
            return Ok(None);
        }
        literals.sort();
        Ok(Some(Self { literals }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TextBlockSummary {
    complete: bool,
    trigrams: Vec<[u8; TRIGRAM_BYTES]>,
}

impl TextBlockSummary {
    pub(crate) fn memory_bound(body_bytes: usize) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(
            body_bytes
                .saturating_sub(TRIGRAM_BYTES - 1)
                .min(MAX_TEXT_TRIGRAMS)
                .checked_mul(std::mem::size_of::<[u8; TRIGRAM_BYTES]>())?,
        )
    }

    pub(crate) fn from_bodies<'a>(
        bodies: impl IntoIterator<Item = Option<&'a str>>,
    ) -> Result<Self, SchemaFailure> {
        let mut trigrams = Vec::new();
        let mut complete = true;
        'bodies: for body in bodies {
            let Some(body) = body else { continue };
            for window in body.as_bytes().windows(TRIGRAM_BYTES) {
                let trigram = [window[0], window[1], window[2]];
                match trigrams.binary_search(&trigram) {
                    Ok(_) => continue,
                    Err(position) if trigrams.len() < MAX_TEXT_TRIGRAMS => {
                        trigrams
                            .try_reserve_exact(1)
                            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                        trigrams.insert(position, trigram);
                    },
                    Err(_) => {
                        complete = false;
                        break 'bodies;
                    },
                }
            }
        }
        trigrams.shrink_to_fit();
        Ok(Self { complete, trigrams })
    }

    pub(crate) const fn complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn encoded_bytes(&self) -> Result<usize, SchemaFailure> {
        1_usize
            .checked_add(8)
            .and_then(|bytes| bytes.checked_add(self.trigrams.len().checked_mul(TRIGRAM_BYTES)?))
            .ok_or(SchemaFailure::LimitExceeded)
    }

    pub(crate) fn memory_bytes(&self) -> Result<usize, SchemaFailure> {
        std::mem::size_of::<Self>()
            .checked_add(
                self.trigrams
                    .capacity()
                    .checked_mul(std::mem::size_of::<[u8; TRIGRAM_BYTES]>())
                    .ok_or(SchemaFailure::LimitExceeded)?,
            )
            .ok_or(SchemaFailure::LimitExceeded)
    }

    pub(crate) fn try_clone(&self) -> Result<Self, SchemaFailure> {
        let mut trigrams = Vec::new();
        trigrams
            .try_reserve_exact(self.trigrams.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        trigrams.extend_from_slice(&self.trigrams);
        Ok(Self {
            complete: self.complete,
            trigrams,
        })
    }

    pub(crate) fn might_contain(&self, candidate: &TextSearchCandidate) -> Option<bool> {
        if !self.complete {
            return None;
        }
        Some(candidate.literals().iter().any(|literal| {
            literal.as_slice().windows(TRIGRAM_BYTES).all(|window| {
                self.trigrams
                    .binary_search(&[window[0], window[1], window[2]])
                    .is_ok()
            })
        }))
    }

    pub(crate) fn trigrams(&self) -> &[[u8; TRIGRAM_BYTES]] {
        &self.trigrams
    }

    pub(crate) const fn from_wire_parts(
        complete: bool,
        trigrams: Vec<[u8; TRIGRAM_BYTES]>,
    ) -> Self {
        Self { complete, trigrams }
    }
}
