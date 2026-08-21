use regex::Regex;
use regex_syntax::hir::literal::{ExtractKind, Extractor};

use crate::{QueryFailure, QueryFailureCode};

/// Search expressions are deliberately much smaller than a log body. This
/// keeps parsing, compilation, and the authenticated query plan bounded even
/// when the body limit is raised independently.
pub(crate) const MAX_SEARCH_LITERAL_BYTES: usize = 1_024;
const MAX_SEARCH_LITERAL_COUNT: usize = 32;
const MAX_REGEX_COMPILED_BYTES: usize = 64 * 1024;
const MAX_REGEX_NESTING: u32 = 32;

const fn max_candidate_memory_bytes() -> u64 {
    (std::mem::size_of::<Vec<Vec<u8>>>()
        + MAX_SEARCH_LITERAL_COUNT * (std::mem::size_of::<Vec<u8>>() + MAX_SEARCH_LITERAL_BYTES))
        as u64
}

#[derive(Clone, Debug)]
pub(crate) struct BoundedRegex {
    source: String,
    compiled: Regex,
    pruning_literals: Vec<Vec<u8>>,
}

impl BoundedRegex {
    pub(crate) fn new(source: String) -> Result<Self, QueryFailure> {
        if source.is_empty() || source.len() > MAX_SEARCH_LITERAL_BYTES {
            return Err(unsupported());
        }
        let compiled = regex::RegexBuilder::new(&source)
            .size_limit(MAX_REGEX_COMPILED_BYTES)
            .dfa_size_limit(MAX_REGEX_COMPILED_BYTES)
            .nest_limit(MAX_REGEX_NESTING)
            .build()
            .map_err(|_| unsupported())?;
        let pruning_literals = mandatory_literals(&source)?;
        Ok(Self {
            source,
            compiled,
            pruning_literals,
        })
    }

    pub(crate) fn is_match(&self, text: &str) -> bool {
        self.compiled.is_match(text)
    }

    /// Performs the cheap candidate check before invoking the regex engine.
    /// Every retained literal is a mandatory prefix or suffix candidate from
    /// the bounded HIR extractor, so this check can only produce false
    /// positives and can never reject a valid regex match.
    pub(crate) fn has_literal_candidate(&self, text: &str) -> bool {
        self.pruning_literals.is_empty()
            || self.pruning_literals.iter().any(|literal| {
                text.as_bytes()
                    .windows(literal.len())
                    .any(|window| window == literal)
            })
    }

    pub(crate) fn pruning_literals(&self) -> &[Vec<u8>] {
        &self.pruning_literals
    }

    pub(crate) const fn memory_bytes(&self) -> u64 {
        MAX_REGEX_COMPILED_BYTES as u64 + max_candidate_memory_bytes()
    }
}

impl PartialEq for BoundedRegex {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for BoundedRegex {}

pub(crate) fn search_text(source: String) -> Result<String, QueryFailure> {
    if source.is_empty() || source.len() > MAX_SEARCH_LITERAL_BYTES {
        return Err(unsupported());
    }
    Ok(source)
}

pub(crate) const fn text_memory_bytes() -> u64 {
    max_candidate_memory_bytes()
}

fn mandatory_literals(source: &str) -> Result<Vec<Vec<u8>>, QueryFailure> {
    let mut parser = regex_syntax::ParserBuilder::new();
    parser.nest_limit(MAX_REGEX_NESTING).unicode(true);
    let hir = match parser.build().parse(source) {
        Ok(hir) => hir,
        Err(_) => return Ok(Vec::new()),
    };
    for kind in [ExtractKind::Prefix, ExtractKind::Suffix] {
        let mut extractor = Extractor::new();
        extractor
            .kind(kind)
            .limit_class(16)
            .limit_repeat(32)
            .limit_literal_len(MAX_SEARCH_LITERAL_BYTES)
            .limit_total(32);
        let sequence = extractor.extract(&hir);
        let Some(literals) = sequence.literals() else {
            continue;
        };
        if literals.is_empty()
            || literals.iter().any(|literal| {
                !literal.is_exact()
                    || literal.len() < 3
                    || std::str::from_utf8(literal.as_bytes()).is_err()
            })
        {
            continue;
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(literals.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        for literal in literals {
            let bytes = literal.as_bytes();
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(bytes.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            owned.extend_from_slice(bytes);
            result.push(owned);
        }
        result.sort();
        result.dedup();
        return Ok(result);
    }
    Ok(Vec::new())
}

const fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}

#[cfg(test)]
mod tests {
    use super::{BoundedRegex, MAX_SEARCH_LITERAL_BYTES, search_text};
    use crate::QueryFailureCode;

    #[test]
    fn bounded_regex_keeps_only_safe_literal_candidates() {
        let anchored = BoundedRegex::new("^error-42$".to_owned()).expect("regex is valid");
        assert!(anchored.has_literal_candidate("error-42"));
        assert!(!anchored.has_literal_candidate("error-41"));
        assert!(anchored.is_match("error-42"));

        let escaped = BoundedRegex::new(r"error\|42".to_owned()).expect("regex is valid");
        assert!(escaped.has_literal_candidate("error|42"));
        assert!(escaped.is_match("error|42"));

        let dynamic = BoundedRegex::new(r"error-\d+".to_owned()).expect("regex is valid");
        assert!(dynamic.has_literal_candidate("error-42"));
        assert!(dynamic.is_match("error-42"));
        assert_eq!(
            anchored,
            BoundedRegex::new("^error-42$".to_owned()).expect("regex is valid")
        );
        assert_ne!(anchored, dynamic);

        let empty_match = BoundedRegex::new("^$".to_owned()).expect("regex is valid");
        assert!(empty_match.has_literal_candidate(""));
        assert!(empty_match.is_match(""));
    }

    #[test]
    fn bounded_regex_uses_upstream_mandatory_literal_extraction() {
        let dynamic = BoundedRegex::new(r"error-\d+".to_owned()).expect("regex is valid");
        assert!(dynamic.pruning_literals().is_empty());

        let suffix = BoundedRegex::new(r".*foobar".to_owned()).expect("regex is valid");
        assert!(suffix.pruning_literals().is_empty());

        let short_alternative = BoundedRegex::new(r"a|foobar".to_owned()).expect("regex is valid");
        assert!(short_alternative.pruning_literals().is_empty());

        let boundary = BoundedRegex::new(r"\bquux\b".to_owned()).expect("regex is valid");
        assert_eq!(boundary.pruning_literals(), [b"quux".to_vec()]);
    }

    #[test]
    fn extracted_literals_never_reject_a_regex_match() {
        let patterns = [
            r"error-\d+",
            r".*foobar",
            r"a|foobar",
            r"\bquux\b",
            r"(foo|bar)[0-9]+",
            r"foo.*bar",
            r"привет|hello",
        ];
        let bodies = [
            "error-42",
            "prefix error-7 suffix",
            "foobar",
            "a",
            "quux",
            "foo123",
            "bar9",
            "foo and bar",
            "привет мир",
            "hello world",
        ];
        for pattern in patterns {
            let regex = BoundedRegex::new(pattern.to_owned()).expect("bounded regex");
            for body in bodies {
                if regex.is_match(body) {
                    assert!(
                        regex.has_literal_candidate(body),
                        "candidate rejected a match: {pattern:?} / {body:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn truncated_extraction_falls_back_instead_of_using_inexact_literals() {
        let regex = BoundedRegex::new(r"[ab]{8}".to_owned()).expect("bounded regex");
        assert!(regex.pruning_literals().is_empty());
        assert!(regex.is_match("bbbbbbbb"));
        assert!(regex.has_literal_candidate("bbbbbbbb"));
    }

    #[test]
    fn bounded_search_patterns_reject_invalid_and_over_limit_input() {
        assert_eq!(
            BoundedRegex::new("[".to_owned())
                .expect_err("invalid regex must be rejected")
                .code(),
            QueryFailureCode::UnsupportedQuery
        );
        assert_eq!(
            BoundedRegex::new(String::new())
                .expect_err("empty regex must be rejected")
                .code(),
            QueryFailureCode::UnsupportedQuery
        );
        assert_eq!(
            search_text("a".repeat(MAX_SEARCH_LITERAL_BYTES + 1))
                .expect_err("oversized literal must be rejected")
                .code(),
            QueryFailureCode::UnsupportedQuery
        );
    }
}
