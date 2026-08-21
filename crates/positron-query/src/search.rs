use regex::Regex;

use crate::{QueryFailure, QueryFailureCode};

/// Search expressions are deliberately much smaller than a log body. This
/// keeps parsing, compilation, and the authenticated query plan bounded even
/// when the body limit is raised independently.
pub(crate) const MAX_SEARCH_LITERAL_BYTES: usize = 1_024;
const MAX_REGEX_COMPILED_BYTES: usize = 64 * 1024;
const MAX_REGEX_NESTING: u32 = 32;

#[derive(Clone, Debug)]
pub(crate) struct BoundedRegex {
    source: String,
    compiled: Regex,
    literal: Option<String>,
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
        let literal = literal_hint(&source)?;
        Ok(Self {
            source,
            compiled,
            literal,
        })
    }

    pub(crate) fn is_match(&self, text: &str) -> bool {
        self.compiled.is_match(text)
    }

    /// Performs the cheap candidate check before invoking the regex engine.
    /// The hint is only retained for expressions that are entirely literal
    /// apart from optional anchors, so it cannot reject a valid regex match.
    pub(crate) fn has_literal_candidate(&self, text: &str) -> bool {
        self.literal
            .as_deref()
            .is_none_or(|literal| text.contains(literal))
    }

    pub(crate) const fn memory_bytes(&self) -> u64 {
        MAX_REGEX_COMPILED_BYTES as u64
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
    MAX_SEARCH_LITERAL_BYTES as u64
}

fn literal_hint(source: &str) -> Result<Option<String>, QueryFailure> {
    let mut literal = String::new();
    literal
        .try_reserve_exact(source.len())
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let mut characters = source.chars().peekable();
    if matches!(characters.peek(), Some('^')) {
        characters.next();
    }
    while let Some(character) = characters.next() {
        if character == '$' && characters.peek().is_none() {
            break;
        }
        if character == '\\' {
            let Some(escaped) = characters.next() else {
                return Err(unsupported());
            };
            if !matches!(
                escaped,
                '\\' | '.' | '^' | '$' | '|' | '(' | ')' | '[' | ']' | '{' | '}'
            ) {
                return Ok(None);
            }
            literal.push(escaped);
        } else if matches!(
            character,
            '.' | '*' | '+' | '?' | '{' | '}' | '[' | ']' | '(' | ')' | '|'
        ) {
            return Ok(None);
        } else {
            literal.push(character);
        }
    }
    if literal.is_empty() {
        Ok(None)
    } else {
        Ok(Some(literal))
    }
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

        let empty_match = BoundedRegex::new("^$".to_owned()).expect("regex is valid");
        assert!(empty_match.has_literal_candidate(""));
        assert!(empty_match.is_match(""));
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
