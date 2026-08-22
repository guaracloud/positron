use regex_automata::Input;
use regex_automata::dfa::{Automaton, StartKind, dense};
use regex_syntax::hir::literal::{ExtractKind, Extractor};

use crate::{QueryFailure, QueryFailureCode};

/// Search expressions are deliberately much smaller than a log body. This
/// keeps parsing, compilation, and the authenticated query plan bounded even
/// when the body limit is raised independently.
pub(crate) const MAX_SEARCH_LITERAL_BYTES: usize = 1_024;
const MAX_SEARCH_LITERAL_COUNT: usize = 32;
const MAX_REGEX_COMPILED_BYTES: usize = 64 * 1024;
const MAX_REGEX_NESTING: u32 = 32;
const MAX_REGEX_BUILD_BYTES: usize = MAX_REGEX_COMPILED_BYTES * 2;
const MAX_SEARCH_SCRATCH_BYTES: usize =
    std::mem::size_of::<Vec<usize>>() + MAX_SEARCH_LITERAL_BYTES * std::mem::size_of::<usize>();

pub(crate) trait SearchObserver {
    fn observe_search_structure(&mut self) -> Result<(), QueryFailure>;

    fn observe_search_chunk(&mut self) -> Result<(), QueryFailure>;
}

const fn max_candidate_memory_bytes() -> u64 {
    (std::mem::size_of::<Vec<Vec<u8>>>()
        + MAX_SEARCH_LITERAL_COUNT * (std::mem::size_of::<Vec<u8>>() + MAX_SEARCH_LITERAL_BYTES))
        as u64
}

#[derive(Clone, Debug)]
pub(crate) struct BoundedRegex {
    source: String,
    compiled: Box<dense::DFA<Vec<u32>>>,
    pruning_literals: Vec<Vec<u8>>,
}

impl BoundedRegex {
    pub(crate) fn new(source: String) -> Result<Self, QueryFailure> {
        if source.is_empty() || source.len() > MAX_SEARCH_LITERAL_BYTES {
            return Err(unsupported());
        }
        let mut builder = dense::Builder::new();
        builder
            .configure(
                dense::Config::new()
                    .start_kind(StartKind::Unanchored)
                    // Unicode word boundaries require quit-state handling
                    // that is not part of this static stepping loop. ASCII
                    // boundaries remain available through (?-u:\b...).
                    .unicode_word_boundary(false)
                    .dfa_size_limit(Some(MAX_REGEX_COMPILED_BYTES))
                    .determinize_size_limit(Some(MAX_REGEX_COMPILED_BYTES)),
            )
            .syntax(
                regex_automata::util::syntax::Config::new()
                    .unicode(true)
                    .nest_limit(MAX_REGEX_NESTING),
            );
        let compiled = builder.build(&source).map_err(|_| unsupported())?;
        let pruning_literals = mandatory_literals(&source)?;
        Ok(Self {
            source,
            compiled: Box::new(compiled),
            pruning_literals,
        })
    }

    #[cfg(test)]
    pub(crate) fn is_match(&self, text: &str) -> bool {
        let mut observer = UnobservedSearch;
        self.is_match_observed(text, &mut observer)
            .is_ok_and(|matched| matched)
    }

    pub(crate) fn is_match_observed<O: SearchObserver>(
        &self,
        text: &str,
        observer: &mut O,
    ) -> Result<bool, QueryFailure> {
        observer.observe_search_structure()?;
        let input = Input::new(text.as_bytes());
        let mut state = self
            .compiled
            .start_state_forward(&input)
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        for chunk in text
            .as_bytes()
            .chunks(positron_domain::value::NATIVE_VALUE_PAYLOAD_CHUNK_BYTES)
        {
            observer.observe_search_chunk()?;
            for &byte in chunk {
                state = self.compiled.next_state(state, byte);
                if self.compiled.is_match_state(state) {
                    return Ok(true);
                }
            }
        }
        state = self.compiled.next_eoi_state(state);
        Ok(self.compiled.is_match_state(state))
    }

    pub(crate) fn pruning_literals(&self) -> &[Vec<u8>] {
        &self.pruning_literals
    }

    pub(crate) fn memory_bytes(&self) -> u64 {
        let automaton = match u64::try_from(self.compiled.memory_usage()) {
            Ok(bytes) => bytes.saturating_add(std::mem::size_of::<dense::DFA<Vec<u32>>>() as u64),
            Err(_) => return u64::MAX,
        };
        automaton
            .saturating_add(MAX_REGEX_BUILD_BYTES as u64)
            .saturating_add(MAX_SEARCH_LITERAL_BYTES as u64)
            .saturating_add(max_candidate_memory_bytes())
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
    (MAX_SEARCH_LITERAL_BYTES + MAX_SEARCH_SCRATCH_BYTES) as u64 + max_candidate_memory_bytes()
}

pub(crate) fn contains_observed<O: SearchObserver>(
    text: &str,
    pattern: &str,
    observer: &mut O,
) -> Result<bool, QueryFailure> {
    observer.observe_search_structure()?;
    let pattern = pattern.as_bytes();
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(pattern.len())
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    prefix.resize(pattern.len(), 0);
    let mut matched = 0;
    for index in 1..pattern.len() {
        while matched > 0 && pattern[index] != pattern[matched] {
            matched = prefix[matched - 1];
        }
        if pattern[index] == pattern[matched] {
            matched += 1;
        }
        prefix[index] = matched;
    }
    if pattern.is_empty() {
        return Ok(true);
    }
    for chunk in text
        .as_bytes()
        .chunks(positron_domain::value::NATIVE_VALUE_PAYLOAD_CHUNK_BYTES)
    {
        observer.observe_search_chunk()?;
        for &byte in chunk {
            while matched > 0 && byte != pattern[matched] {
                matched = prefix[matched - 1];
            }
            if byte == pattern[matched] {
                matched += 1;
                if matched == pattern.len() {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
struct UnobservedSearch;

#[cfg(test)]
impl SearchObserver for UnobservedSearch {
    fn observe_search_structure(&mut self) -> Result<(), QueryFailure> {
        Ok(())
    }

    fn observe_search_chunk(&mut self) -> Result<(), QueryFailure> {
        Ok(())
    }
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
mod tests;
