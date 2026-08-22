use regex_automata::Input;
use regex_automata::dfa::{Automaton, StartKind, dense};
use regex_automata::nfa::thompson;
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
const REGEX_COMPILE_WORK_QUANTUM_BYTES: usize = 32 * 1024;
const SUBSTRING_COMPILE_WORK_QUANTUM_BYTES: usize = MAX_SEARCH_LITERAL_BYTES;
const MAX_SUBSTRING_PREFIX_BYTES: usize = MAX_SEARCH_LITERAL_BYTES * std::mem::size_of::<usize>();
const MAX_SEARCH_SCRATCH_BYTES: usize =
    std::mem::size_of::<Vec<usize>>() + MAX_SUBSTRING_PREFIX_BYTES;

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
    compiled: Option<Box<dense::DFA<Vec<u32>>>>,
    pruning_literals: Option<Vec<Vec<u8>>>,
}

/// A bounded, plan-owned substring matcher.
///
/// Parsing retains only the bounded source.  The prefix table is compiled once
/// after query admission and reused for every decoded record, so record
/// matching performs no preprocessing allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundedSubstring {
    source: String,
    prefix: Option<Box<[usize]>>,
}

impl BoundedSubstring {
    pub(crate) fn from_source(source: String) -> Result<Self, QueryFailure> {
        if source.is_empty() || source.len() > MAX_SEARCH_LITERAL_BYTES {
            return Err(unsupported());
        }
        Ok(Self {
            source,
            prefix: None,
        })
    }

    pub(crate) fn compile(&mut self) -> Result<(), QueryFailure> {
        if self.prefix.is_some() {
            return Ok(());
        }
        let pattern = self.source.as_bytes();
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
        self.prefix = Some(prefix.into_boxed_slice());
        Ok(())
    }

    /// Conservative one-quantum compile work bound.  This covers the full
    /// bounded prefix-table build once during planning, never per record.
    pub(crate) fn compile_work_units(&self) -> u64 {
        self.source
            .len()
            .div_ceil(SUBSTRING_COMPILE_WORK_QUANTUM_BYTES) as u64
    }

    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    #[cfg(test)]
    pub(crate) fn prefix_len(&self) -> usize {
        self.prefix.as_ref().map_or(0, |prefix| prefix.len())
    }

    pub(crate) fn is_match_observed<O: SearchObserver>(
        &self,
        text: &str,
        observer: &mut O,
    ) -> Result<bool, QueryFailure> {
        observer.observe_search_structure()?;
        let pattern = self.source.as_bytes();
        let prefix = self
            .prefix
            .as_ref()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let mut matched = 0;
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
}

impl BoundedRegex {
    #[cfg(test)]
    pub(crate) fn new(source: String) -> Result<Self, QueryFailure> {
        let mut regex = Self::from_source(source)?;
        regex.compile()?;
        Ok(regex)
    }

    pub(crate) fn from_source(source: String) -> Result<Self, QueryFailure> {
        if source.is_empty() || source.len() > MAX_SEARCH_LITERAL_BYTES {
            return Err(unsupported());
        }
        Ok(Self {
            source,
            compiled: None,
            pruning_literals: None,
        })
    }

    pub(crate) fn compile(&mut self) -> Result<(), QueryFailure> {
        if self.compiled.is_some() {
            return Ok(());
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
            )
            .thompson(thompson::Config::new().nfa_size_limit(Some(MAX_REGEX_COMPILED_BYTES)));
        let compiled = builder.build(&self.source).map_err(|_| unsupported())?;
        let pruning_literals = mandatory_literals(&self.source)?;
        self.compiled = Some(Box::new(compiled));
        self.pruning_literals = Some(pruning_literals);
        Ok(())
    }

    /// Conservative deterministic parse work for the bounded compiler. Each
    /// unit admits one fixed 32-KiB source/program quantum plus one nesting
    /// quantum, covering the complete configured source and DFA/NFA limits
    /// before the compiler is allowed to allocate.
    pub(crate) fn compile_work_units(&self) -> u64 {
        let source_quanta = self.source.len().div_ceil(REGEX_COMPILE_WORK_QUANTUM_BYTES);
        let program_quanta = MAX_REGEX_COMPILED_BYTES.div_ceil(REGEX_COMPILE_WORK_QUANTUM_BYTES);
        let nesting_quanta = 1_usize;
        (source_quanta + program_quanta + nesting_quanta) as u64
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
        let compiled = self
            .compiled
            .as_ref()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let input = Input::new(text.as_bytes());
        let mut state = compiled
            .start_state_forward(&input)
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        for chunk in text
            .as_bytes()
            .chunks(positron_domain::value::NATIVE_VALUE_PAYLOAD_CHUNK_BYTES)
        {
            observer.observe_search_chunk()?;
            for &byte in chunk {
                state = compiled.next_state(state, byte);
                if compiled.is_match_state(state) {
                    return Ok(true);
                }
            }
        }
        state = compiled.next_eoi_state(state);
        Ok(compiled.is_match_state(state))
    }

    pub(crate) fn pruning_literals(&self) -> &[Vec<u8>] {
        self.pruning_literals.as_deref().unwrap_or_default()
    }

    pub(crate) fn memory_bytes(&self) -> u64 {
        let automaton = self
            .compiled
            .as_ref()
            .and_then(|compiled| u64::try_from(compiled.memory_usage()).ok())
            .map_or(MAX_REGEX_COMPILED_BYTES as u64, |bytes| {
                bytes.saturating_add(std::mem::size_of::<dense::DFA<Vec<u32>>>() as u64)
            });
        automaton
            .saturating_add(MAX_REGEX_BUILD_BYTES as u64)
            .saturating_add(MAX_SEARCH_LITERAL_BYTES as u64)
            .saturating_add(max_candidate_memory_bytes())
    }
}

pub(crate) const fn regex_peak_memory_bytes() -> u64 {
    (MAX_REGEX_COMPILED_BYTES
        + MAX_REGEX_BUILD_BYTES
        + MAX_SEARCH_LITERAL_BYTES
        + std::mem::size_of::<dense::DFA<Vec<u32>>>()
        + max_candidate_memory_bytes() as usize) as u64
}

impl PartialEq for BoundedRegex {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for BoundedRegex {}

pub(crate) fn search_text(source: String) -> Result<BoundedSubstring, QueryFailure> {
    BoundedSubstring::from_source(source)
}

pub(crate) const fn text_memory_bytes() -> u64 {
    (MAX_SEARCH_LITERAL_BYTES + MAX_SEARCH_SCRATCH_BYTES) as u64 + max_candidate_memory_bytes()
}

#[cfg(any(test, fuzzing))]
pub(crate) struct UnobservedSearch;

#[cfg(any(test, fuzzing))]
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
        // A prefix/suffix sequence with alternatives does not establish that
        // any one literal occurs in every match. Keep physical evidence only
        // when the extractor proves one exact mandatory literal; otherwise
        // the authenticated decoder remains the conservative path.
        if literals.len() != 1
            || literals.iter().any(|literal| {
                !literal.is_exact()
                    || literal.len() < 3
                    || std::str::from_utf8(literal.as_bytes()).is_err()
            })
        {
            continue;
        }
        let literal = literals
            .first()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let bytes = literal.as_bytes();
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        owned.extend_from_slice(bytes);
        return Ok(vec![owned]);
    }
    Ok(Vec::new())
}

const fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}

#[cfg(test)]
mod tests;
