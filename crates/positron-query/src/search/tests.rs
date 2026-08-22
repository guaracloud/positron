use super::{
    BoundedRegex, MAX_SEARCH_LITERAL_BYTES, SearchObserver, UnobservedSearch, contains_observed,
    search_text,
};
use crate::QueryFailureCode;

struct CancellingObserver {
    chunks_left: usize,
}

impl SearchObserver for CancellingObserver {
    fn observe_search_structure(&mut self) -> Result<(), crate::QueryFailure> {
        Ok(())
    }

    fn observe_search_chunk(&mut self) -> Result<(), crate::QueryFailure> {
        if self.chunks_left == 0 {
            Err(crate::QueryFailure::new(QueryFailureCode::Cancelled))
        } else {
            self.chunks_left -= 1;
            Ok(())
        }
    }
}

#[test]
fn bounded_regex_matches_literal_and_dynamic_patterns() {
    let anchored = BoundedRegex::new("^error-42$".to_owned()).expect("regex is valid");
    assert!(anchored.is_match("error-42"));
    assert!(!anchored.is_match("error-41"));

    let escaped = BoundedRegex::new(r"error\|42".to_owned()).expect("regex is valid");
    assert!(escaped.is_match("error|42"));

    let dynamic = BoundedRegex::new(r"error-\d+".to_owned()).expect("regex is valid");
    assert!(dynamic.pruning_literals().is_empty());
    assert!(dynamic.is_match("error-42"));
    assert_eq!(
        anchored,
        BoundedRegex::new("^error-42$".to_owned()).expect("regex is valid")
    );
    assert_ne!(anchored, dynamic);

    let empty_match = BoundedRegex::new("^$".to_owned()).expect("regex is valid");
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

    let boundary = BoundedRegex::new(r"(?-u:\bquux\b)".to_owned()).expect("regex is valid");
    assert_eq!(boundary.pruning_literals(), [b"quux".to_vec()]);
}

#[test]
fn automaton_matches_known_patterns_and_bodies() {
    let cases = [
        (r"error-\d+", "error-42", true),
        (r"error-\d+", "error-x", false),
        (r".*foobar", "prefix foobar", true),
        (r".*foobar", "prefix foo", false),
        (r"a|foobar", "a", true),
        (r"a|foobar", "quux", false),
        (r"(?-u:\bquux\b)", "quux", true),
        (r"(?-u:\bquux\b)", "quuxword", false),
        (r"(foo|bar)[0-9]+", "foo123", true),
        (r"(foo|bar)[0-9]+", "foo", false),
        (r"foo.*bar", "foo and bar", true),
        (r"foo.*bar", "bar and foo", false),
        (r"привет|hello", "привет мир", true),
        (r"привет|hello", "goodbye", false),
    ];
    for (pattern, body, expected) in cases {
        let regex = BoundedRegex::new(pattern.to_owned()).expect("bounded regex");
        assert_eq!(
            regex.is_match(body),
            expected,
            "pattern {pattern:?}, body {body:?}"
        );
    }
}

#[test]
fn truncated_extraction_falls_back_instead_of_using_inexact_literals() {
    let regex = BoundedRegex::new(r"[ab]{8}".to_owned()).expect("bounded regex");
    assert!(regex.pruning_literals().is_empty());
    assert!(regex.is_match("bbbbbbbb"));
}

#[test]
fn extracted_literals_remain_conservative_pruning_proofs() {
    let cases = [
        (r"error-\d+", "error-42"),
        (r".*foobar", "prefix foobar suffix"),
        (r"a|foobar", "foobar"),
        (r"(?-u:\bquux\b)", "quux"),
        (r"(foo|bar)[0-9]+", "bar9"),
        (r"foo.*bar", "foo and bar"),
        (r"привет|hello", "привет мир"),
    ];
    for (pattern, body) in cases {
        let regex = BoundedRegex::new(pattern.to_owned()).expect("bounded regex");
        assert!(regex.is_match(body));
        assert!(
            regex.pruning_literals().is_empty()
                || regex.pruning_literals().iter().any(|literal| body
                    .as_bytes()
                    .windows(literal.len())
                    .any(|window| window == literal))
        );
    }
}

#[test]
fn substring_matching_preserves_state_across_payload_chunks() {
    let chunk = positron_domain::value::NATIVE_VALUE_PAYLOAD_CHUNK_BYTES;
    let body = format!("{}needle", "x".repeat(chunk - 2));
    let mut observer = UnobservedSearch;
    assert!(contains_observed(&body, "needle", &mut observer).expect("substring succeeds"));
    assert!(!contains_observed(&body, "needles", &mut observer).expect("substring succeeds"));
    assert!(contains_observed(&body, "", &mut observer).expect("empty substring succeeds"));
}

#[test]
fn matching_polls_cancellation_between_body_chunks() {
    let body = "x".repeat(2_048);
    let regex = BoundedRegex::new("needle".to_owned()).expect("bounded regex");
    let mut regex_observer = CancellingObserver { chunks_left: 1 };
    assert_eq!(
        regex
            .is_match_observed(&body, &mut regex_observer)
            .expect_err("regex should observe cancellation"),
        crate::QueryFailure::new(QueryFailureCode::Cancelled)
    );

    let mut substring_observer = CancellingObserver { chunks_left: 1 };
    assert_eq!(
        contains_observed(&body, "needle", &mut substring_observer)
            .expect_err("substring should observe cancellation"),
        crate::QueryFailure::new(QueryFailureCode::Cancelled)
    );
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
        BoundedRegex::new(r"\bquux\b".to_owned())
            .expect_err("Unicode word boundaries are not DFA-safe")
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
