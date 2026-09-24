use super::super::{MAX_GENERATIONS, MAX_RETAINED_HISTORY_BYTES, reserve_history};
use crate::{CatalogFailureCode, CatalogSecret, CatalogWrappingKey};

use super::super::{CatalogFailure, CatalogGenerationId};

#[test]
fn retained_history_admits_the_exact_boundary_and_refuses_the_next_byte() {
    assert_eq!(
        reserve_history(MAX_RETAINED_HISTORY_BYTES - 1, 1, 1)
            .expect("the exact retained-history boundary must remain recoverable"),
        MAX_RETAINED_HISTORY_BYTES
    );
    assert_eq!(
        reserve_history(MAX_RETAINED_HISTORY_BYTES, 1, 1)
            .expect_err("one byte beyond recoverable history must be refused")
            .code(),
        CatalogFailureCode::LimitExceeded
    );
    assert_eq!(
        reserve_history(0, 1, MAX_GENERATIONS as u64 + 1)
            .expect_err("one generation beyond the recoverable bound must be refused")
            .code(),
        CatalogFailureCode::LimitExceeded
    );
}

#[test]
fn root_key_routing_requires_nonzero_provider_and_epoch() {
    assert_eq!(
        CatalogSecret::from_owned_at_epoch(Box::new([2; 32]), Box::new([1; 32]), [0; 16], 1)
            .expect_err("the zero provider reference is reserved")
            .code(),
        CatalogFailureCode::InvalidInput
    );
    assert_eq!(
        CatalogSecret::from_owned_at_epoch(Box::new([2; 32]), Box::new([1; 32]), [1; 16], 0)
            .expect_err("the zero root-key epoch is reserved")
            .code(),
        CatalogFailureCode::InvalidInput
    );
    assert_eq!(
        CatalogSecret::from_owned_at_epoch(Box::new([2; 32]), Box::new([1; 32]), [0; 16], 1,)
            .expect_err("the explicit marker authority does not weaken routing validation")
            .code(),
        CatalogFailureCode::InvalidInput
    );

    let current =
        CatalogSecret::from_owned_at_epoch(Box::new([2; 32]), Box::new([1; 32]), [1; 16], 2)
            .expect("current route is valid");
    let non_predecessor = CatalogWrappingKey::from_owned_at_epoch(Box::new([2; 32]), [2; 16], 2)
        .expect("candidate route is valid");
    assert_eq!(
        current
            .with_predecessor(non_predecessor)
            .expect_err("a predecessor epoch must be older")
            .code(),
        CatalogFailureCode::InvalidInput
    );

    let wrapping = CatalogWrappingKey::from_owned_at_epoch(Box::new([3; 32]), [3; 16], 3)
        .expect("wrapping route is valid");
    assert_eq!(format!("{wrapping:?}"), "CatalogWrappingKey { <redacted> }");

    let stale = CatalogFailure::stale(CatalogGenerationId::ORIGIN);
    assert_eq!(stale.code(), CatalogFailureCode::StaleGeneration);
    assert_eq!(
        stale.current_generation(),
        Some(CatalogGenerationId::ORIGIN)
    );
}

#[test]
fn opaque_digest_is_domain_separated_and_refuses_an_ambiguous_input() {
    let secret = CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32]));
    let first = secret
        .opaque_digest(b"positron.test.binding.v1\0", b"first")
        .expect("bounded binding input is accepted");
    let same = secret
        .opaque_digest(b"positron.test.binding.v1\0", b"first")
        .expect("same binding input is stable");
    let different_domain = secret
        .opaque_digest(b"positron.test.other.v1\0", b"first")
        .expect("different domain is accepted");
    let first_split = secret
        .opaque_digest(b"a", b"bc")
        .expect("first split binding is accepted");
    let second_split = secret
        .opaque_digest(b"ab", b"c")
        .expect("second split binding is accepted");
    assert_eq!(first, same);
    assert_ne!(first, different_domain);
    assert_ne!(first_split, second_split);
    assert_eq!(
        secret
            .opaque_digest(b"", b"first")
            .expect_err("an unscoped private binding is ambiguous")
            .code(),
        CatalogFailureCode::InvalidInput
    );
}
