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
