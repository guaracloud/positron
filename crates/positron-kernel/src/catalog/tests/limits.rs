use super::super::{MAX_GENERATIONS, MAX_RETAINED_HISTORY_BYTES, reserve_history};
use crate::{CatalogFailureCode, CatalogSecret};

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
        CatalogSecret::from_owned_at_epoch(Box::new([1; 32]), [0; 16], 1)
            .expect_err("the zero provider reference is reserved")
            .code(),
        CatalogFailureCode::InvalidInput
    );
    assert_eq!(
        CatalogSecret::from_owned_at_epoch(Box::new([1; 32]), [1; 16], 0)
            .expect_err("the zero root-key epoch is reserved")
            .code(),
        CatalogFailureCode::InvalidInput
    );
}
