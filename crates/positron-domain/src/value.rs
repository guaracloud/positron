//! Bounded native dynamic attribute values.

include!("value/namespace_limits.rs");
include!("value/profiles.rs");
include!("value/candidates.rs");
include!("value/validated.rs");
include!("value/occurrences.rs");

mod validated_encoding;

use validated_encoding::visit_comparison_sequence;

#[cfg(test)]
mod tests;
