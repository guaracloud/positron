//! Bounded native dynamic attribute values.

include!("value/namespace_limits.rs");
include!("value/profiles.rs");
include!("value/candidates.rs");
include!("value/validated.rs");
include!("value/occurrences.rs");

#[cfg(test)]
mod tests;
