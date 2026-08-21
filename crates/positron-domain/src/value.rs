//! Bounded native dynamic attribute values.

include!("value/namespace_limits.rs");
include!("value/profiles.rs");
include!("value/candidates.rs");
include!("value/validated.rs");
include!("value/occurrences.rs");

mod observed;
mod observed_encoding;
mod validated_encoding;

pub use observed::{NATIVE_VALUE_PAYLOAD_CHUNK_BYTES, NativeValueObserver, ObservedValueFailure};
use validated_encoding::visit_comparison_sequence;

#[cfg(test)]
mod tests;
