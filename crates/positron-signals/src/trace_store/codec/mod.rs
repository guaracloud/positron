//! Versioned native Trace Store Block codec.

mod bounds;
mod decode;
mod encode;
mod format;
#[cfg(test)]
mod tests;

pub(super) use bounds::decoded_memory_bound;
pub(super) use decode::BlockDecode;
pub(super) use encode::encode_block;
pub(super) use format::MAX_RECORDS;

#[cfg(test)]
pub(super) use bounds::preflight_policy;
#[cfg(test)]
pub(super) use decode::Input;
#[cfg(test)]
pub(super) use decode::decode_observation;
#[cfg(fuzzing)]
pub(super) use decode::{decode_observation, decode_observation_version};
#[cfg(test)]
pub(super) use encode::put_slice;
#[cfg(test)]
pub(super) use format::{
    MAX_BLOCK_BYTES, check_cancel, decode_kind, decode_namespace, decode_quality, decode_sampling,
    kind_tag, namespace_index, namespace_tag, quality_tag, sampling_tag,
};

pub(super) const DECODED_RECORD_SLOT_BYTES: u64 = 512;
pub(super) const DECODED_VECTOR_SLOT_BYTES: u64 = 64;
pub(super) const DECODED_KEY_VALUE_SLOT_BYTES: u64 = 96;
