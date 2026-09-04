use positron_domain::value::AttributeNamespace;

use super::super::details::SpanStatusCode;
use super::super::failure::TraceStoreFailure;
use super::super::observation::{SamplingDecision, SpanKind};
use crate::ScanCancellation;

pub(crate) const MAGIC: &[u8; 8] = b"PTRCBL01";
pub(crate) const LEGACY_VERSION: u16 = 1;
pub(crate) const VERSION: u16 = 2;
pub(crate) const MAX_RECORDS: usize = 1_024;
pub(crate) const MAX_BLOCK_BYTES: usize = 1_048_576;

pub(crate) const fn supported_version(version: u16) -> bool {
    matches!(version, LEGACY_VERSION | VERSION)
}

pub(crate) const fn status_tag(status: SpanStatusCode) -> u8 {
    match status {
        SpanStatusCode::Unset => 0,
        SpanStatusCode::Ok => 1,
        SpanStatusCode::Error => 2,
    }
}

pub(crate) const fn decode_status_tag(
    tag: u8,
) -> Result<SpanStatusCode, super::super::failure::TraceStoreFailure> {
    match tag {
        0 => Ok(SpanStatusCode::Unset),
        1 => Ok(SpanStatusCode::Ok),
        2 => Ok(SpanStatusCode::Error),
        _ => Err(super::super::failure::TraceStoreFailure::malformed_block()),
    }
}

pub(crate) fn check_cancel(cancellation: &dyn ScanCancellation) -> Result<(), TraceStoreFailure> {
    if cancellation.is_cancelled() {
        Err(TraceStoreFailure::cancelled())
    } else {
        Ok(())
    }
}

pub(crate) fn quality_tag(quality: positron_domain::time::SourceTimeQuality) -> u8 {
    match quality {
        positron_domain::time::SourceTimeQuality::Usable => 1,
        positron_domain::time::SourceTimeQuality::Missing => 2,
        positron_domain::time::SourceTimeQuality::Zero => 3,
        positron_domain::time::SourceTimeQuality::Outlier => 4,
        positron_domain::time::SourceTimeQuality::Contradictory => 5,
    }
}

pub(crate) fn decode_quality(
    tag: u8,
) -> Result<positron_domain::time::SourceTimeQuality, TraceStoreFailure> {
    match tag {
        1 => Ok(positron_domain::time::SourceTimeQuality::Usable),
        2 => Ok(positron_domain::time::SourceTimeQuality::Missing),
        3 => Ok(positron_domain::time::SourceTimeQuality::Zero),
        4 => Ok(positron_domain::time::SourceTimeQuality::Outlier),
        5 => Ok(positron_domain::time::SourceTimeQuality::Contradictory),
        _ => Err(TraceStoreFailure::malformed_block()),
    }
}

pub(crate) fn namespace_tag(namespace: AttributeNamespace) -> Result<u8, TraceStoreFailure> {
    match namespace {
        AttributeNamespace::Resource => Ok(1),
        AttributeNamespace::InstrumentationScope => Ok(2),
        AttributeNamespace::Record => Ok(3),
        AttributeNamespace::Stream => Err(TraceStoreFailure::invalid_input()),
    }
}

pub(crate) fn decode_namespace(tag: u8) -> Result<AttributeNamespace, TraceStoreFailure> {
    match tag {
        1 => Ok(AttributeNamespace::Resource),
        2 => Ok(AttributeNamespace::InstrumentationScope),
        3 => Ok(AttributeNamespace::Record),
        _ => Err(TraceStoreFailure::malformed_block()),
    }
}

pub(crate) fn namespace_index(namespace: AttributeNamespace) -> Result<usize, TraceStoreFailure> {
    match namespace {
        AttributeNamespace::Resource => Ok(0),
        AttributeNamespace::InstrumentationScope => Ok(1),
        AttributeNamespace::Record => Ok(2),
        AttributeNamespace::Stream => Err(TraceStoreFailure::malformed_block()),
    }
}

pub(crate) fn kind_tag(kind: SpanKind) -> u8 {
    match kind {
        SpanKind::Unspecified => 0,
        SpanKind::Internal => 1,
        SpanKind::Server => 2,
        SpanKind::Client => 3,
        SpanKind::Producer => 4,
        SpanKind::Consumer => 5,
    }
}

pub(crate) fn decode_kind(tag: u8) -> Result<SpanKind, TraceStoreFailure> {
    match tag {
        0 => Ok(SpanKind::Unspecified),
        1 => Ok(SpanKind::Internal),
        2 => Ok(SpanKind::Server),
        3 => Ok(SpanKind::Client),
        4 => Ok(SpanKind::Producer),
        5 => Ok(SpanKind::Consumer),
        _ => Err(TraceStoreFailure::malformed_block()),
    }
}

pub(crate) fn sampling_tag(sampling: SamplingDecision) -> u8 {
    match sampling {
        SamplingDecision::Unknown => 0,
        SamplingDecision::NotSampled => 1,
        SamplingDecision::Sampled => 2,
    }
}

pub(crate) fn decode_sampling(tag: u8) -> Result<SamplingDecision, TraceStoreFailure> {
    match tag {
        0 => Ok(SamplingDecision::Unknown),
        1 => Ok(SamplingDecision::NotSampled),
        2 => Ok(SamplingDecision::Sampled),
        _ => Err(TraceStoreFailure::malformed_block()),
    }
}
