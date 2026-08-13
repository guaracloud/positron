use crate::data_protection::{
    FrameFailure, FrameFormatEpoch, FrameObjectContext, FrameObjectId, KeyEpoch,
};

use super::{FORMAT_EPOCH, LedgerFailure, LedgerFailureCode, SegmentId, SegmentScope};

pub(super) fn object_context(
    scope: SegmentScope,
    id: SegmentId,
) -> Result<FrameObjectContext, LedgerFailure> {
    Ok(FrameObjectContext::tenant_segment(
        scope.tenant,
        scope.signal,
        scope.shard,
        FrameObjectId::new(id.0).map_err(map_frame_failure)?,
        KeyEpoch::new(1),
        FrameFormatEpoch::new(FORMAT_EPOCH).map_err(map_frame_failure)?,
    ))
}

pub(super) fn map_frame_failure(failure: FrameFailure) -> LedgerFailure {
    use crate::data_protection::FrameFailureCode as Code;
    let code = match failure.code() {
        Code::InvalidContext | Code::InvalidLimit => LedgerFailureCode::InvalidInput,
        Code::LimitExceeded => LedgerFailureCode::LimitExceeded,
        Code::SealFailed | Code::HashFailed | Code::EntropyUnavailable => {
            LedgerFailureCode::StorageUnavailable
        },
        Code::OpenFailed | Code::AuthenticationFailed => LedgerFailureCode::AuthenticationFailed,
        Code::MalformedFrame | Code::ChecksumMismatch => LedgerFailureCode::IntegrityCorruption,
        Code::UnsupportedVersion | Code::UnsupportedAlgorithm => {
            LedgerFailureCode::UnsupportedFormat
        },
    };
    LedgerFailure::new(code)
}
