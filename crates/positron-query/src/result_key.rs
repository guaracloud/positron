use positron_domain::routing::{CommitPosition, RecordOrdinal};
use positron_domain::time::UnixNanoseconds;

use crate::{QueryFailure, QueryFailureCode, QueryRecord};

/// Fixed authenticated representation of the last delivered result.
///
/// The key deliberately contains no result offset or dynamic value. Raw rows
/// use the source identity as the stable frontier and a canonical result
/// digest to detect a changed projection. Aggregate rows use the canonical
/// group/result digest because synthetic rows do not have a source identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResultResumeKey {
    kind: ResultResumeKind,
    ordering_time: UnixNanoseconds,
    commit_position: CommitPosition,
    record_ordinal: RecordOrdinal,
    result_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResultResumeKind {
    Raw,
    Aggregate,
}

pub(crate) const RESULT_RESUME_KEY_BYTES: usize = 64;

impl ResultResumeKey {
    pub(crate) fn from_record(record: &QueryRecord, result_digest: [u8; 32]) -> Self {
        Self {
            kind: if record.count().is_some() {
                ResultResumeKind::Aggregate
            } else {
                ResultResumeKind::Raw
            },
            ordering_time: record.ordering_time(),
            commit_position: record.commit_position(),
            record_ordinal: record.record_ordinal(),
            result_digest,
        }
    }

    pub(crate) fn encode(self) -> [u8; RESULT_RESUME_KEY_BYTES] {
        let mut bytes = [0; RESULT_RESUME_KEY_BYTES];
        bytes[0] = match self.kind {
            ResultResumeKind::Raw => 1,
            ResultResumeKind::Aggregate => 2,
        };
        bytes[1..9].copy_from_slice(&self.ordering_time.value().to_be_bytes());
        bytes[9..17].copy_from_slice(&self.commit_position.value().to_be_bytes());
        bytes[17..19].copy_from_slice(&self.record_ordinal.value().to_be_bytes());
        bytes[19..51].copy_from_slice(&self.result_digest);
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>, QueryFailure> {
        if bytes.len() != RESULT_RESUME_KEY_BYTES {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        let tag = *bytes
            .first()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        if tag == 0 {
            if bytes.iter().skip(1).any(|byte| *byte != 0) {
                return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
            }
            return Ok(None);
        }
        let kind = match tag {
            1 => ResultResumeKind::Raw,
            2 => ResultResumeKind::Aggregate,
            _ => return Err(QueryFailure::new(QueryFailureCode::InvalidCursor)),
        };
        if bytes[51..].iter().any(|byte| *byte != 0) {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        let ordering_time = i64::from_be_bytes(
            bytes
                .get(1..9)
                .and_then(|value| value.try_into().ok())
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?,
        );
        let commit_position = u64::from_be_bytes(
            bytes
                .get(9..17)
                .and_then(|value| value.try_into().ok())
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?,
        );
        let record_ordinal = u16::from_be_bytes(
            bytes
                .get(17..19)
                .and_then(|value| value.try_into().ok())
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?,
        );
        let record_ordinal = RecordOrdinal::new(record_ordinal)
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        let result_digest = bytes
            .get(19..51)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        let commit_position = match std::num::NonZeroU64::new(commit_position) {
            Some(value) => CommitPosition::origin()
                .advance_by(value)
                .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?,
            None => CommitPosition::origin(),
        };
        Ok(Some(Self {
            kind,
            ordering_time: UnixNanoseconds::new(ordering_time),
            commit_position,
            record_ordinal,
            result_digest,
        }))
    }

    pub(crate) fn matches_record(&self, record: &QueryRecord, result_digest: [u8; 32]) -> bool {
        let kind_matches = match self.kind {
            ResultResumeKind::Raw => record.count().is_none(),
            ResultResumeKind::Aggregate => record.count().is_some(),
        };
        kind_matches
            && (self.kind == ResultResumeKind::Aggregate
                || (self.ordering_time == record.ordering_time()
                    && self.commit_position == record.commit_position()
                    && self.record_ordinal == record.record_ordinal()))
            && self.result_digest == result_digest
    }

    pub(crate) const fn is_aggregate(self) -> bool {
        matches!(self.kind, ResultResumeKind::Aggregate)
    }
}
