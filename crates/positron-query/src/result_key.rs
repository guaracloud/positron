use std::cmp::Ordering;

use positron_domain::routing::{CommitPosition, RecordOrdinal, VirtualShardId};
use positron_domain::time::UnixNanoseconds;

use crate::plan::{OrderDirection, OrderSpec};
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

    pub(crate) fn compare_ordering(self, other: Self, ordering: OrderSpec) -> Ordering {
        let primary = self.ordering_time.cmp(&other.ordering_time);
        let primary = match ordering.primary_direction() {
            OrderDirection::Ascending => primary,
            OrderDirection::Descending => primary.reverse(),
        };
        if primary != Ordering::Equal {
            return primary;
        }
        let commit = self.commit_position.cmp(&other.commit_position);
        let commit = match ordering.commit_direction() {
            OrderDirection::Ascending => commit,
            OrderDirection::Descending => commit.reverse(),
        };
        if commit != Ordering::Equal {
            return commit;
        }
        let ordinal = self.record_ordinal.cmp(&other.record_ordinal);
        match ordering.commit_direction() {
            OrderDirection::Ascending => ordinal,
            OrderDirection::Descending => ordinal.reverse(),
        }
    }
}

/// The bounded continuation for a canonical historical tail result.
///
/// The result key owns the query ordering fields and comparator. A source is
/// appended only to make otherwise equal records from different shards total.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalTotalKey {
    result: ResultResumeKey,
    source: VirtualShardId,
}

pub(crate) const HISTORICAL_TOTAL_KEY_BYTES: usize = RESULT_RESUME_KEY_BYTES + 4;

impl HistoricalTotalKey {
    pub(crate) fn from_record(record: &QueryRecord, source: VirtualShardId) -> Self {
        Self {
            result: ResultResumeKey::from_record(record, [0; 32]),
            source,
        }
    }

    pub(crate) fn compare(self, other: Self, ordering: OrderSpec) -> Ordering {
        self.result
            .compare_ordering(other.result, ordering)
            .then_with(|| self.source.cmp(&other.source))
    }

    pub(crate) fn encode(self) -> [u8; HISTORICAL_TOTAL_KEY_BYTES] {
        let mut bytes = [0; HISTORICAL_TOTAL_KEY_BYTES];
        bytes[..RESULT_RESUME_KEY_BYTES].copy_from_slice(&self.result.encode());
        bytes[RESULT_RESUME_KEY_BYTES..].copy_from_slice(&self.source.value().to_be_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>, QueryFailure> {
        if bytes.len() != HISTORICAL_TOTAL_KEY_BYTES {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        let result = ResultResumeKey::decode(
            bytes
                .get(..RESULT_RESUME_KEY_BYTES)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?,
        )?;
        let Some(result) = result else {
            return Ok(None);
        };
        let source = VirtualShardId::new(u32::from_be_bytes(
            bytes
                .get(RESULT_RESUME_KEY_BYTES..)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?
                .try_into()
                .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?,
        ))
        .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        Ok(Some(Self { result, source }))
    }
}

#[cfg(test)]
mod tests {
    use positron_domain::routing::VirtualShardId;

    use super::{
        HISTORICAL_TOTAL_KEY_BYTES, HistoricalTotalKey, RESULT_RESUME_KEY_BYTES, ResultResumeKey,
    };

    #[test]
    fn fixed_resume_key_rejects_short_empty_and_nonzero_reserved_bytes() {
        assert!(ResultResumeKey::decode(&[0; RESULT_RESUME_KEY_BYTES - 1]).is_err());

        let mut empty = [0; RESULT_RESUME_KEY_BYTES];
        empty[1] = 1;
        assert!(ResultResumeKey::decode(&empty).is_err());

        let mut encoded = [0; RESULT_RESUME_KEY_BYTES];
        encoded[0] = 1;
        encoded[18] = 1;
        assert!(ResultResumeKey::decode(&encoded).is_ok());
        encoded[51] = 1;
        assert!(ResultResumeKey::decode(&encoded).is_err());
    }

    #[test]
    fn fixed_resume_key_round_trips_both_result_kinds() {
        for kind in [1_u8, 2_u8] {
            let mut encoded = [0; RESULT_RESUME_KEY_BYTES];
            encoded[0] = kind;
            encoded[1..9].copy_from_slice(&(-7_i64).to_be_bytes());
            encoded[9..17].copy_from_slice(&1_u64.to_be_bytes());
            encoded[17..19].copy_from_slice(&1_u16.to_be_bytes());
            encoded[19..51].copy_from_slice(&[0x5a; 32]);
            let decoded = ResultResumeKey::decode(&encoded)
                .expect("canonical raw and aggregate keys must decode")
                .expect("tagged keys must carry a result frontier");
            assert_eq!(decoded.encode(), encoded);
        }
    }

    #[test]
    fn historical_total_key_round_trips_its_source_tiebreaker() {
        let record = crate::QueryRecord::count_record(1);
        let source = VirtualShardId::new(7).expect("valid source");
        let key = HistoricalTotalKey::from_record(&record, source);
        let bytes = key.encode();
        assert_eq!(bytes.len(), HISTORICAL_TOTAL_KEY_BYTES);
        assert_eq!(HistoricalTotalKey::decode(&bytes), Ok(Some(key)));
    }
}
