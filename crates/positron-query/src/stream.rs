mod contract;
mod events;

pub(crate) use contract::column_type;
pub use contract::{
    QueryHeader, ResultLease, ResultOrdering, ResultSchema, ResultSnapshot, ResultValueType,
};
pub(crate) use events::QueryCounters;
pub use events::{QueryBatch, QueryEvent, QueryIncomplete, QueryStats, QueryTerminal};

use positron_domain::routing::{CommitPosition, RecordOrdinal};
use positron_domain::time::{EventTime, QueryTime, UnixNanoseconds};
use positron_kernel::IngestTime;

use crate::{QueryFailure, QueryFailureCode};

const INTERNAL: QueryFailure = QueryFailure::new(QueryFailureCode::Internal);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryRecord {
    body: Option<positron_domain::value::ValidatedAttributeValue>,
    body_retained_bytes: u64,
    body_selected: bool,
    query_time: Option<QueryTime>,
    event_time: Option<EventTime>,
    ingest_time: Option<IngestTime>,
    ordering_time: UnixNanoseconds,
    commit_position: CommitPosition,
    record_ordinal: RecordOrdinal,
    query_time_selected: bool,
    event_time_selected: bool,
    ingest_time_selected: bool,
    commit_position_selected: bool,
    count: Option<u64>,
    attributes: Vec<AttributeProjection>,
    attribute_retained_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AttributeProjection {
    Intrinsic,
    Attribute(Option<positron_domain::value::AttributeOccurrenceSet>),
}

pub(crate) struct QueryRecordTimes {
    pub(crate) query: QueryTime,
    pub(crate) event: EventTime,
    pub(crate) ingest: IngestTime,
    pub(crate) ordering: UnixNanoseconds,
}

pub(crate) struct QueryRecordSelection {
    pub(crate) body: bool,
    pub(crate) query_time: bool,
    pub(crate) event_time: bool,
    pub(crate) ingest_time: bool,
    pub(crate) commit_position: bool,
    pub(crate) attributes: Vec<AttributeProjection>,
    pub(crate) attribute_retained_bytes: u64,
}

pub(crate) struct QueryGroupFields {
    pub(crate) body: Option<positron_domain::value::ValidatedAttributeValue>,
    pub(crate) body_retained_bytes: u64,
    pub(crate) query_time: QueryTime,
    pub(crate) event_time: EventTime,
    pub(crate) ingest_time: IngestTime,
    pub(crate) commit_position: CommitPosition,
    pub(crate) attributes: Vec<AttributeProjection>,
    pub(crate) attribute_retained_bytes: u64,
}

pub(crate) struct GroupedCountFields {
    pub(crate) body: Option<positron_domain::value::ValidatedAttributeValue>,
    pub(crate) body_retained_bytes: u64,
    pub(crate) body_selected: bool,
    pub(crate) query_time: Option<QueryTime>,
    pub(crate) event_time: Option<EventTime>,
    pub(crate) ingest_time: Option<IngestTime>,
    pub(crate) commit_position: Option<CommitPosition>,
    pub(crate) attributes: Vec<AttributeProjection>,
    pub(crate) attribute_retained_bytes: u64,
}

impl QueryRecord {
    pub(crate) fn new(
        body: Option<positron_domain::value::ValidatedAttributeValue>,
        body_retained_bytes: u64,
        times: QueryRecordTimes,
        commit_position: CommitPosition,
        record_ordinal: RecordOrdinal,
        selection: QueryRecordSelection,
    ) -> Self {
        Self {
            body,
            body_retained_bytes,
            body_selected: selection.body,
            query_time: Some(times.query),
            event_time: Some(times.event),
            ingest_time: Some(times.ingest),
            ordering_time: times.ordering,
            commit_position,
            record_ordinal,
            query_time_selected: selection.query_time,
            event_time_selected: selection.event_time,
            ingest_time_selected: selection.ingest_time,
            commit_position_selected: selection.commit_position,
            count: None,
            attributes: selection.attributes,
            attribute_retained_bytes: selection.attribute_retained_bytes,
        }
    }

    pub(crate) const fn count_record(count: u64) -> Self {
        Self {
            body: None,
            body_retained_bytes: 0,
            body_selected: false,
            query_time: None,
            event_time: None,
            ingest_time: None,
            ordering_time: UnixNanoseconds::new(0),
            commit_position: CommitPosition::origin(),
            record_ordinal: RecordOrdinal::first(),
            query_time_selected: false,
            event_time_selected: false,
            ingest_time_selected: false,
            commit_position_selected: false,
            count: Some(count),
            attributes: Vec::new(),
            attribute_retained_bytes: 0,
        }
    }

    pub(crate) fn grouped_count_record(fields: GroupedCountFields, count: u64) -> Self {
        Self {
            body: fields.body,
            body_retained_bytes: fields.body_retained_bytes,
            body_selected: fields.body_selected,
            query_time: fields.query_time,
            event_time: fields.event_time,
            ingest_time: fields.ingest_time,
            ordering_time: UnixNanoseconds::new(0),
            commit_position: fields
                .commit_position
                .unwrap_or_else(CommitPosition::origin),
            record_ordinal: RecordOrdinal::first(),
            query_time_selected: fields.query_time.is_some(),
            event_time_selected: fields.event_time.is_some(),
            ingest_time_selected: fields.ingest_time.is_some(),
            commit_position_selected: fields.commit_position.is_some(),
            count: Some(count),
            attributes: fields.attributes,
            attribute_retained_bytes: fields.attribute_retained_bytes,
        }
    }

    #[must_use]
    pub fn body_text(&self) -> Option<&str> {
        self.body.as_ref().and_then(|body| body.as_str())
    }
    #[must_use]
    pub const fn body_value(&self) -> Option<&positron_domain::value::ValidatedAttributeValue> {
        self.body.as_ref()
    }
    #[must_use]
    pub fn attribute_occurrence_set(
        &self,
        column: usize,
    ) -> Option<&positron_domain::value::AttributeOccurrenceSet> {
        match self.attributes.get(column) {
            Some(AttributeProjection::Attribute(value)) => value.as_ref(),
            Some(AttributeProjection::Intrinsic) | None => None,
        }
    }
    #[must_use]
    pub const fn query_time(&self) -> UnixNanoseconds {
        match self.query_time {
            Some(value) => value.instant(),
            None => UnixNanoseconds::new(0),
        }
    }
    #[must_use]
    pub const fn query_time_value(&self) -> Option<QueryTime> {
        self.query_time
    }
    #[must_use]
    pub const fn event_time(&self) -> Option<UnixNanoseconds> {
        match self.event_time {
            Some(value) => value.instant(),
            None => None,
        }
    }
    #[must_use]
    pub const fn event_time_value(&self) -> Option<EventTime> {
        self.event_time
    }
    #[must_use]
    pub const fn ingest_time_value(&self) -> Option<IngestTime> {
        self.ingest_time
    }
    #[must_use]
    pub const fn commit_position(&self) -> CommitPosition {
        self.commit_position
    }
    #[must_use]
    pub const fn record_ordinal(&self) -> RecordOrdinal {
        self.record_ordinal
    }
    #[must_use]
    pub const fn count(&self) -> Option<u64> {
        self.count
    }

    pub(crate) fn emitted_size_bytes(&self) -> Result<u64, QueryFailure> {
        let body_bytes = if self.body_selected {
            let encoded = self
                .body
                .as_ref()
                .map_or(Ok(0), |body| body.canonical_encoded_size_bytes())
                .map_err(crate::execution_support::map_domain_value_failure)?;
            u64::try_from(encoded)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(INTERNAL)?
        } else {
            0
        };
        let query_time_bytes = if self.query_time_selected {
            self.query_time.ok_or(INTERNAL)?;
            9
        } else {
            0
        };
        let event_time_bytes = if self.event_time_selected {
            let value = self.event_time.ok_or(INTERNAL)?;
            2 + u64::from(value.instant().is_some()) * 8
        } else {
            0
        };
        let ingest_time_bytes = if self.ingest_time_selected {
            self.ingest_time.ok_or(INTERNAL)?;
            8
        } else {
            0
        };
        let attribute_bytes = self.attributes.iter().try_fold(0_u64, |total, projected| {
            let AttributeProjection::Attribute(value) = projected else {
                return Ok(total);
            };
            let encoded = value
                .as_ref()
                .map_or(Ok(0), |set| set.canonical_encoded_size_bytes())
                .map_err(crate::execution_support::map_domain_value_failure)?;
            total
                .checked_add(1)
                .and_then(|value| value.checked_add(u64::try_from(encoded).ok()?))
                .ok_or(INTERNAL)
        })?;
        body_bytes
            .checked_add(query_time_bytes)
            .and_then(|value| value.checked_add(event_time_bytes))
            .and_then(|value| value.checked_add(ingest_time_bytes))
            .and_then(|value| value.checked_add(u64::from(self.commit_position_selected) * 8))
            .and_then(|value| value.checked_add(u64::from(self.count.is_some()) * 8))
            .and_then(|value| value.checked_add(attribute_bytes))
            .ok_or(INTERNAL)
    }

    pub(crate) const fn order_key(&self) -> (UnixNanoseconds, CommitPosition, RecordOrdinal) {
        (
            self.ordering_time,
            self.commit_position,
            self.record_ordinal,
        )
    }
    pub(crate) const fn ordering_time(&self) -> UnixNanoseconds {
        self.ordering_time
    }
    pub(crate) fn retained_dynamic_bytes(&self) -> Result<u64, QueryFailure> {
        self.body_retained_bytes
            .checked_add(self.attribute_retained_bytes)
            .ok_or(INTERNAL)
    }
    pub(crate) fn into_group_fields(self) -> Result<QueryGroupFields, QueryFailure> {
        Ok(QueryGroupFields {
            body: self.body,
            body_retained_bytes: self.body_retained_bytes,
            query_time: self.query_time.ok_or(INTERNAL)?,
            event_time: self.event_time.ok_or(INTERNAL)?,
            ingest_time: self.ingest_time.ok_or(INTERNAL)?,
            commit_position: self.commit_position,
            attributes: self.attributes,
            attribute_retained_bytes: self.attribute_retained_bytes,
        })
    }
    pub(crate) const fn query_time_selected(&self) -> bool {
        self.query_time_selected
    }
    pub(crate) const fn event_time_selected(&self) -> bool {
        self.event_time_selected
    }
    pub(crate) const fn ingest_time_selected(&self) -> bool {
        self.ingest_time_selected
    }
    pub(crate) fn attribute_projections(&self) -> &[AttributeProjection] {
        &self.attributes
    }
}
