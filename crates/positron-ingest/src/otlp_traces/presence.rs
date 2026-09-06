//! Wire-presence metadata for OTLP timestamp scalars.
//!
//! Generated protobuf structs use scalar defaults, so decoding alone cannot
//! distinguish an omitted timestamp from an explicitly encoded zero. This
//! bounded adapter records that distinction before generated-message decode.

use super::TraceReceiveFailure;
use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::fmt;

const NO_FIELDS: &[(u64, u8)] = &[];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtlpTraceTimestampPresence {
    spans: Vec<SpanTimestampPresence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpanTimestampPresence {
    start: bool,
    end: bool,
    events: Vec<bool>,
}

impl OtlpTraceTimestampPresence {
    /// Scans a payload whose structural and semantic bounds were already
    /// validated by the receiver adapter.
    pub(crate) fn protobuf(bytes: &[u8]) -> Result<Self, TraceReceiveFailure> {
        let mut presence = Self { spans: Vec::new() };
        visit_request(bytes, &mut presence)?;
        Ok(presence)
    }

    /// Scans a payload whose structural and semantic bounds were already
    /// validated by the receiver adapter.
    pub(crate) fn json(bytes: &[u8]) -> Result<Self, TraceReceiveFailure> {
        let mut presence = Self { spans: Vec::new() };
        let mut collector = JsonPresenceCollector {
            presence: &mut presence,
            failure: None,
        };
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        deserializer.disable_recursion_limit();
        let parsed = deserializer.deserialize_any(JsonRootVisitor {
            collector: &mut collector,
        });
        if parsed.is_err() {
            return Err(collector
                .failure
                .unwrap_or(TraceReceiveFailure::MalformedPayload));
        }
        deserializer
            .end()
            .map_err(|_| TraceReceiveFailure::MalformedPayload)?;
        Ok(presence)
    }

    pub(crate) fn span(&self, ordinal: usize) -> Option<&SpanTimestampPresence> {
        self.spans.get(ordinal)
    }
}

struct JsonPresenceCollector<'presence> {
    presence: &'presence mut OtlpTraceTimestampPresence,
    failure: Option<TraceReceiveFailure>,
}

impl JsonPresenceCollector<'_> {
    fn fail<E: de::Error>(&mut self, failure: TraceReceiveFailure) -> E {
        self.failure = Some(failure);
        E::custom("OTLP Traces JSON timestamp presence allocation failed")
    }

    fn push_span<E: de::Error>(&mut self, span: SpanTimestampPresence) -> Result<(), E> {
        if self.presence.spans.try_reserve(1).is_err() {
            return Err(self.fail(TraceReceiveFailure::CapacityUnavailable));
        }
        self.presence.spans.push(span);
        Ok(())
    }
}

struct JsonRootVisitor<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> Visitor<'de> for JsonRootVisitor<'borrow, 'presence> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OTLP Traces ProtoJSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "resourceSpans" || key == "resource_spans" {
                map.next_value_seed(ResourceSpansSeed {
                    collector: self.collector,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct ResourceSpansSeed<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> DeserializeSeed<'de> for ResourceSpansSeed<'borrow, 'presence> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ResourceSpansVisitor {
            collector: self.collector,
        })
    }
}

struct ResourceSpansVisitor<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> Visitor<'de> for ResourceSpansVisitor<'borrow, 'presence> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OTLP resourceSpans array")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(ResourceSpansEntrySeed {
                collector: self.collector,
            })?
            .is_some()
        {}
        Ok(())
    }
}

struct ResourceSpansEntrySeed<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> DeserializeSeed<'de> for ResourceSpansEntrySeed<'borrow, 'presence> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ResourceSpansEntryVisitor {
            collector: self.collector,
        })
    }
}

struct ResourceSpansEntryVisitor<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> Visitor<'de> for ResourceSpansEntryVisitor<'borrow, 'presence> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OTLP ResourceSpans object")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "scopeSpans" || key == "scope_spans" {
                map.next_value_seed(ScopeSpansSeed {
                    collector: self.collector,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct ScopeSpansSeed<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> DeserializeSeed<'de> for ScopeSpansSeed<'borrow, 'presence> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ScopeSpansVisitor {
            collector: self.collector,
        })
    }
}

struct ScopeSpansVisitor<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> Visitor<'de> for ScopeSpansVisitor<'borrow, 'presence> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OTLP scopeSpans array")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(ScopeSpansEntrySeed {
                collector: self.collector,
            })?
            .is_some()
        {}
        Ok(())
    }
}

struct ScopeSpansEntrySeed<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> DeserializeSeed<'de> for ScopeSpansEntrySeed<'borrow, 'presence> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ScopeSpansEntryVisitor {
            collector: self.collector,
        })
    }
}

struct ScopeSpansEntryVisitor<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> Visitor<'de> for ScopeSpansEntryVisitor<'borrow, 'presence> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OTLP ScopeSpans object")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "spans" {
                map.next_value_seed(SpansSeed {
                    collector: self.collector,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct SpansSeed<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> DeserializeSeed<'de> for SpansSeed<'borrow, 'presence> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SpansVisitor {
            collector: self.collector,
        })
    }
}

struct SpansVisitor<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> Visitor<'de> for SpansVisitor<'borrow, 'presence> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OTLP spans array")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(SpanSeed {
                collector: self.collector,
            })?
            .is_some()
        {}
        Ok(())
    }
}

struct SpanSeed<'borrow, 'presence> {
    collector: &'borrow mut JsonPresenceCollector<'presence>,
}

impl<'de, 'borrow, 'presence> DeserializeSeed<'de> for SpanSeed<'borrow, 'presence> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut span = SpanTimestampPresence {
            start: false,
            end: false,
            events: Vec::new(),
        };
        deserializer.deserialize_any(SpanVisitor {
            span: &mut span,
            collector: self.collector,
        })?;
        self.collector.push_span(span)
    }
}

struct SpanVisitor<'span, 'collector, 'presence> {
    span: &'span mut SpanTimestampPresence,
    collector: &'collector mut JsonPresenceCollector<'presence>,
}

impl<'de, 'span, 'collector, 'presence> Visitor<'de> for SpanVisitor<'span, 'collector, 'presence> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OTLP Span object")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "startTimeUnixNano" || key == "start_time_unix_nano" {
                map.next_value_seed(ScalarPresenceSeed {
                    present: &mut self.span.start,
                })?;
            } else if key == "endTimeUnixNano" || key == "end_time_unix_nano" {
                map.next_value_seed(ScalarPresenceSeed {
                    present: &mut self.span.end,
                })?;
            } else if key == "events" {
                map.next_value_seed(EventsSeed {
                    span: self.span,
                    collector: self.collector,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct EventsSeed<'span, 'collector, 'presence> {
    span: &'span mut SpanTimestampPresence,
    collector: &'collector mut JsonPresenceCollector<'presence>,
}

impl<'de, 'span, 'collector, 'presence> DeserializeSeed<'de>
    for EventsSeed<'span, 'collector, 'presence>
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(EventsVisitor {
            span: self.span,
            collector: self.collector,
        })
    }
}

struct EventsVisitor<'span, 'collector, 'presence> {
    span: &'span mut SpanTimestampPresence,
    collector: &'collector mut JsonPresenceCollector<'presence>,
}

impl<'de, 'span, 'collector, 'presence> Visitor<'de>
    for EventsVisitor<'span, 'collector, 'presence>
{
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OTLP events array")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(EventSeed {
                span: self.span,
                collector: self.collector,
            })?
            .is_some()
        {}
        Ok(())
    }
}

struct EventSeed<'span, 'collector, 'presence> {
    span: &'span mut SpanTimestampPresence,
    collector: &'collector mut JsonPresenceCollector<'presence>,
}

impl<'de, 'span, 'collector, 'presence> DeserializeSeed<'de>
    for EventSeed<'span, 'collector, 'presence>
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut present = false;
        deserializer.deserialize_any(EventVisitor {
            present: &mut present,
        })?;
        if self.span.events.try_reserve(1).is_err() {
            return Err(self
                .collector
                .fail(TraceReceiveFailure::CapacityUnavailable));
        }
        self.span.events.push(present);
        Ok(())
    }
}

struct EventVisitor<'present> {
    present: &'present mut bool,
}

impl<'de> Visitor<'de> for EventVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OTLP Event object")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "timeUnixNano" || key == "time_unix_nano" {
                map.next_value_seed(ScalarPresenceSeed {
                    present: self.present,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct ScalarPresenceSeed<'present> {
    present: &'present mut bool,
}

impl<'de> DeserializeSeed<'de> for ScalarPresenceSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ScalarPresenceVisitor {
            present: self.present,
        })
    }
}

struct ScalarPresenceVisitor<'present> {
    present: &'present mut bool,
}

impl<'de> Visitor<'de> for ScalarPresenceVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OTLP timestamp scalar or null")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        *self.present = true;
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        *self.present = true;
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        *self.present = true;
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        *self.present = true;
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        *self.present = true;
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        *self.present = true;
        Ok(())
    }
}

impl SpanTimestampPresence {
    pub(crate) const fn start(&self) -> bool {
        self.start
    }

    pub(crate) const fn end(&self) -> bool {
        self.end
    }

    pub(crate) fn event(&self, ordinal: usize) -> bool {
        self.events.get(ordinal).copied().unwrap_or(true)
    }
}

fn visit_request(
    message: &[u8],
    presence: &mut OtlpTraceTimestampPresence,
) -> Result<(), TraceReceiveFailure> {
    super::bounds::visit_fields_with_wire(message, NO_FIELDS, |field, wire, value| {
        if field == 1 && wire == 2 {
            visit_resource_spans(
                value.ok_or(TraceReceiveFailure::MalformedPayload)?,
                presence,
            )?;
        }
        Ok(())
    })
}

fn visit_resource_spans(
    message: &[u8],
    presence: &mut OtlpTraceTimestampPresence,
) -> Result<(), TraceReceiveFailure> {
    super::bounds::visit_fields_with_wire(message, NO_FIELDS, |field, wire, value| {
        if field == 2 && wire == 2 {
            visit_scope_spans(
                value.ok_or(TraceReceiveFailure::MalformedPayload)?,
                presence,
            )?;
        }
        Ok(())
    })
}

fn visit_scope_spans(
    message: &[u8],
    presence: &mut OtlpTraceTimestampPresence,
) -> Result<(), TraceReceiveFailure> {
    super::bounds::visit_fields_with_wire(message, NO_FIELDS, |field, wire, value| {
        if field == 2 && wire == 2 {
            visit_span(
                value.ok_or(TraceReceiveFailure::MalformedPayload)?,
                presence,
            )?;
        }
        Ok(())
    })
}

fn visit_span(
    message: &[u8],
    presence: &mut OtlpTraceTimestampPresence,
) -> Result<(), TraceReceiveFailure> {
    let mut span = SpanTimestampPresence {
        start: false,
        end: false,
        events: Vec::new(),
    };
    super::bounds::visit_fields_with_wire(message, NO_FIELDS, |field, wire, value| {
        match (field, wire) {
            (7, 1) => span.start = true,
            (8, 1) => span.end = true,
            (11, 2) => {
                let event = value.ok_or(TraceReceiveFailure::MalformedPayload)?;
                span.events
                    .try_reserve(1)
                    .map_err(|_| TraceReceiveFailure::CapacityUnavailable)?;
                span.events.push(event_time_present(event)?);
            },
            _ => {},
        }
        Ok(())
    })?;
    presence
        .spans
        .try_reserve(1)
        .map_err(|_| TraceReceiveFailure::CapacityUnavailable)?;
    presence.spans.push(span);
    Ok(())
}

fn event_time_present(message: &[u8]) -> Result<bool, TraceReceiveFailure> {
    let mut present = false;
    super::bounds::visit_fields_with_wire(message, NO_FIELDS, |field, wire, _| {
        if field == 1 && wire == 1 {
            present = true;
        }
        Ok(())
    })?;
    Ok(present)
}
