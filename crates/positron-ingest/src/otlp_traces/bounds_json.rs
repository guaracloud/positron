use serde::de::{self, DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use std::fmt;

use super::{Limits, TraceLimitClass, TraceReceiveFailure};

pub(super) fn validate(
    json: &[u8],
    profile: positron_domain::value::ValueLimitProfile,
) -> Result<(), TraceReceiveFailure> {
    if json.len()
        > usize::try_from(
            profile
                .effective_limits()
                .request()
                .decompressed_bytes()
                .value(),
        )
        .map_err(|_| TraceReceiveFailure::TransportLimitExceeded)?
    {
        return Err(TraceReceiveFailure::TransportLimitExceeded);
    }
    let mut bounds = JsonBounds {
        limits: Limits::from_profile(profile)?,
        decoded_bytes: 0,
        containers: 0,
        depth: 0,
        failure: None,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    // The receiver's bounded visitor owns the JSON depth contract. Keep the
    // parser's implementation limit disabled so an input crossing that
    // contract is reported as the stable ValueLimitExceeded outcome rather
    // than as an indistinguishable syntax error.
    deserializer.disable_recursion_limit();
    let max_string_bytes = bounds.limits.key_bytes;
    deserializer
        .deserialize_any(JsonVisitor {
            bounds: &mut bounds,
            max_string_bytes,
            max_string_class: TraceLimitClass::KeyPathBytes,
        })
        .map_err(|_| {
            bounds
                .failure
                .unwrap_or(TraceReceiveFailure::MalformedPayload)
        })?;
    deserializer
        .end()
        .map_err(|_| TraceReceiveFailure::MalformedPayload)
}

/// Streams the generic ProtoJSON tree once before generated-message decode.
/// Strings and collections are counted from borrowed parser input, so a
/// hostile escaped value cannot force an unbounded intermediate allocation.
struct JsonBounds {
    limits: Limits,
    decoded_bytes: usize,
    containers: usize,
    depth: usize,
    failure: Option<TraceReceiveFailure>,
}

impl JsonBounds {
    fn fail(&mut self, failure: TraceReceiveFailure) -> serde_json::Error {
        self.failure = Some(failure);
        <serde_json::Error as de::Error>::custom("OTLP Traces JSON bound exceeded")
    }

    fn text(
        &mut self,
        length: usize,
        max_string_bytes: usize,
        class: TraceLimitClass,
    ) -> Result<(), serde_json::Error> {
        if length > max_string_bytes {
            return Err(self.fail(super::limit_failure(class, length, max_string_bytes)));
        }
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(length)
            .filter(|bytes| *bytes <= self.limits.decoded_batch_bytes)
            .ok_or_else(|| self.fail(TraceReceiveFailure::ValueLimitExceeded))?;
        Ok(())
    }

    fn protocol_key(&mut self, length: usize) -> Result<(), serde_json::Error> {
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(length)
            .filter(|bytes| *bytes <= self.limits.decoded_batch_bytes)
            .ok_or_else(|| self.fail(TraceReceiveFailure::ValueLimitExceeded))?;
        Ok(())
    }

    fn container(&mut self) -> Result<(), serde_json::Error> {
        self.containers = self
            .containers
            .checked_add(1)
            .ok_or_else(|| self.fail(TraceReceiveFailure::ValueLimitExceeded))?;
        if self.containers > self.limits.containers {
            return Err(self.fail(super::limit_failure(
                TraceLimitClass::ContainerCount,
                self.containers,
                self.limits.containers,
            )));
        }
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| self.fail(TraceReceiveFailure::ValueLimitExceeded))?;
        if self.depth > self.limits.nesting_depth {
            return Err(self.fail(super::limit_failure(
                TraceLimitClass::NestingDepth,
                self.depth,
                self.limits.nesting_depth,
            )));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

struct JsonVisitor<'bounds> {
    bounds: &'bounds mut JsonBounds,
    max_string_bytes: usize,
    max_string_class: TraceLimitClass,
}

impl<'de> Visitor<'de> for JsonVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded OTLP Traces ProtoJSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.bounds
            .text(value.len(), self.max_string_bytes, self.max_string_class)
            .map_err(E::custom)
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(value)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.bounds.container().map_err(A::Error::custom)?;
        let result = (|| {
            let mut entries = 0_usize;
            while sequence
                .next_element_seed(JsonSeed {
                    bounds: self.bounds,
                    max_string_bytes: self.max_string_bytes,
                    max_string_class: self.max_string_class,
                })?
                .is_some()
            {
                entries = entries
                    .checked_add(1)
                    .ok_or_else(|| A::Error::custom("OTLP Traces JSON array bound exceeded"))?;
                if entries > self.bounds.limits.array_entries {
                    return Err(A::Error::custom(self.bounds.fail(super::limit_failure(
                        TraceLimitClass::ArrayEntries,
                        entries,
                        self.bounds.limits.array_entries,
                    ))));
                }
            }
            Ok(())
        })();
        self.bounds.leave();
        result
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.bounds.container().map_err(A::Error::custom)?;
        let result = (|| {
            let mut entries = 0_usize;
            while let Some(key) = map.next_key::<String>()? {
                let key_limit = self.bounds.limits.key_bytes;
                if is_protocol_field_name(&key) {
                    self.bounds
                        .protocol_key(key.len())
                        .map_err(A::Error::custom)?;
                } else {
                    self.bounds
                        .text(key.len(), key_limit, TraceLimitClass::KeyPathBytes)
                        .map_err(A::Error::custom)?;
                }
                entries = entries
                    .checked_add(1)
                    .filter(|entries| *entries <= self.bounds.limits.key_value_entries)
                    .ok_or_else(|| A::Error::custom("OTLP Traces JSON object bound exceeded"))?;
                let (value_limit, value_class) = match key.as_str() {
                    "bytesValue" | "bytes_value" => (
                        self.bounds.limits.json_bytes_text,
                        TraceLimitClass::IndividualValueBytes,
                    ),
                    "stringValue" | "string_value" => (
                        self.bounds.limits.value_bytes,
                        TraceLimitClass::IndividualValueBytes,
                    ),
                    "traceId" | "trace_id" | "spanId" | "span_id" | "parentSpanId"
                    | "parent_span_id" => (usize::MAX, TraceLimitClass::KeyPathBytes),
                    _ => (key_limit, TraceLimitClass::KeyPathBytes),
                };
                map.next_value_seed(JsonSeed {
                    bounds: self.bounds,
                    max_string_bytes: value_limit,
                    max_string_class: value_class,
                })?;
            }
            Ok(())
        })();
        self.bounds.leave();
        result
    }
}

fn is_protocol_field_name(name: &str) -> bool {
    matches!(
        name,
        "resourceSpans"
            | "resource_spans"
            | "resource"
            | "scopeSpans"
            | "scope_spans"
            | "scope"
            | "spans"
            | "traceId"
            | "trace_id"
            | "spanId"
            | "span_id"
            | "traceState"
            | "trace_state"
            | "parentSpanId"
            | "parent_span_id"
            | "flags"
            | "name"
            | "kind"
            | "startTimeUnixNano"
            | "start_time_unix_nano"
            | "endTimeUnixNano"
            | "end_time_unix_nano"
            | "attributes"
            | "droppedAttributesCount"
            | "dropped_attributes_count"
            | "events"
            | "timeUnixNano"
            | "time_unix_nano"
            | "droppedEventsCount"
            | "dropped_events_count"
            | "links"
            | "droppedLinksCount"
            | "dropped_links_count"
            | "status"
            | "message"
            | "code"
            | "key"
            | "value"
            | "stringValue"
            | "string_value"
            | "boolValue"
            | "bool_value"
            | "intValue"
            | "int_value"
            | "doubleValue"
            | "double_value"
            | "bytesValue"
            | "bytes_value"
            | "arrayValue"
            | "array_value"
            | "kvlistValue"
            | "kvlist_value"
            | "values"
            | "schemaUrl"
            | "schema_url"
            | "version"
            | "entityRefs"
            | "entity_refs"
            | "id"
            | "idKeys"
            | "id_keys"
            | "type"
            | "description"
    )
}

struct JsonSeed<'bounds> {
    bounds: &'bounds mut JsonBounds,
    max_string_bytes: usize,
    max_string_class: TraceLimitClass,
}

impl<'de> DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonVisitor {
            bounds: self.bounds,
            max_string_bytes: self.max_string_bytes,
            max_string_class: self.max_string_class,
        })
    }
}
