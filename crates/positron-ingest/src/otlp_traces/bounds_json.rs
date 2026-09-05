use serde::de::{self, DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use std::fmt;

use super::{Limits, TraceLimitClass, TraceLimitViolation, TraceReceiveFailure};

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
            let failure = match (u64::try_from(length), u64::try_from(max_string_bytes)) {
                (Ok(actual), Ok(allowed)) => TraceReceiveFailure::ValueLimitExceededWithDetail(
                    TraceLimitViolation::new(class, actual, allowed),
                ),
                _ => TraceReceiveFailure::ValueLimitExceeded,
            };
            return Err(self.fail(failure));
        }
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
            .filter(|containers| *containers <= self.limits.containers)
            .ok_or_else(|| self.fail(TraceReceiveFailure::ValueLimitExceeded))?;
        self.depth = self
            .depth
            .checked_add(1)
            .filter(|depth| *depth <= self.limits.nesting_depth)
            .ok_or_else(|| self.fail(TraceReceiveFailure::ValueLimitExceeded))?;
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
                    .filter(|entries| *entries <= self.bounds.limits.array_entries)
                    .ok_or_else(|| A::Error::custom("OTLP Traces JSON array bound exceeded"))?;
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
                self.bounds
                    .text(key.len(), key_limit, TraceLimitClass::KeyPathBytes)
                    .map_err(A::Error::custom)?;
                entries = entries
                    .checked_add(1)
                    .filter(|entries| *entries <= self.bounds.limits.key_value_entries)
                    .ok_or_else(|| A::Error::custom("OTLP Traces JSON object bound exceeded"))?;
                let (value_limit, value_class) = if key == "bytesValue" {
                    (
                        self.bounds.limits.json_bytes_text,
                        TraceLimitClass::IndividualValueBytes,
                    )
                } else if key == "stringValue" || key == "string_value" {
                    (
                        self.bounds.limits.value_bytes,
                        TraceLimitClass::IndividualValueBytes,
                    )
                } else {
                    (key_limit, TraceLimitClass::KeyPathBytes)
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
