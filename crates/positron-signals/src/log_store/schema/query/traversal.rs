use positron_domain::value::{
    AttributeOccurrenceSet, NativeValueObserver, ObservedValueFailure, ValidatedAttributeValue,
};

use super::{OccurrenceSelector, QueryValue, SchemaQuery, SchemaRepresentation, SchemaValue};
pub(crate) fn visit_terminals(
    value: &ValidatedAttributeValue,
    segments: &[String],
    visit: &mut impl FnMut(&ValidatedAttributeValue) -> bool,
) -> bool {
    let Some((segment, remaining)) = segments.split_first() else {
        return visit(value);
    };
    let Some(count) = value.key_value_list_len() else {
        return true;
    };
    for index in 0..count {
        if let Some(entry) = value.key_value_entry(index)
            && entry.key() == segment
            && !visit_terminals(entry.value(), remaining, visit)
        {
            return false;
        }
    }
    true
}

pub(super) fn value_matches(value: &ValidatedAttributeValue, expected: &QueryValue) -> bool {
    match expected {
        QueryValue::Scalar(SchemaValue::Null) => value.is_null(),
        QueryValue::Scalar(SchemaValue::Boolean(expected)) => value.as_boolean() == Some(*expected),
        QueryValue::Scalar(SchemaValue::SignedInteger(expected)) => {
            value.as_signed_integer() == Some(*expected)
        },
        QueryValue::Scalar(SchemaValue::FloatingPointBits(expected)) => {
            value.as_floating_point_bits() == Some(*expected)
        },
        QueryValue::Scalar(SchemaValue::String(expected)) => {
            value.as_str() == Some(expected.as_str())
        },
        QueryValue::Scalar(SchemaValue::Bytes(expected)) => {
            value.as_bytes() == Some(expected.as_slice())
        },
        QueryValue::Scalar(SchemaValue::Kind(expected)) => value.kind() == *expected,
        QueryValue::Native(expected) => value == expected,
    }
}

pub(crate) fn matches_observed<'a, O: NativeValueObserver>(
    attributes: impl Iterator<Item = (&'a AttributeOccurrenceSet, SchemaRepresentation)>,
    query: &SchemaQuery,
    observer: &mut O,
) -> Result<bool, ObservedValueFailure<O::Error>> {
    let Some(remaining) = query.path.segments().get(1..) else {
        return Ok(false);
    };
    let mut selection = ObservedSelection::new(query.selector, &query.value);
    for (attribute, _) in attributes {
        observe_structure(observer)?;
        observe_payload(attribute.key().as_bytes(), observer)?;
        for index in 0..attribute.len() {
            observe_structure(observer)?;
            let Some(value) = attribute.occurrence(index) else {
                return Ok(false);
            };
            if !visit_terminals_observed(value, remaining, observer, &mut |terminal, observer| {
                selection.visit(terminal, observer)
            })? || selection.complete
            {
                break;
            }
        }
        if selection.complete {
            break;
        }
    }
    Ok(selection.selected > 0 && selection.matched)
}

pub(crate) fn visit_terminals_observed<O: NativeValueObserver>(
    value: &ValidatedAttributeValue,
    segments: &[String],
    observer: &mut O,
    visit: &mut impl FnMut(
        &ValidatedAttributeValue,
        &mut O,
    ) -> Result<bool, ObservedValueFailure<O::Error>>,
) -> Result<bool, ObservedValueFailure<O::Error>> {
    observe_structure(observer)?;
    let Some((segment, remaining)) = segments.split_first() else {
        return visit(value, observer);
    };
    observe_payload(segment.as_bytes(), observer)?;
    let Some(count) = value.key_value_list_len() else {
        return Ok(true);
    };
    for index in 0..count {
        observe_structure(observer)?;
        let Some(entry) = value.key_value_entry(index) else {
            return Ok(false);
        };
        observe_payload(entry.key().as_bytes(), observer)?;
        if entry.key() == segment
            && !visit_terminals_observed(entry.value(), remaining, observer, visit)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

struct ObservedSelection<'a> {
    selector: OccurrenceSelector,
    expected: &'a QueryValue,
    ordinal: usize,
    selected: usize,
    matched: bool,
    complete: bool,
}

impl<'a> ObservedSelection<'a> {
    const fn new(selector: OccurrenceSelector, expected: &'a QueryValue) -> Self {
        Self {
            selector,
            expected,
            ordinal: 0,
            selected: 0,
            matched: matches!(selector, OccurrenceSelector::All),
            complete: false,
        }
    }

    fn visit<O: NativeValueObserver>(
        &mut self,
        value: &ValidatedAttributeValue,
        observer: &mut O,
    ) -> Result<bool, ObservedValueFailure<O::Error>> {
        observe_structure(observer)?;
        let current = self.ordinal;
        self.ordinal = self.ordinal.saturating_add(1);
        if matches!(self.selector, OccurrenceSelector::Index(wanted) if wanted != current) {
            return Ok(true);
        }
        self.selected = self.selected.saturating_add(1);
        let matches = value_matches_observed(value, self.expected, observer)?;
        match self.selector {
            OccurrenceSelector::Index(_) => {
                self.matched = matches;
                self.complete = true;
            },
            OccurrenceSelector::Any if matches => {
                self.matched = true;
                self.complete = true;
            },
            OccurrenceSelector::All if !matches => {
                self.matched = false;
                self.complete = true;
            },
            OccurrenceSelector::Any | OccurrenceSelector::All => {},
        }
        Ok(!self.complete)
    }
}

fn value_matches_observed<O: NativeValueObserver>(
    value: &ValidatedAttributeValue,
    expected: &QueryValue,
    observer: &mut O,
) -> Result<bool, ObservedValueFailure<O::Error>> {
    match expected {
        QueryValue::Native(expected) => value.equals_observed(expected, observer),
        _ => {
            observe_structure(observer)?;
            Ok(value_matches(value, expected))
        },
    }
}

fn observe_structure<O: NativeValueObserver>(
    observer: &mut O,
) -> Result<(), ObservedValueFailure<O::Error>> {
    observer
        .observe_structure()
        .map_err(ObservedValueFailure::Observer)
}

fn observe_payload<O: NativeValueObserver>(
    payload: &[u8],
    observer: &mut O,
) -> Result<(), ObservedValueFailure<O::Error>> {
    for chunk in payload.chunks(positron_domain::value::NATIVE_VALUE_PAYLOAD_CHUNK_BYTES) {
        observer
            .observe_payload(chunk)
            .map_err(ObservedValueFailure::Observer)?;
    }
    Ok(())
}
