use positron_domain::value::AttributeNamespace;
use positron_signals::{OccurrenceSelector, SchemaFailure, SchemaPath, SchemaQuery};

use crate::{QueryFailure, QueryFailureCode};

pub(crate) fn parse_predicate(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<SchemaQuery, QueryFailure> {
    let (path_source, remainder) = split_path(source)?;
    let path = parse_path(path_source, memory)?;
    let (selector, literal) = if let Some(literal) = remainder.strip_prefix(" any == ") {
        (OccurrenceSelector::Any, literal)
    } else if let Some(literal) = remainder.strip_prefix(" all == ") {
        (OccurrenceSelector::All, literal)
    } else if let Some(indexed) = remainder.strip_prefix(" index(") {
        let (index, literal) = indexed.split_once(") == ").ok_or_else(unsupported)?;
        if index.is_empty() || index.starts_with('+') || index.starts_with('0') && index.len() > 1 {
            return Err(unsupported());
        }
        let index = index.parse::<u16>().map_err(|_| unsupported())?;
        (OccurrenceSelector::Index(usize::from(index)), literal)
    } else {
        return Err(unsupported());
    };
    let (value, reservation, retained) =
        crate::native_literal::parse_attribute_with_reservation(literal, memory)?;
    let query =
        SchemaQuery::exact_native_value(path, selector, value).map_err(map_schema_failure)?;
    memory.retain_reservation(reservation, retained)?;
    Ok(query)
}

pub(crate) fn parse_path(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<SchemaPath, QueryFailure> {
    let (namespace, mut remaining) = if let Some(value) = strip_namespace(source, "resource") {
        (AttributeNamespace::Resource, value)
    } else if let Some(value) = strip_namespace(source, "scope") {
        (AttributeNamespace::InstrumentationScope, value)
    } else if let Some(value) = strip_namespace(source, "record") {
        (AttributeNamespace::Record, value)
    } else {
        return Err(unsupported());
    };
    let mut reservation = memory.reserve(0)?;
    let mut segments = crate::planning_memory::PlanningVec::with_capacity(memory, 0)?;
    while !remaining.is_empty() {
        let Some(after_open) = remaining.strip_prefix("[\"") else {
            return Err(unsupported());
        };
        let (segment, after_segment, segment_reservation) = parse_segment(after_open, memory)?;
        if segments.len() == SchemaPath::system_max_segments() {
            return Err(unsupported());
        }
        reservation.merge(segment_reservation)?;
        segments.push(segment)?;
        remaining = after_segment;
    }
    let (segments, segments_reservation) = segments.into_vec_with_reservation();
    reservation.merge(segments_reservation)?;
    let path = SchemaPath::from_segments(namespace, segments).map_err(map_schema_failure)?;
    memory.retain_reservation(reservation, crate::planning_memory::path_memory(0, &path)?)?;
    Ok(path)
}

fn strip_namespace<'source>(source: &'source str, namespace: &str) -> Option<&'source str> {
    source
        .get(..namespace.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(namespace))
        .map(|_| &source[namespace.len()..])
}

pub(crate) fn render_path(path: &SchemaPath) -> Result<String, QueryFailure> {
    let namespace = match path.namespace() {
        AttributeNamespace::Resource => "resource",
        AttributeNamespace::InstrumentationScope => "scope",
        AttributeNamespace::Record => "record",
        AttributeNamespace::Stream => return Err(unsupported()),
    };
    let required = path
        .segments()
        .iter()
        .try_fold(namespace.len(), |total, segment| {
            let escapes = segment
                .bytes()
                .filter(|byte| matches!(byte, b'"' | b'\\' | b'|'))
                .count();
            total
                .checked_add(4)?
                .checked_add(segment.len())?
                .checked_add(escapes)
        })
        .ok_or_else(unsupported)?;
    let mut rendered = String::new();
    rendered
        .try_reserve_exact(required)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    rendered.push_str(namespace);
    for segment in path.segments() {
        rendered.push_str("[\"");
        for character in segment.chars() {
            if matches!(character, '"' | '\\' | '|') {
                rendered.push('\\');
            }
            rendered.push(character);
        }
        rendered.push_str("\"]");
    }
    Ok(rendered)
}

fn split_path(source: &str) -> Result<(&str, &str), QueryFailure> {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in source.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == ' ' && !quoted {
            return Ok((
                source.get(..index).ok_or_else(unsupported)?,
                source.get(index..).ok_or_else(unsupported)?,
            ));
        }
    }
    Err(unsupported())
}

fn parse_segment<'source>(
    source: &'source str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<
    (
        String,
        &'source str,
        crate::planning_memory::PlanningReservation,
    ),
    QueryFailure,
> {
    let (segment, remaining, reservation) = crate::quoted::parse_after_open(source, memory)?;
    let remaining = remaining.strip_prefix(']').ok_or_else(unsupported)?;
    Ok((segment, remaining, reservation))
}

fn map_schema_failure(failure: SchemaFailure) -> QueryFailure {
    match failure {
        SchemaFailure::AllocationUnavailable => {
            QueryFailure::new(QueryFailureCode::ResourceExhausted)
        },
        _ => unsupported(),
    }
}

const fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}
