use positron_domain::value::AttributeNamespace;
use positron_signals::{OccurrenceSelector, SchemaFailure, SchemaPath, SchemaQuery};

use crate::{QueryFailure, QueryFailureCode};

pub(crate) fn parse_predicate(source: &str) -> Result<SchemaQuery, QueryFailure> {
    let (path_source, remainder) = split_path(source)?;
    let path = parse_path(path_source)?;
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
    let value = crate::native_literal::parse_attribute(literal)?;
    Ok(SchemaQuery::native_value(path, selector, value))
}

pub(crate) fn parse_path(source: &str) -> Result<SchemaPath, QueryFailure> {
    let (namespace, mut remaining) = if let Some(value) = source.strip_prefix("resource") {
        (AttributeNamespace::Resource, value)
    } else if let Some(value) = source.strip_prefix("scope") {
        (AttributeNamespace::InstrumentationScope, value)
    } else if let Some(value) = source.strip_prefix("record") {
        (AttributeNamespace::Record, value)
    } else {
        return Err(unsupported());
    };
    let mut segments = Vec::new();
    while !remaining.is_empty() {
        let Some(after_open) = remaining.strip_prefix("[\"") else {
            return Err(unsupported());
        };
        let (segment, after_segment) = parse_segment(after_open)?;
        if segments.len() == SchemaPath::system_max_segments() {
            return Err(unsupported());
        }
        segments
            .try_reserve(1)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        segments.push(segment);
        remaining = after_segment;
    }
    SchemaPath::from_segments(namespace, segments).map_err(map_schema_failure)
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

fn parse_segment(source: &str) -> Result<(String, &str), QueryFailure> {
    let mut segment = String::new();
    segment
        .try_reserve_exact(source.len().min(4_096))
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let mut remaining = source;
    loop {
        let character = remaining.chars().next().ok_or_else(unsupported)?;
        remaining = remaining
            .get(character.len_utf8()..)
            .ok_or_else(unsupported)?;
        match character {
            '"' => {
                remaining = remaining.strip_prefix(']').ok_or_else(unsupported)?;
                return Ok((segment, remaining));
            },
            '\\' => {
                let escaped = remaining.chars().next().ok_or_else(unsupported)?;
                if !matches!(escaped, '"' | '\\' | '|') {
                    return Err(unsupported());
                }
                remaining = remaining
                    .get(escaped.len_utf8()..)
                    .ok_or_else(unsupported)?;
                segment.push(escaped);
            },
            _ => segment.push(character),
        }
    }
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
