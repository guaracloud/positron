//! Source-policy enforcement for registered concurrency primitives.
//!
//! This module owns the fail-closed scan that reconciles active tooling spawn
//! sites with their registry and resolves Rust `use` trees before checking for
//! forbidden spawn and unbounded-resource invocations.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::error::XtaskError;

pub(crate) type SpawnSiteKey = (String, String, String);
pub(crate) type SpawnSiteRegistry = BTreeMap<SpawnSiteKey, String>;

pub(crate) fn validate_registered_spawn_sites(
    root: &Path,
    registry_path: &Path,
    registered: &SpawnSiteRegistry,
    registered_thread_site: &str,
) -> Result<(), XtaskError> {
    let source_root = root.join("tools/xtask/src");
    let mut files = Vec::new();
    crate::registry::collect_files_with_extension(&source_root, "rs", 0, &mut files)?;
    let mut observed = BTreeMap::new();
    for source in files {
        let relative = source.strip_prefix(root).map_err(|_| {
            XtaskError::invalid_path(&source, "tooling source escaped its workspace root")
        })?;
        let relative = relative.to_string_lossy().into_owned();
        let source_text = fs::read_to_string(&source)
            .map_err(|error| XtaskError::io(format!("read {}", source.display()), error))?;
        let tokenized = tokenized_source(&source_text);
        let (production, excluded_test_lines) = mask_cfg_test_items(&tokenized)?;
        let tokens = source_tokens(&production);
        reject_forbidden_invocations(&source, &tokens)?;

        let markers = source_text
            .lines()
            .enumerate()
            .filter(|(offset, _)| !excluded_test_lines.contains(&(offset + 1)))
            .filter_map(|(offset, raw_line)| {
                raw_line
                    .trim_start()
                    .strip_prefix("// positron-concurrency-spawn: ")
                    .map(|value| (offset + 1, value))
            })
            .map(|(line_number, value)| {
                let Some((symbol, id)) = value.split_once("\\t") else {
                    return Err(XtaskError::invalid_path(
                        &source,
                        format!("spawn marker at tooling line {line_number} is malformed"),
                    ));
                };
                if symbol.is_empty() || id.is_empty() {
                    return Err(XtaskError::invalid_path(
                        &source,
                        format!("spawn marker at tooling line {line_number} is incomplete"),
                    ));
                }
                Ok((line_number, symbol.to_owned(), id.to_owned()))
            })
            .collect::<Result<Vec<_>, XtaskError>>()?;
        let spawn_lines = method_spawn_lines(&tokens);
        if spawn_lines.len() != markers.len() {
            return Err(XtaskError::invalid_path(
                &source,
                "unregistered process or task spawn: every active method spawn must have exactly one registered marker",
            ));
        }
        for ((marker_line, _, _), spawn_line) in markers.iter().zip(&spawn_lines) {
            if *spawn_line != marker_line.saturating_add(1) {
                return Err(XtaskError::invalid_path(
                    &source,
                    format!(
                        "spawn marker at tooling line {marker_line} is not immediately bound to its exact method spawn"
                    ),
                ));
            }
        }
        for (line_number, symbol, id) in markers {
            let key = (relative.clone(), symbol, id);
            let Some(kind) = registered.get(&key) else {
                return Err(XtaskError::invalid_path(
                    &source,
                    format!("unregistered semantic spawn site at tooling line {line_number}"),
                ));
            };
            let controlled_framed_stdout_thread = key.0
                == "tools/xtask/src/framed_stdout_broker.rs"
                && key.1 == "FramedStdoutBroker::start"
                && key.2 == "controlled-framed-stdout-broker-v1";
            let actual = if key.2 == registered_thread_site || controlled_framed_stdout_thread {
                "thread"
            } else {
                "process"
            };
            if kind != actual {
                return Err(XtaskError::invalid_path(
                    &source,
                    format!("spawn-site kind drift at tooling line {line_number}"),
                ));
            }
            if observed.insert(key, kind.clone()).is_some() {
                return Err(XtaskError::invalid_path(
                    &source,
                    format!("duplicate observed semantic spawn site at tooling line {line_number}"),
                ));
            }
        }
    }
    if observed != *registered {
        return Err(XtaskError::invalid_path(
            registry_path,
            "registered spawn-site set does not exactly match active tooling source",
        ));
    }
    Ok(())
}

fn mask_cfg_test_items(source: &str) -> Result<(String, BTreeSet<usize>), XtaskError> {
    let characters = source.chars().collect::<Vec<_>>();
    let mut excluded = vec![false; characters.len()];
    let mut cursor = 0;
    while cursor < characters.len() {
        if characters.get(cursor) != Some(&'#') || characters.get(cursor + 1) != Some(&'[') {
            cursor += 1;
            continue;
        }
        let attribute_end = balanced_end(&characters, cursor + 1, '[', ']')?;
        let attribute = characters
            .get(cursor..attribute_end)
            .ok_or_else(|| {
                XtaskError::invalid(
                    "concurrency source policy",
                    "test-only attribute escaped its tokenized source boundary",
                )
            })?
            .iter()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        if !is_test_only_cfg_attribute(&attribute) {
            cursor = attribute_end;
            continue;
        }
        let item_start = cursor;
        cursor = attribute_end;
        loop {
            while characters
                .get(cursor)
                .is_some_and(|character| character.is_whitespace())
            {
                cursor += 1;
            }
            if characters.get(cursor) != Some(&'#') || characters.get(cursor + 1) != Some(&'[') {
                break;
            }
            cursor = balanced_end(&characters, cursor + 1, '[', ']')?;
        }
        let item_end = rust_item_end(&characters, cursor)?;
        excluded
            .get_mut(item_start..item_end)
            .ok_or_else(|| {
                XtaskError::invalid(
                    "concurrency source policy",
                    "test-only item escaped its tokenized source boundary",
                )
            })?
            .fill(true);
        cursor = item_end;
    }
    let mut line = 1_usize;
    let mut excluded_lines = BTreeSet::new();
    let production = characters
        .iter()
        .zip(excluded)
        .map(|(character, excluded)| {
            let current_line = line;
            if *character == '\n' {
                line += 1;
            }
            if excluded {
                excluded_lines.insert(current_line);
                if *character == '\n' { '\n' } else { ' ' }
            } else {
                *character
            }
        })
        .collect();
    Ok((production, excluded_lines))
}

fn is_test_only_cfg_attribute(attribute: &str) -> bool {
    attribute == "#[cfg(test)]"
        || (attribute.starts_with("#[cfg(all(")
            && attribute.ends_with("))]")
            && attribute
                .trim_start_matches("#[cfg(all(")
                .trim_end_matches("))]")
                .split(',')
                .any(|predicate| predicate == "test"))
}

fn balanced_end(
    characters: &[char],
    open_at: usize,
    open: char,
    close: char,
) -> Result<usize, XtaskError> {
    if characters.get(open_at) != Some(&open) {
        return Err(XtaskError::invalid(
            "concurrency source policy",
            "annotated Rust boundary omitted its opening delimiter",
        ));
    }
    let mut depth = 0_usize;
    for (offset, character) in characters.iter().enumerate().skip(open_at) {
        if *character == open {
            depth = depth.checked_add(1).ok_or_else(|| {
                XtaskError::invalid(
                    "concurrency source policy",
                    "annotated Rust boundary nesting overflowed",
                )
            })?;
        } else if *character == close {
            depth = depth.checked_sub(1).ok_or_else(|| {
                XtaskError::invalid(
                    "concurrency source policy",
                    "annotated Rust boundary closed before it opened",
                )
            })?;
            if depth == 0 {
                return Ok(offset + 1);
            }
        }
    }
    Err(XtaskError::invalid(
        "concurrency source policy",
        "annotated Rust boundary was not closed",
    ))
}

fn rust_item_end(characters: &[char], start: usize) -> Result<usize, XtaskError> {
    let mut parenthesis_depth = 0_usize;
    let mut bracket_depth = 0_usize;
    for (offset, character) in characters.iter().enumerate().skip(start) {
        match *character {
            '(' => parenthesis_depth += 1,
            ')' => {
                parenthesis_depth = parenthesis_depth.checked_sub(1).ok_or_else(|| {
                    XtaskError::invalid(
                        "concurrency source policy",
                        "test-only Rust item has an unmatched parenthesis",
                    )
                })?;
            },
            '[' => bracket_depth += 1,
            ']' => {
                bracket_depth = bracket_depth.checked_sub(1).ok_or_else(|| {
                    XtaskError::invalid(
                        "concurrency source policy",
                        "test-only Rust item has an unmatched bracket",
                    )
                })?;
            },
            '{' if parenthesis_depth == 0 && bracket_depth == 0 => {
                return balanced_end(characters, offset, '{', '}');
            },
            ';' if parenthesis_depth == 0 && bracket_depth == 0 => return Ok(offset + 1),
            _ => {},
        }
    }
    Err(XtaskError::invalid(
        "concurrency source policy",
        "test-only Rust attribute omitted its item boundary",
    ))
}

fn reject_forbidden_invocations(source: &Path, tokens: &[SourceToken]) -> Result<(), XtaskError> {
    let kinds = tokens
        .iter()
        .map(|token| token.kind.clone())
        .collect::<Vec<_>>();
    let imports = resolved_imports(&kinds)?;
    for glob in &imports.globs {
        let resolved = resolve_alias_path(glob, &imports.aliases);
        if matches!(
            resolved.as_slice(),
            [std, thread] if std == "std" && thread == "thread"
        ) || matches!(
            resolved.as_slice(),
            [std, sync, mpsc] if std == "std" && sync == "sync" && mpsc == "mpsc"
        ) {
            return Err(XtaskError::invalid_path(
                source,
                "forbidden concurrency primitive glob import in activated tooling source",
            ));
        }
    }
    for start in 0..kinds.len() {
        let Some(path) = source_path_at(&kinds, start) else {
            continue;
        };
        let called = path_is_called(&kinds, path.end);
        if called && is_direct_thread_spawn(&path.segments) {
            return Err(XtaskError::invalid_path(
                source,
                "direct unregistered thread spawn in activated tooling source",
            ));
        }
        if is_direct_unbounded_primitive(&path.segments, called) {
            return Err(XtaskError::invalid_path(
                source,
                "unbounded concurrency primitive in activated tooling source",
            ));
        }
        let resolved = resolve_alias_path(&path.segments, &imports.aliases);
        if matches_forbidden_function_item(&resolved) {
            return Err(XtaskError::invalid_path(
                source,
                "unregistered imported concurrency primitive alias in activated tooling source",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum UseToken {
    Identifier(String),
    PathSeparator,
    OpenGroup,
    CloseGroup,
    Comma,
    Semicolon,
    Equals,
    Glob,
    OpenParenthesis,
    CloseParenthesis,
    Dot,
    Less,
    Greater,
}

#[derive(Clone, Debug)]
struct SourceToken {
    kind: UseToken,
    line: usize,
}

struct SourcePath {
    segments: Vec<String>,
    end: usize,
}

struct ResolvedImports {
    aliases: BTreeMap<String, Vec<String>>,
    globs: Vec<Vec<String>>,
}

fn resolved_imports(tokens: &[UseToken]) -> Result<ResolvedImports, XtaskError> {
    let mut bindings = Vec::new();
    let mut globs = Vec::new();
    let mut cursor = 0;
    while cursor < tokens.len() {
        if identifier_at(tokens, cursor) != Some("use") {
            cursor += 1;
            continue;
        }
        cursor += 1;
        parse_use_tree(tokens, &mut cursor, &[], &mut bindings, &mut globs)?;
        if tokens.get(cursor) != Some(&UseToken::Semicolon) {
            return Err(XtaskError::invalid(
                "concurrency source policy",
                "Rust use tree did not terminate at its registered boundary",
            ));
        }
        cursor += 1;
    }
    let mut aliases = bindings
        .into_iter()
        .map(|(path, local)| (local, path))
        .collect::<BTreeMap<_, _>>();
    for _ in 0..=aliases.len() {
        let snapshot = aliases.clone();
        let mut changed = false;
        for path in aliases.values_mut() {
            let resolved = resolve_alias_path(path, &snapshot);
            if *path != resolved {
                *path = resolved;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(ResolvedImports { aliases, globs })
}

fn resolve_alias_path(path: &[String], aliases: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut resolved = path.to_vec();
    for _ in 0..=aliases.len() {
        let Some(first) = resolved.first() else {
            break;
        };
        let Some(prefix) = aliases.get(first) else {
            break;
        };
        let mut next = prefix.clone();
        next.extend(resolved.iter().skip(1).cloned());
        if next == resolved {
            break;
        }
        resolved = next;
    }
    resolved
}

fn is_direct_thread_spawn(path: &[String]) -> bool {
    matches!(
        path,
        [std, thread, spawn]
            if std == "std" && thread == "thread" && spawn == "spawn"
    ) || matches!(path, [thread, spawn] if thread == "thread" && spawn == "spawn")
}

fn is_direct_unbounded_primitive(path: &[String], called: bool) -> bool {
    matches_vec_deque_new(path)
        || (called
            && (matches!(
                path,
                [std, sync, mpsc, channel]
                    if std == "std"
                        && sync == "sync"
                        && mpsc == "mpsc"
                        && channel == "channel"
            ) || matches!(path, [mpsc, channel] if mpsc == "mpsc" && channel == "channel")
                || matches!(path, [unbounded] if unbounded == "unbounded_channel")
                || matches!(path, [tokio, spawn] if tokio == "tokio" && spawn == "spawn")
                || matches!(
                    path,
                    [async_std, task, spawn]
                        if async_std == "async_std" && task == "task" && spawn == "spawn"
                )))
}

fn matches_forbidden_function_item(path: &[String]) -> bool {
    is_direct_thread_spawn(path)
        || matches!(
            path,
            [std, sync, mpsc, channel]
                if std == "std"
                    && sync == "sync"
                    && mpsc == "mpsc"
                    && channel == "channel"
        )
        || matches!(
            path,
            [std, thread, builder, spawn]
                if std == "std"
                    && thread == "thread"
                    && builder == "Builder"
                    && spawn == "spawn"
        )
        || matches!(
            path,
            [std, thread, scope, spawn]
                if std == "std"
                    && thread == "thread"
                    && scope == "Scope"
                    && spawn == "spawn"
        )
        || matches_vec_deque_new(path)
}

fn matches_vec_deque_new(path: &[String]) -> bool {
    matches!(
        path,
        [std, collections, queue, new]
            if std == "std"
                && collections == "collections"
                && queue == "VecDeque"
                && new == "new"
    ) || matches!(path, [queue, new] if queue == "VecDeque" && new == "new")
}

fn source_path_at(tokens: &[UseToken], start: usize) -> Option<SourcePath> {
    let first = identifier_at(tokens, start)?;
    let mut segments = vec![first.to_owned()];
    let mut cursor = start + 1;
    loop {
        cursor = skip_turbofish(tokens, cursor)?;
        while tokens.get(cursor) == Some(&UseToken::CloseParenthesis) {
            cursor += 1;
        }
        if tokens.get(cursor) != Some(&UseToken::PathSeparator) {
            break;
        }
        cursor += 1;
        while tokens.get(cursor) == Some(&UseToken::OpenParenthesis) {
            cursor += 1;
        }
        let Some(segment) = identifier_at(tokens, cursor) else {
            break;
        };
        segments.push(segment.to_owned());
        cursor += 1;
    }
    Some(SourcePath {
        segments,
        end: cursor,
    })
}

fn skip_turbofish(tokens: &[UseToken], cursor: usize) -> Option<usize> {
    if tokens.get(cursor) != Some(&UseToken::PathSeparator)
        || tokens.get(cursor + 1) != Some(&UseToken::Less)
    {
        return Some(cursor);
    }
    let mut cursor = cursor + 2;
    let mut depth = 1_usize;
    while depth > 0 {
        match tokens.get(cursor) {
            Some(UseToken::Less) => depth += 1,
            Some(UseToken::Greater) => depth = depth.checked_sub(1)?,
            None => return None,
            _ => {},
        }
        cursor += 1;
    }
    Some(cursor)
}

fn path_is_called(tokens: &[UseToken], mut cursor: usize) -> bool {
    while tokens.get(cursor) == Some(&UseToken::CloseParenthesis) {
        cursor += 1;
    }
    tokens.get(cursor) == Some(&UseToken::OpenParenthesis)
}

fn method_spawn_lines(tokens: &[SourceToken]) -> Vec<usize> {
    tokens
        .iter()
        .enumerate()
        .filter(|(cursor, token)| {
            if token.kind != UseToken::Dot
                || !matches!(
                    source_identifier_at(tokens, cursor + 1),
                    Some("spawn" | "spawn_scoped")
                )
            {
                return false;
            }
            let mut next = cursor + 2;
            if tokens.get(next).map(|token| &token.kind) == Some(&UseToken::PathSeparator)
                && tokens.get(next + 1).map(|token| &token.kind) == Some(&UseToken::Less)
            {
                next += 2;
                let mut depth = 1_usize;
                while depth > 0 {
                    match tokens.get(next).map(|token| &token.kind) {
                        Some(UseToken::Less) => depth += 1,
                        Some(UseToken::Greater) => depth -= 1,
                        None => return false,
                        _ => {},
                    }
                    next += 1;
                }
            }
            tokens.get(next).map(|token| &token.kind) == Some(&UseToken::OpenParenthesis)
        })
        .filter_map(|(cursor, _)| tokens.get(cursor).map(|token| token.line))
        .collect()
}

fn parse_use_tree(
    tokens: &[UseToken],
    cursor: &mut usize,
    prefix: &[String],
    bindings: &mut Vec<(Vec<String>, String)>,
    globs: &mut Vec<Vec<String>>,
) -> Result<(), XtaskError> {
    if tokens.get(*cursor) == Some(&UseToken::Glob) {
        globs.push(prefix.to_vec());
        *cursor += 1;
        return Ok(());
    }
    let mut path = prefix.to_vec();
    let Some(first) = identifier_at(tokens, *cursor) else {
        return Err(XtaskError::invalid(
            "concurrency source policy",
            "Rust use tree omitted an imported identifier",
        ));
    };
    *cursor += 1;
    if first == "self" {
        if path.is_empty() {
            return Err(XtaskError::invalid(
                "concurrency source policy",
                "Rust use tree used self without a parent path",
            ));
        }
    } else {
        path.push(first.to_owned());
    }

    while tokens.get(*cursor) == Some(&UseToken::PathSeparator) {
        *cursor += 1;
        if tokens.get(*cursor) == Some(&UseToken::OpenGroup) {
            break;
        }
        let Some(segment) = identifier_at(tokens, *cursor) else {
            if tokens.get(*cursor) == Some(&UseToken::Glob) {
                globs.push(path);
                *cursor += 1;
                return Ok(());
            }
            return Err(XtaskError::invalid(
                "concurrency source policy",
                "Rust use path ended after a path separator",
            ));
        };
        path.push(segment.to_owned());
        *cursor += 1;
    }

    if tokens.get(*cursor) == Some(&UseToken::OpenGroup) {
        *cursor += 1;
        loop {
            if tokens.get(*cursor) == Some(&UseToken::CloseGroup) {
                *cursor += 1;
                return Ok(());
            }
            parse_use_tree(tokens, cursor, &path, bindings, globs)?;
            match tokens.get(*cursor) {
                Some(UseToken::Comma) => *cursor += 1,
                Some(UseToken::CloseGroup) => {
                    *cursor += 1;
                    return Ok(());
                },
                _ => {
                    return Err(XtaskError::invalid(
                        "concurrency source policy",
                        "Rust use group contains an unregistered separator",
                    ));
                },
            }
        }
    }

    let local = if identifier_at(tokens, *cursor) == Some("as") {
        *cursor += 1;
        let Some(alias) = identifier_at(tokens, *cursor) else {
            return Err(XtaskError::invalid(
                "concurrency source policy",
                "Rust use alias omitted its local identifier",
            ));
        };
        *cursor += 1;
        alias.to_owned()
    } else {
        path.last().cloned().ok_or_else(|| {
            XtaskError::invalid(
                "concurrency source policy",
                "Rust use tree resolved to an empty path",
            )
        })?
    };
    bindings.push((path, local));
    Ok(())
}

fn identifier_at(tokens: &[UseToken], cursor: usize) -> Option<&str> {
    match tokens.get(cursor) {
        Some(UseToken::Identifier(identifier)) => Some(identifier),
        _ => None,
    }
}

fn source_identifier_at(tokens: &[SourceToken], cursor: usize) -> Option<&str> {
    match tokens.get(cursor).map(|token| &token.kind) {
        Some(UseToken::Identifier(identifier)) => Some(identifier),
        _ => None,
    }
}

fn source_tokens(source: &str) -> Vec<SourceToken> {
    let mut tokens = Vec::new();
    let mut characters = source.chars().peekable();
    let mut line = 1_usize;
    while let Some(character) = characters.next() {
        if character == '\n' {
            line += 1;
            continue;
        }
        let raw_identifier_start = if character == 'r' && characters.peek() == Some(&'#') {
            let mut lookahead = characters.clone();
            let _hash = lookahead.next();
            lookahead
                .next()
                .filter(|next| next.is_ascii_alphabetic() || *next == '_')
        } else {
            None
        };
        if let Some(first) = raw_identifier_start {
            let _hash = characters.next();
            let _first = characters.next();
            let mut identifier = String::from(first);
            while characters
                .peek()
                .is_some_and(|next| next.is_ascii_alphanumeric() || *next == '_')
            {
                if let Some(next) = characters.next() {
                    identifier.push(next);
                }
            }
            tokens.push(SourceToken {
                kind: UseToken::Identifier(identifier),
                line,
            });
        } else if character.is_ascii_alphabetic() || character == '_' {
            let mut identifier = String::from(character);
            while characters
                .peek()
                .is_some_and(|next| next.is_ascii_alphanumeric() || *next == '_')
            {
                if let Some(next) = characters.next() {
                    identifier.push(next);
                }
            }
            tokens.push(SourceToken {
                kind: UseToken::Identifier(identifier),
                line,
            });
        } else {
            let token = match character {
                ':' if characters.peek() == Some(&':') => {
                    let _ = characters.next();
                    Some(UseToken::PathSeparator)
                },
                '{' => Some(UseToken::OpenGroup),
                '}' => Some(UseToken::CloseGroup),
                ',' => Some(UseToken::Comma),
                ';' => Some(UseToken::Semicolon),
                '=' => Some(UseToken::Equals),
                '*' => Some(UseToken::Glob),
                '(' => Some(UseToken::OpenParenthesis),
                ')' => Some(UseToken::CloseParenthesis),
                '.' => Some(UseToken::Dot),
                '<' => Some(UseToken::Less),
                '>' => Some(UseToken::Greater),
                _ => None,
            };
            if let Some(kind) = token {
                tokens.push(SourceToken { kind, line });
            }
        }
    }
    tokens
}

fn tokenized_source(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut characters = source.chars().peekable();
    let mut block_comment = false;
    let mut quoted = None;
    while let Some(character) = characters.next() {
        if block_comment {
            if character == '*' && characters.peek() == Some(&'/') {
                let _ = characters.next();
                output.push_str("  ");
                block_comment = false;
            } else if character == '\n' {
                output.push('\n');
            } else {
                output.push(' ');
            }
            continue;
        }
        if let Some(quote) = quoted {
            if character == '\\' {
                output.push(' ');
                if let Some(next) = characters.next() {
                    output.push(if next == '\n' { '\n' } else { ' ' });
                }
            } else if character == quote {
                output.push(' ');
                quoted = None;
            } else {
                output.push(if character == '\n' { '\n' } else { ' ' });
            }
            continue;
        }
        if character == '/' && characters.peek() == Some(&'/') {
            let _ = characters.next();
            output.push_str("  ");
            for next in characters.by_ref() {
                output.push(if next == '\n' { '\n' } else { ' ' });
                if next == '\n' {
                    break;
                }
            }
        } else if character == '/' && characters.peek() == Some(&'*') {
            let _ = characters.next();
            output.push_str("  ");
            block_comment = true;
        } else if character == '"' {
            output.push(' ');
            quoted = Some(character);
        } else if character == '\'' {
            let mut lookahead = characters.clone();
            let first = lookahead.next();
            let second = lookahead.next();
            if first == Some('\\') || second == Some('\'') {
                output.push(' ');
                quoted = Some(character);
            } else {
                output.push(character);
            }
        } else {
            output.push(character);
        }
    }
    output
}
