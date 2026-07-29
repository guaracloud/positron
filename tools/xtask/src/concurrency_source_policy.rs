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
        let compact = production
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();

        reject_forbidden_invocations(&source, &production, &compact)?;

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
        let spawn_count = compact.match_indices(".spawn(").count();
        if spawn_count != markers.len() {
            return Err(XtaskError::invalid_path(
                &source,
                "unregistered process or task spawn: every active method spawn must have exactly one registered marker",
            ));
        }
        for (line_number, symbol, id) in markers {
            let key = (relative.clone(), symbol, id);
            let Some(kind) = registered.get(&key) else {
                return Err(XtaskError::invalid_path(
                    &source,
                    format!("unregistered semantic spawn site at tooling line {line_number}"),
                ));
            };
            let actual = if key.2 == registered_thread_site {
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

fn reject_forbidden_invocations(
    source: &Path,
    production: &str,
    compact: &str,
) -> Result<(), XtaskError> {
    if invocation_exists(compact, "std::thread::spawn")
        || invocation_exists(compact, "thread::spawn")
    {
        return Err(XtaskError::invalid_path(
            source,
            "direct unregistered thread spawn in activated tooling source",
        ));
    }
    if [
        "std::sync::mpsc::channel",
        "mpsc::channel",
        "unbounded_channel",
        "VecDeque::new",
        "tokio::spawn",
        "async_std::task::spawn",
    ]
    .into_iter()
    .any(|primitive| invocation_exists(compact, primitive))
    {
        return Err(XtaskError::invalid_path(
            source,
            "unbounded concurrency primitive in activated tooling source",
        ));
    }
    if ["std::thread::spawn", "std::sync::mpsc::channel"]
        .into_iter()
        .any(|primitive| compact.contains(&format!("={primitive};")))
    {
        return Err(XtaskError::invalid_path(
            source,
            "unregistered imported concurrency primitive alias in activated tooling source",
        ));
    }
    for invocation in resolved_forbidden_binding_invocations(production)? {
        if invocation_exists(compact, &invocation) {
            return Err(XtaskError::invalid_path(
                source,
                "unregistered imported concurrency primitive alias in activated tooling source",
            ));
        }
    }
    Ok(())
}

fn invocation_exists(compact: &str, path: &str) -> bool {
    compact.contains(&format!("{path}(")) || compact.contains(&format!("{path}::<"))
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
}

fn resolved_forbidden_binding_invocations(source: &str) -> Result<Vec<String>, XtaskError> {
    let tokens = use_tokens(source);
    let mut bindings = Vec::new();
    let mut cursor = 0;
    while cursor < tokens.len() {
        if identifier_at(&tokens, cursor) != Some("use") {
            cursor += 1;
            continue;
        }
        cursor += 1;
        parse_use_tree(&tokens, &mut cursor, &[], &mut bindings)?;
        if tokens.get(cursor) != Some(&UseToken::Semicolon) {
            return Err(XtaskError::invalid(
                "concurrency source policy",
                "Rust use tree did not terminate at its registered boundary",
            ));
        }
        cursor += 1;
    }
    let mut invocations = Vec::new();
    for (path, local) in bindings {
        let suffixes: &[&str] = match path.as_slice() {
            [std, thread, spawn] if std == "std" && thread == "thread" && spawn == "spawn" => &[""],
            [std, sync, mpsc, channel]
                if std == "std" && sync == "sync" && mpsc == "mpsc" && channel == "channel" =>
            {
                &[""]
            },
            [std, thread] if std == "std" && thread == "thread" => &["::spawn"],
            [std, sync, mpsc] if std == "std" && sync == "sync" && mpsc == "mpsc" => &["::channel"],
            [std, sync] if std == "std" && sync == "sync" => &["::mpsc::channel"],
            [std] if std == "std" => &["::thread::spawn", "::sync::mpsc::channel"],
            _ => &[],
        };
        invocations.extend(suffixes.iter().map(|suffix| format!("{local}{suffix}")));
    }
    let mut paths = invocations
        .iter()
        .map(|invocation| invocation.split("::").map(str::to_owned).collect())
        .collect::<Vec<Vec<String>>>();
    paths.extend([
        vec!["std".to_owned(), "thread".to_owned(), "spawn".to_owned()],
        vec![
            "std".to_owned(),
            "sync".to_owned(),
            "mpsc".to_owned(),
            "channel".to_owned(),
        ],
    ]);
    loop {
        let mut changed = false;
        let mut cursor = 0;
        while cursor < tokens.len() {
            if identifier_at(&tokens, cursor) != Some("let") {
                cursor += 1;
                continue;
            }
            cursor += 1;
            if identifier_at(&tokens, cursor) == Some("mut") {
                cursor += 1;
            }
            let Some(local) = identifier_at(&tokens, cursor) else {
                continue;
            };
            cursor += 1;
            while !matches!(
                tokens.get(cursor),
                Some(UseToken::Equals | UseToken::Semicolon) | None
            ) {
                cursor += 1;
            }
            if tokens.get(cursor) != Some(&UseToken::Equals) {
                continue;
            }
            cursor += 1;
            let mut parenthesis_depth = 0_usize;
            while tokens.get(cursor) == Some(&UseToken::OpenParenthesis) {
                parenthesis_depth += 1;
                cursor += 1;
            }
            let Some(first) = identifier_at(&tokens, cursor) else {
                continue;
            };
            let mut right_hand_side = vec![first.to_owned()];
            cursor += 1;
            while tokens.get(cursor) == Some(&UseToken::PathSeparator) {
                cursor += 1;
                let Some(segment) = identifier_at(&tokens, cursor) else {
                    break;
                };
                right_hand_side.push(segment.to_owned());
                cursor += 1;
            }
            while parenthesis_depth > 0 && tokens.get(cursor) == Some(&UseToken::CloseParenthesis) {
                parenthesis_depth -= 1;
                cursor += 1;
            }
            if tokens.get(cursor) != Some(&UseToken::Semicolon)
                || !paths.contains(&right_hand_side)
                || parenthesis_depth != 0
            {
                continue;
            }
            let rebound = vec![local.to_owned()];
            if !paths.contains(&rebound) {
                invocations.push(local.to_owned());
                paths.push(rebound);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(invocations)
}

fn parse_use_tree(
    tokens: &[UseToken],
    cursor: &mut usize,
    prefix: &[String],
    bindings: &mut Vec<(Vec<String>, String)>,
) -> Result<(), XtaskError> {
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
            parse_use_tree(tokens, cursor, &path, bindings)?;
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

fn use_tokens(source: &str) -> Vec<UseToken> {
    let mut tokens = Vec::new();
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        if character.is_ascii_alphabetic() || character == '_' {
            let mut identifier = String::from(character);
            while characters
                .peek()
                .is_some_and(|next| next.is_ascii_alphanumeric() || *next == '_')
            {
                if let Some(next) = characters.next() {
                    identifier.push(next);
                }
            }
            tokens.push(UseToken::Identifier(identifier));
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
                _ => None,
            };
            if let Some(token) = token {
                tokens.push(token);
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
