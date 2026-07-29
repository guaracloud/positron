//! Source-policy enforcement for registered concurrency primitives.
//!
//! This module owns the fail-closed scan that reconciles active tooling spawn
//! sites with their registry and resolves Rust `use` trees before checking for
//! forbidden spawn and unbounded-resource invocations.

use std::collections::BTreeMap;
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
        let test_start = ["\n#[cfg(test)]", "\n#[cfg(all(test,"]
            .into_iter()
            .filter_map(|marker| tokenized.find(marker))
            .min();
        let production = test_start
            .and_then(|index| tokenized.get(..index))
            .unwrap_or(&tokenized);
        let compact = production
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();

        reject_forbidden_invocations(&source, production, &compact)?;

        let production_line_count = production.lines().count();
        let markers = source_text
            .lines()
            .take(production_line_count)
            .enumerate()
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
    for invocation in resolved_forbidden_import_invocations(production)? {
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
    Glob,
}

fn resolved_forbidden_import_invocations(source: &str) -> Result<Vec<String>, XtaskError> {
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
                '*' => Some(UseToken::Glob),
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
