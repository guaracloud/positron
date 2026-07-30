//! Rust tokenization, test-item masking, and import alias resolution.

use std::collections::BTreeMap;

use crate::error::XtaskError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum UseToken {
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
pub(super) struct SourceToken {
    pub(super) kind: UseToken,
    pub(super) line: usize,
}

pub(super) fn resolved_import_aliases(
    tokens: &[UseToken],
    globs: &mut Vec<Vec<String>>,
) -> Result<BTreeMap<String, Vec<String>>, XtaskError> {
    let mut bindings = Vec::new();
    let mut cursor = 0;
    while cursor < tokens.len() {
        if identifier_at(tokens, cursor) == Some("extern")
            && identifier_at(tokens, cursor + 1) == Some("crate")
        {
            let Some(root) = identifier_at(tokens, cursor + 2) else {
                return Err(XtaskError::invalid(
                    "concurrency source policy",
                    "Rust extern crate declaration omitted its root",
                ));
            };
            cursor += 3;
            if identifier_at(tokens, cursor) == Some("as") {
                let Some(alias) = identifier_at(tokens, cursor + 1) else {
                    return Err(XtaskError::invalid(
                        "concurrency source policy",
                        "Rust extern crate alias omitted its local identifier",
                    ));
                };
                bindings.push((vec![root.to_owned()], alias.to_owned()));
                cursor += 2;
            }
            if tokens.get(cursor) != Some(&UseToken::Semicolon) {
                return Err(XtaskError::invalid(
                    "concurrency source policy",
                    "Rust extern crate declaration did not terminate at its registered boundary",
                ));
            }
            cursor += 1;
            continue;
        }
        if identifier_at(tokens, cursor) != Some("use") {
            cursor += 1;
            continue;
        }
        cursor += 1;
        parse_use_tree(tokens, &mut cursor, &[], &mut bindings, globs)?;
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
    Ok(aliases)
}

pub(super) fn resolve_alias_path(
    path: &[String],
    aliases: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
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

pub(super) fn source_tokens(source: &str) -> Vec<SourceToken> {
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

pub(super) fn tokenized_source(source: &str) -> String {
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
