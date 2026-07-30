//! Exact concurrency and growable-resource policy matching.

use std::path::Path;

use crate::error::XtaskError;

use super::syntax::{SourceToken, UseToken, resolve_alias_path, resolved_import_aliases};

pub(super) fn reject_forbidden_invocations(
    source: &Path,
    tokens: &[SourceToken],
) -> Result<(), XtaskError> {
    let kinds = tokens
        .iter()
        .map(|token| token.kind.clone())
        .collect::<Vec<_>>();
    let mut globs = Vec::new();
    let aliases = resolved_import_aliases(&kinds, &mut globs)?;
    for glob in &globs {
        let resolved = resolve_alias_path(glob, &aliases);
        if matches!(
            resolved.as_slice(),
            [std, thread] if std == "std" && thread == "thread"
        ) || matches!(resolved.as_slice(), [tokio] if tokio == "tokio")
            || matches!(
                resolved.as_slice(),
                [tokio, sync, mpsc]
                    if tokio == "tokio" && sync == "sync" && mpsc == "mpsc"
            )
            || matches!(
                resolved.as_slice(),
                [std, sync, mpsc] if std == "std" && sync == "sync" && mpsc == "mpsc"
            )
            || matches!(
                resolved.as_slice(),
                [async_std, task] if async_std == "async_std" && task == "task"
            )
            || matches!(
                resolved.as_slice(),
                [std, collections] if std == "std" && collections == "collections"
            )
            || is_resolved_vec_deque_reference(&resolved)
        {
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
        let resolved = resolve_alias_path(&path.segments, &aliases);
        if matches_forbidden_function_item(&resolved) {
            return Err(XtaskError::invalid_path(
                source,
                "unregistered imported concurrency primitive alias in activated tooling source",
            ));
        }
    }
    Ok(())
}

struct SourcePath {
    segments: Vec<String>,
    end: usize,
}

fn is_direct_thread_spawn(path: &[String]) -> bool {
    matches!(
        path,
        [std, thread, spawn]
            if std == "std" && thread == "thread" && spawn == "spawn"
    ) || matches!(path, [thread, spawn] if thread == "thread" && spawn == "spawn")
}

fn is_direct_unbounded_primitive(path: &[String], called: bool) -> bool {
    is_resolved_vec_deque_reference(path)
        || (called
            && (matches!(
                path,
                [std, sync, mpsc, channel]
                    if std == "std"
                        && sync == "sync"
                        && mpsc == "mpsc"
                        && channel == "channel"
            ) || matches!(path, [mpsc, channel] if mpsc == "mpsc" && channel == "channel")
                || matches!(path, [tokio, spawn] if tokio == "tokio" && spawn == "spawn")
                || matches!(
                    path,
                    [async_std, task, spawn]
                        if async_std == "async_std" && task == "task" && spawn == "spawn"
                )))
}

fn matches_forbidden_function_item(path: &[String]) -> bool {
    is_direct_thread_spawn(path)
        || matches!(path, [tokio, spawn] if tokio == "tokio" && spawn == "spawn")
        || matches!(
            path,
            [async_std, task, spawn]
                if async_std == "async_std" && task == "task" && spawn == "spawn"
        )
        || matches!(
            path,
            [tokio, sync, mpsc, unbounded]
                if tokio == "tokio"
                    && sync == "sync"
                    && mpsc == "mpsc"
                    && unbounded == "unbounded_channel"
        )
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
        || is_resolved_vec_deque_reference(path)
}

fn is_resolved_vec_deque_reference(path: &[String]) -> bool {
    matches!(
        path,
        [std, collections, queue, ..]
            if std == "std"
                && collections == "collections"
                && queue == "VecDeque"
    )
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

pub(super) fn method_spawn_lines(tokens: &[SourceToken]) -> Vec<usize> {
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
