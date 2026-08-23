use crate::{QueryFailure, QueryFailureCode};

const MAX_SQL_TOKENS: usize = 128;
const MAX_SQL_NESTING: usize = 16;

pub(crate) fn tokenize(source: &str) -> Result<Vec<&str>, QueryFailure> {
    let mut tokens = Vec::new();
    tokens
        .try_reserve_exact(source.len().min(MAX_SQL_TOKENS))
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let mut start = None;
    let mut quoted = false;
    let mut escaped = false;
    let mut nesting = 0_usize;
    let mut index = 0_usize;
    while index < source.len() {
        let character = source
            .get(index..)
            .and_then(|remaining| remaining.chars().next())
            .ok_or_else(unsupported)?;
        let width = character.len_utf8();
        if quoted {
            if escaped {
                if !matches!(character, '"' | '\\' | '|') {
                    return Err(unsupported());
                }
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            index = index.checked_add(width).ok_or_else(unsupported)?;
            continue;
        }
        if character == '"' {
            quoted = true;
            if start.is_none() {
                start = Some(index);
            }
        } else if character == '(' {
            nesting = nesting.checked_add(1).ok_or_else(unsupported)?;
            if nesting > MAX_SQL_NESTING {
                return Err(unsupported());
            }
            if start.is_none() {
                start = Some(index);
            }
        } else if character == ')' {
            if nesting == 0 {
                return Err(unsupported());
            }
            nesting -= 1;
        }
        let boundary = !quoted && nesting == 0 && character.is_ascii_whitespace();
        let punctuation =
            !quoted && nesting == 0 && matches!(character, ',' | '=' | '>' | '<' | '~');
        if punctuation {
            if let Some(begin) = start.take() {
                push_token(
                    &mut tokens,
                    source.get(begin..index).ok_or_else(unsupported)?,
                )?;
            }
            let next = source
                .get(index + width..)
                .and_then(|value| value.chars().next());
            let operator_width = if matches!(character, '=' | '>' | '<') && next == Some('=') {
                width + 1
            } else {
                width
            };
            push_token(
                &mut tokens,
                source
                    .get(index..index + operator_width)
                    .ok_or_else(unsupported)?,
            )?;
            index = index.checked_add(operator_width).ok_or_else(unsupported)?;
            continue;
        }
        if boundary {
            if let Some(begin) = start.take() {
                push_token(
                    &mut tokens,
                    source.get(begin..index).ok_or_else(unsupported)?,
                )?;
            }
        } else if start.is_none() && !character.is_ascii_whitespace() {
            start = Some(index);
        }
        index = index.checked_add(width).ok_or_else(unsupported)?;
    }
    if quoted || escaped || nesting != 0 {
        return Err(unsupported());
    }
    if let Some(begin) = start {
        push_token(&mut tokens, source.get(begin..).ok_or_else(unsupported)?)?;
    }
    if tokens.is_empty() {
        return Err(unsupported());
    }
    Ok(tokens)
}

fn push_token<'source>(
    tokens: &mut Vec<&'source str>,
    token: &'source str,
) -> Result<(), QueryFailure> {
    if token.is_empty() {
        return Err(unsupported());
    }
    if tokens.len() >= MAX_SQL_TOKENS {
        return Err(unsupported());
    }
    tokens.push(token);
    Ok(())
}

fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}
