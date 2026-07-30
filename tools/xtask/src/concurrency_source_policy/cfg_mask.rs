//! Complete-item masking for Rust test-only source.

use std::collections::BTreeSet;

use crate::error::XtaskError;

pub(super) fn mask_cfg_test_items(source: &str) -> Result<(String, BTreeSet<usize>), XtaskError> {
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
