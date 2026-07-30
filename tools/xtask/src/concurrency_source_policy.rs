//! Source-policy enforcement for registered concurrency primitives.
//!
//! This owner reconciles active tooling spawn sites with their registry.
//! Tokenization and import resolution are isolated from policy matching.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::error::XtaskError;

mod cfg_mask;
mod matcher;
mod syntax;

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
        let tokenized = syntax::tokenized_source(&source_text);
        let (production, excluded_test_lines) = cfg_mask::mask_cfg_test_items(&tokenized)?;
        let tokens = syntax::source_tokens(&production);
        matcher::reject_forbidden_invocations(&source, &tokens)?;

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
        let spawn_lines = matcher::method_spawn_lines(&tokens);
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
