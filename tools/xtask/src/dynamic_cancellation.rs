//! Production-owned cancellation source for dynamic-quality execution.
//!
//! The ordinary quality command uses a quiescent token and no marker. This
//! typed internal seam adds an owned marker to that same controlled execution
//! path so lifecycle tests can trigger cancellation without rewriting source.

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};

use crate::error::XtaskError;
use crate::hooks;
use crate::quality::{self, Options};

pub(crate) fn run(mut arguments: impl Iterator<Item = String>) -> Result<(), XtaskError> {
    let profile_flag = arguments.next();
    let profile = arguments.next();
    let marker_flag = arguments.next();
    let marker = arguments.next();
    if profile_flag.as_deref() != Some("--profile")
        || marker_flag.as_deref() != Some("--ready-marker")
        || arguments.next().is_some()
    {
        return Err(XtaskError::usage(
            "quality-internal-cancel-dynamic requires `--profile pr|ext --ready-marker <absolute-owned-path>`"
                .to_owned(),
        ));
    }
    let profile = profile.ok_or_else(|| {
        XtaskError::usage("quality-internal-cancel-dynamic requires a profile".to_owned())
    })?;
    if !matches!(profile.as_str(), "pr" | "ext") {
        return Err(XtaskError::usage(
            "quality-internal-cancel-dynamic profile must select EG-DYNAMIC".to_owned(),
        ));
    }
    let options = Options::parse(["--profile".to_owned(), profile].into_iter())?;
    let marker = PathBuf::from(marker.ok_or_else(|| {
        XtaskError::usage("quality-internal-cancel-dynamic requires a readiness marker".to_owned())
    })?);
    let root = hooks::workspace_root()?;
    validate_marker(&root, &marker)?;
    quality::run_with_dynamic_cancellation(&options, Arc::new(AtomicBool::new(false)), Some(marker))
}

fn validate_marker(root: &Path, marker: &Path) -> Result<(), XtaskError> {
    let owned = root.join("target/quality-tools");
    let owned_identity = fs::canonicalize(&owned).map_err(|source| {
        XtaskError::io(
            format!("resolve dynamic cancellation owner {}", owned.display()),
            source,
        )
    })?;
    let marker_parent = marker.parent().ok_or_else(|| {
        XtaskError::invalid_path(
            marker,
            "internal dynamic cancellation marker must have an owned parent",
        )
    })?;
    let marker_parent_identity = fs::canonicalize(marker_parent).map_err(|source| {
        XtaskError::io(
            format!(
                "resolve dynamic cancellation marker parent {}",
                marker_parent.display()
            ),
            source,
        )
    })?;
    if !marker.is_absolute()
        || !marker_parent_identity.starts_with(&owned_identity)
        || marker
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || marker.exists()
    {
        return Err(XtaskError::invalid_path(
            marker,
            "internal dynamic cancellation marker must be a new absolute path inside target/quality-tools",
        ));
    }
    Ok(())
}
