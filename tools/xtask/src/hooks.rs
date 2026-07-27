use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::XtaskError;

pub(crate) fn install() -> Result<(), XtaskError> {
    let root = workspace_root()?;
    validate_repository_hooks(&root)?;

    let status = Command::new("git")
        .current_dir(&root)
        .args(["config", "--local", "core.hooksPath", ".githooks"])
        .status()
        .map_err(|source| XtaskError::io("configure repository Git hooks", source))?;

    if !status.success() {
        return Err(XtaskError::command(
            "git config --local core.hooksPath .githooks",
            format!("exit status {status}"),
        ));
    }

    println!(
        "Configured repository hooks for {}. Global Git configuration was not changed.",
        root.display()
    );
    Ok(())
}

pub(crate) fn validate_repository_hooks(root: &Path) -> Result<(), XtaskError> {
    let hooks = root.join(".githooks");
    ensure_hook_exists(&hooks.join("pre-commit"))?;
    ensure_hook_exists(&hooks.join("pre-push"))?;
    Ok(())
}

pub(crate) fn workspace_root() -> Result<PathBuf, XtaskError> {
    let mut candidate =
        env::current_dir().map_err(|source| XtaskError::io("read current directory", source))?;

    loop {
        let manifest = candidate.join("Cargo.toml");
        if manifest.is_file() {
            let content = std::fs::read_to_string(&manifest).map_err(|source| {
                XtaskError::io(
                    format!("read workspace manifest {}", manifest.display()),
                    source,
                )
            })?;
            if content.lines().any(|line| line.trim() == "[workspace]") {
                return Ok(candidate);
            }
        }

        if !candidate.pop() {
            return Err(XtaskError::invalid(
                "workspace",
                "could not find a Cargo.toml containing [workspace]",
            ));
        }
    }
}

fn ensure_hook_exists(path: &Path) -> Result<(), XtaskError> {
    if !path.is_file() {
        return Err(XtaskError::invalid_path(
            path,
            "required repository-managed hook is missing",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = std::fs::metadata(path)
            .map_err(|source| XtaskError::io(format!("read hook mode {}", path.display()), source))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(XtaskError::invalid_path(
                path,
                "repository-managed hook is not executable",
            ));
        }
    }

    Ok(())
}
