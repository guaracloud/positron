use std::fs;
use std::path::{Path, PathBuf};

use super::canary::{LEAK_CANARY_ID, emit_candidate, read_bounded, scan_candidate};
use crate::error::XtaskError;

const MAXIMUM_ARTIFACT_BYTES: usize = 4_096;

fn root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("positron-{name}-{}", std::process::id()))
}

#[test]
fn executable_intentional_leak_is_rejected_by_parent_scanner() -> Result<(), XtaskError> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let artifact_root = root("canary-leak");
    fs::create_dir(&artifact_root)
        .map_err(|source| XtaskError::io("create leak test root", source))?;
    emit_candidate(&repository, &artifact_root, LEAK_CANARY_ID)?;
    assert!(scan_candidate(&repository, &artifact_root).is_err());
    fs::remove_dir_all(&artifact_root)
        .map_err(|source| XtaskError::io("remove leak test root", source))
}

#[test]
fn bounded_reader_accepts_boundary_and_rejects_oversize() -> Result<(), XtaskError> {
    let path = root("canary-bound");
    fs::write(&path, vec![b'x'; MAXIMUM_ARTIFACT_BYTES])
        .map_err(|source| XtaskError::io("write boundary artifact", source))?;
    assert_eq!(
        read_bounded(&path, MAXIMUM_ARTIFACT_BYTES, "test artifact")?.len(),
        MAXIMUM_ARTIFACT_BYTES
    );
    fs::write(&path, vec![b'x'; MAXIMUM_ARTIFACT_BYTES + 1])
        .map_err(|source| XtaskError::io("write oversize artifact", source))?;
    assert!(read_bounded(&path, MAXIMUM_ARTIFACT_BYTES, "test artifact").is_err());
    fs::remove_file(&path).map_err(|source| XtaskError::io("remove bound artifact", source))
}
