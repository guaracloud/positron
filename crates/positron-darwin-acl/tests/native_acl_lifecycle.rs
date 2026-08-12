//! Cross-crate contract tests for the descriptor-authoritative Darwin ACL leaf.
//!
//! Issue #27 supplies this real filesystem primitive to the kernel. Paired-root
//! classification, proof issuance, and runtime composition remain owned by #31.

#![cfg(target_os = "macos")]

use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_darwin_acl::{ExtendedAclPresence, extended_acl_presence};

static NEXT_NATIVE_PATH: AtomicU64 = AtomicU64::new(0);

#[test]
fn native_acl_lifecycle_is_descriptor_authoritative() -> Result<(), Box<dyn std::error::Error>> {
    let root = NativeTestRoot::create()?;
    let file_path = root.path.join("key");
    let replacement_path = root.path.join("replacement");
    let original = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file_path)?;
    assert_eq!(
        extended_acl_presence(root.directory.as_fd())?,
        ExtendedAclPresence::Absent
    );
    assert_eq!(
        extended_acl_presence(original.as_fd())?,
        ExtendedAclPresence::Absent
    );

    chmod(&["+a", "everyone allow read", path_text(&file_path)?])?;
    assert_eq!(
        extended_acl_presence(original.as_fd())?,
        ExtendedAclPresence::Present
    );
    chmod(&["600", path_text(&file_path)?])?;
    assert_eq!(
        extended_acl_presence(original.as_fd())?,
        ExtendedAclPresence::Present
    );
    chmod(&["-a#", "0", path_text(&file_path)?])?;
    assert_eq!(
        extended_acl_presence(original.as_fd())?,
        ExtendedAclPresence::Absent
    );

    chmod(&[
        "+a",
        "everyone allow read,file_inherit,directory_inherit",
        path_text(&root.path)?,
    ])?;
    assert_eq!(
        extended_acl_presence(root.directory.as_fd())?,
        ExtendedAclPresence::Present
    );
    let inherited_path = root.path.join("inherited");
    let inherited = File::create(&inherited_path)?;
    assert_eq!(
        extended_acl_presence(inherited.as_fd())?,
        ExtendedAclPresence::Present
    );
    chmod(&["-a#", "0", path_text(&root.path)?])?;

    let replacement = File::create(&replacement_path)?;
    let read_only = File::open(&replacement_path)?;
    chmod(&["+a", "everyone deny read", path_text(&replacement_path)?])?;
    std::fs::rename(&replacement_path, &file_path)?;
    assert_eq!(
        extended_acl_presence(original.as_fd())?,
        ExtendedAclPresence::Absent
    );
    assert_eq!(
        extended_acl_presence(replacement.as_fd())?,
        ExtendedAclPresence::Present
    );
    assert_eq!(
        extended_acl_presence(read_only.as_fd())?,
        ExtendedAclPresence::Present
    );
    assert_eq!(read_only.metadata()?.len(), 0);
    Ok(())
}

fn chmod(arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("/bin/chmod").args(arguments).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("chmod fixture command failed with {status}").into())
    }
}

fn path_text(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str()
        .ok_or_else(|| "native ACL fixture path was not UTF-8".into())
}

struct NativeTestRoot {
    path: PathBuf,
    directory: File,
}

impl NativeTestRoot {
    fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "positron-darwin-acl-integration-{}-{}",
            std::process::id(),
            NEXT_NATIVE_PATH.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        let directory = File::open(&path)?;
        Ok(Self { path, directory })
    }
}

impl Drop for NativeTestRoot {
    fn drop(&mut self) {
        let _result = std::fs::remove_dir_all(&self.path);
    }
}
