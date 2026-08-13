use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::BootstrapPaths;
use positron_kernel::MountQualification;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

pub(super) struct Roots {
    parent: PathBuf,
}

impl Roots {
    pub(super) fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let parent = std::env::temp_dir().join(format!(
            "positron-instance-bootstrap-unit-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&parent)?;
        fs::create_dir(parent.join("data"))?;
        fs::create_dir(parent.join("secrets"))?;
        set_owner_only(&parent.join("secrets"))?;
        Ok(Self { parent })
    }

    pub(super) fn paths(&self) -> BootstrapPaths {
        BootstrapPaths::new(
            &self.parent.join("data"),
            &self.parent.join("secrets"),
            MountQualification::LocalHost,
        )
        .expect("test roots are distinct")
    }

    pub(super) fn parent(&self) -> &Path {
        &self.parent
    }
}

impl Drop for Roots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}
