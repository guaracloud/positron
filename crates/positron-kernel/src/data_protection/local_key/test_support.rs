use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

pub(super) struct SecurityRoot {
    pub(super) path: PathBuf,
    _directory: File,
}

impl SecurityRoot {
    pub(super) fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
            "positron-local-key-persistence-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        let directory = File::open(&path)?;
        Ok(Self {
            path,
            _directory: directory,
        })
    }
}

impl Drop for SecurityRoot {
    fn drop(&mut self) {
        let _result = std::fs::remove_dir_all(&self.path);
    }
}
