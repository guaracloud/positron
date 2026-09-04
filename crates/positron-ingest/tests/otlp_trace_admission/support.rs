use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct TemporaryRoots {
    root: PathBuf,
}

pub fn temporary_roots() -> Result<TemporaryRoots, std::io::Error> {
    TemporaryRoots::new()
}

impl TemporaryRoots {
    fn new() -> Result<Self, std::io::Error> {
        static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "positron-ingest-traces-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        fs::create_dir(root.join("data"))?;
        fs::create_dir(root.join("secrets"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("secrets"), fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { root })
    }

    pub fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    pub fn secrets(&self) -> PathBuf {
        self.root.join("secrets")
    }
}

impl Drop for TemporaryRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
