use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::{BootstrapPaths, BootstrapState};
use crate::InstanceBootstrap;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Roots(PathBuf);

impl Roots {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "positron-bootstrap-classification-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        fs::create_dir(root.join("data"))?;
        fs::create_dir(root.join("secrets"))?;
        Ok(Self(root))
    }

    fn paths(&self) -> BootstrapPaths {
        BootstrapPaths::new(&self.0.join("data"), &self.0.join("secrets"))
            .expect("test roots are distinct")
    }
}

impl Drop for Roots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn unknown_state_is_inconsistent_instead_of_empty() -> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    fs::write(roots.0.join("data/foreign"), b"state")?;
    assert_eq!(
        InstanceBootstrap::classify(&roots.paths())?,
        BootstrapState::Inconsistent
    );
    Ok(())
}

#[test]
fn missing_key_is_resumable_only_before_protected_data_exists()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    fs::write(
        paths.data_root().join(".positron-bootstrap.pending"),
        super::super::storage::INTENT,
    )?;
    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Incomplete
    );

    fs::create_dir(paths.data_root().join("catalog"))?;
    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Inconsistent
    );
    Ok(())
}
