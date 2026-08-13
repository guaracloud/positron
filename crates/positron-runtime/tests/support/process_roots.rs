use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use positron_kernel::MountQualification;

pub struct TestRoots {
    parent: PathBuf,
    pub data: PathBuf,
    secrets: PathBuf,
}

impl TestRoots {
    pub fn new(label: &str) -> Result<Self, std::io::Error> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let parent = std::env::temp_dir().join(format!(
            "positron-runtime-{label}-{}-{nonce}",
            std::process::id()
        ));
        let data = parent.join("data");
        let secrets = parent.join("secrets");
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&secrets)?;
        set_owner_only(&secrets)?;
        Ok(Self {
            parent,
            data,
            secrets,
        })
    }

    pub fn bootstrap_paths(
        &self,
    ) -> Result<positron_runtime::BootstrapPaths, Box<dyn std::error::Error>> {
        Ok(positron_runtime::BootstrapPaths::new(
            &self.data,
            &self.secrets,
            MountQualification::LocalHost,
        )?)
    }

    pub fn acquire_volume_again(
        &self,
    ) -> Result<positron_kernel::OwnedPrimaryDataVolume, positron_kernel::VolumeFailure> {
        positron_kernel::PrimaryDataVolume::acquire(&self.data, MountQualification::LocalHost)
    }
}

#[cfg(unix)]
fn set_owner_only(path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

impl Drop for TestRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}
