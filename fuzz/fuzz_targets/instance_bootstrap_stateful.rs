#![no_main]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_runtime::{
    BootstrapFailureCode, BootstrapPaths, InitializationPlan, InstanceBootstrap,
};
use positron_kernel::MountQualification;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct FuzzRoots {
    parent: PathBuf,
    data: PathBuf,
    secrets: PathBuf,
}

impl FuzzRoots {
    fn new() -> Option<Self> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let parent = std::env::temp_dir().join(format!(
            "positron-bootstrap-fuzz-{}-{sequence}",
            std::process::id()
        ));
        let data = parent.join("data");
        let secrets = parent.join("secrets");
        fs::create_dir(&parent).ok()?;
        fs::create_dir(&data).ok()?;
        fs::create_dir(&secrets).ok()?;
        set_owner_only(&secrets).ok()?;
        Some(Self {
            parent,
            data,
            secrets,
        })
    }

    fn paths(&self) -> Option<BootstrapPaths> {
        BootstrapPaths::new(&self.data, &self.secrets, MountQualification::LocalHost).ok()
    }
}

impl Drop for FuzzRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn corrupt(path: &Path, selector: usize) {
    let Ok(mut bytes) = fs::read(path) else {
        return;
    };
    if bytes.is_empty() {
        return;
    }
    let index = selector % bytes.len();
    if let Some(byte) = bytes.get_mut(index) {
        *byte ^= 0x80;
        let _ = fs::write(path, bytes);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 24 || data[0] & 7 != 0 {
        return;
    }
    let Some(roots) = FuzzRoots::new() else {
        return;
    };
    let Some(paths) = roots.paths() else {
        return;
    };
    let mut identity = None;
    let mut integrity = None;
    let mut claim_released = false;
    for (index, command) in data.iter().copied().enumerate() {
        match command & 7 {
            0 | 1 => {
                if let Ok(instance) =
                    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
                {
                    assert_eq!(
                        identity.get_or_insert(instance.instance_id()),
                        &instance.instance_id()
                    );
                    assert_eq!(
                        integrity.get_or_insert(instance.integrity_key_fingerprint()),
                        &instance.integrity_key_fingerprint()
                    );
                }
            },
            2 => {
                if let Ok(instance) = InstanceBootstrap::reopen(&paths) {
                    assert_eq!(
                        identity.get_or_insert(instance.instance_id()),
                        &instance.instance_id()
                    );
                    assert_eq!(
                        integrity.get_or_insert(instance.integrity_key_fingerprint()),
                        &instance.integrity_key_fingerprint()
                    );
                }
            },
            3 => match InstanceBootstrap::claim(&paths) {
                Ok(claim) => {
                    assert!(!claim_released);
                    assert!(claim.secret().starts_with("pos_"));
                    assert_eq!(claim.secret().len(), 68);
                    claim_released = true;
                },
                Err(failure) if claim_released => {
                    assert_eq!(failure.code(), BootstrapFailureCode::ClaimUnavailable);
                },
                Err(_) => {},
            },
            4 => corrupt(&roots.secrets.join("bootstrap-claim.v1"), index),
            5 => corrupt(&roots.data.join(".positron-bootstrap.initialized"), index),
            6 => {
                let _ = InstanceBootstrap::classify(&paths);
            },
            _ => {},
        }
    }
});
