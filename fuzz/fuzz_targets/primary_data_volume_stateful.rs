#![no_main]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_kernel::{MountQualification, PrimaryDataVolume, VolumeCompletionState};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct FuzzRoot(PathBuf);

impl FuzzRoot {
    fn new() -> Option<Self> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-volume-fuzz-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).ok()?;
        Some(Self(path))
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn install_bounded_layout(root: &Path, data: &[u8]) {
    let selector = data.first().copied().unwrap_or_default() % 8;
    let payload_len = data.len().min(64);
    let payload = data.get(..payload_len).unwrap_or_default();
    match selector {
        1 => {
            let _ = fs::write(root.join(".positron-volume.lock"), payload);
        },
        2 => {
            let _ = fs::create_dir(root.join(".positron-volume.lock"));
        },
        3 => {
            let probe = root.join(".positron-volume-probe");
            let _ = fs::create_dir(&probe);
            let _ = fs::write(probe.join("unexpected"), payload);
        },
        4 => {
            let _ = fs::write(root.join(".positron-volume-probe"), payload);
        },
        5 => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                let _ = symlink(root.join("missing-lock-target"), root.join(".positron-volume.lock"));
            }
        },
        6 => {
            let foreign = root.join("foreign");
            let _ = fs::write(&foreign, payload);
            let _ = fs::hard_link(&foreign, root.join(".positron-volume.lock"));
        },
        7 => {
            let probe = root.join(".positron-volume-probe");
            let _ = fs::create_dir(&probe);
            let _ = fs::write(probe.join("candidate"), payload);
        },
        _ => {},
    }
}

fn assert_completion_truth(root: &Path, completion: VolumeCompletionState) {
    let probe_exists = root.join(".positron-volume-probe").exists();
    match completion {
        VolumeCompletionState::ProbeCleanupSynchronized
        | VolumeCompletionState::ProbeCleanupDurabilityUncertain => assert!(!probe_exists),
        VolumeCompletionState::RejectedBeforeProbeMutation
        | VolumeCompletionState::ProbeResiduePresent => {},
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 {
        return;
    }
    let Some(root) = FuzzRoot::new() else {
        return;
    };
    install_bounded_layout(&root.0, data);

    match PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost) {
        Ok(first) => {
            assert!(!root.0.join(".positron-volume-probe").exists());
            if data.get(1).copied().unwrap_or_default() & 1 == 0 {
                let second =
                    PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost);
                assert!(second.is_err());
            }
            drop(first);
            if data.get(1).copied().unwrap_or_default() & 2 != 0 {
                let reopened =
                    PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost);
                assert!(reopened.is_ok());
            }
        },
        Err(failure) => assert_completion_truth(&root.0, failure.completion_state()),
    }
});
