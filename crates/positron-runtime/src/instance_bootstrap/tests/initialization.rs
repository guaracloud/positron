use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use positron_runtime::{
    BootstrapFailureCode, BootstrapPaths, BootstrapState, InitializationPlan, InstanceBootstrap,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Roots {
    parent: PathBuf,
    data: PathBuf,
    secrets: PathBuf,
}

impl Roots {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let parent = std::env::temp_dir().join(format!(
            "positron-instance-bootstrap-test-{}-{sequence}",
            std::process::id()
        ));
        let data = parent.join("data");
        let secrets = parent.join("secrets");
        fs::create_dir(&parent)?;
        fs::create_dir(&data)?;
        fs::create_dir(&secrets)?;
        set_owner_only(&secrets)?;
        Ok(Self {
            parent,
            data,
            secrets,
        })
    }

    fn paths(&self) -> Result<BootstrapPaths, BootstrapFailureCode> {
        BootstrapPaths::new(&self.data, &self.secrets).map_err(|failure| failure.code())
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

#[test]
fn empty_roots_initialize_reopen_and_claim_exactly_once() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    assert_eq!(InstanceBootstrap::classify(&paths)?, BootstrapState::Empty);

    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    assert_eq!(initialized.default_tenant_slug().as_str(), "default");
    assert_eq!(initialized.catalog_generation(), 3);
    assert_eq!(initialized.governance_audit_frontier(), 1);
    assert!(initialized.claim_available());
    let identity = initialized.instance_id();
    let tenant = initialized.default_tenant_id();
    let integrity = initialized.integrity_key_fingerprint();
    assert!(integrity.iter().any(|byte| *byte != 0));
    drop(initialized);

    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Initialized
    );
    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(reopened.instance_id(), identity);
    assert_eq!(reopened.default_tenant_id(), tenant);
    assert_eq!(reopened.integrity_key_fingerprint(), integrity);
    assert!(reopened.claim_available());

    let retried = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    assert_eq!(retried.instance_id(), identity);
    assert_eq!(retried.integrity_key_fingerprint(), integrity);

    let claim = InstanceBootstrap::claim(&paths)?;
    assert_eq!(claim.principal_id(), reopened.system_administrator_id());
    assert!(!claim.secret().is_empty());
    let second = InstanceBootstrap::claim(&paths).expect_err("claim is one-time");
    assert_eq!(second.code(), BootstrapFailureCode::ClaimUnavailable);
    Ok(())
}

#[test]
fn corrupt_claim_is_rejected_without_consuming_it() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;

    let claim_path = roots.secrets.join("bootstrap-claim.v1");
    let mut claim = fs::read(&claim_path)?;
    let last = claim
        .last_mut()
        .ok_or("claim artifact must contain authenticated bytes")?;
    *last ^= 0x01;
    fs::write(&claim_path, claim)?;

    let failure = InstanceBootstrap::claim(&paths).expect_err("corrupt claim must fail closed");
    assert_eq!(failure.code(), BootstrapFailureCode::CorruptState);
    assert!(claim_path.is_file());
    assert!(InstanceBootstrap::reopen(&paths)?.claim_available());
    Ok(())
}

#[test]
fn initialized_data_rejects_a_different_secrets_root() -> Result<(), Box<dyn Error>> {
    let first = Roots::new()?;
    let second = Roots::new()?;
    let first_paths = first.paths().map_err(|code| format!("paths: {code:?}"))?;
    let second_paths = second.paths().map_err(|code| format!("paths: {code:?}"))?;
    InstanceBootstrap::initialize(&first_paths, InitializationPlan::non_interactive())?;
    InstanceBootstrap::initialize(&second_paths, InitializationPlan::non_interactive())?;

    let mismatched = BootstrapPaths::new(&first.data, &second.secrets)?;
    let failure = InstanceBootstrap::reopen(&mismatched)
        .expect_err("initialized data and secrets identities must be jointly bound");
    assert!(matches!(
        failure.code(),
        BootstrapFailureCode::CorruptState | BootstrapFailureCode::IdentityMismatch
    ));
    Ok(())
}
