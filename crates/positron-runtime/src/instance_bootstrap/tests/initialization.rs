use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use positron_kernel::{MountQualification, PrimaryDataVolume};
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
        BootstrapPaths::new(&self.data, &self.secrets, MountQualification::LocalHost)
            .map_err(|failure| failure.code())
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
    assert_eq!(paths.mount_qualification(), MountQualification::LocalHost);
    assert_eq!(InstanceBootstrap::classify(&paths)?, BootstrapState::Empty);

    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    assert_eq!(initialized.default_tenant_slug().as_str(), "default");
    assert_eq!(initialized.catalog_generation(), 3);
    assert_eq!(initialized.governance_audit_frontier(), 1);
    assert!(initialized.claim_available());
    assert!(format!("{initialized:?}").contains("InitializedInstance"));
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
    let administrator = reopened.system_administrator_id();
    drop(reopened);

    let retried = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    assert_eq!(retried.instance_id(), identity);
    assert_eq!(retried.integrity_key_fingerprint(), integrity);
    drop(retried);

    let claim = InstanceBootstrap::claim(&paths)?;
    assert_eq!(claim.principal_id(), administrator);
    assert!(!claim.secret().is_empty());
    assert_eq!(format!("{claim:?}"), "BootstrapClaim { <redacted> }");
    let second = InstanceBootstrap::claim(&paths).expect_err("claim is one-time");
    assert_eq!(second.code(), BootstrapFailureCode::ClaimUnavailable);
    assert_eq!(second.to_string(), "instance bootstrap failed");
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

    let mismatched =
        BootstrapPaths::new(&first.data, &second.secrets, MountQualification::LocalHost)?;
    let failure = InstanceBootstrap::reopen(&mismatched)
        .expect_err("initialized data and secrets identities must be jointly bound");
    assert!(matches!(
        failure.code(),
        BootstrapFailureCode::CorruptState
            | BootstrapFailureCode::IdentityMismatch
            | BootstrapFailureCode::InconsistentRoots
    ));
    Ok(())
}

#[test]
fn unverified_mount_and_busy_volume_fail_before_bootstrap_mutation() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let unverified = BootstrapPaths::new(
        &roots.data,
        &roots.secrets,
        MountQualification::UnverifiedExternalOrPvc,
    )?;
    let failure = InstanceBootstrap::initialize(&unverified, InitializationPlan::non_interactive())
        .expect_err("unverified provenance must be refused");
    assert_eq!(failure.code(), BootstrapFailureCode::StorageUnavailable);
    assert_eq!(fs::read_dir(&roots.data)?.count(), 0);
    assert_eq!(fs::read_dir(&roots.secrets)?.count(), 0);

    let ownership = PrimaryDataVolume::acquire(&roots.data, MountQualification::LocalHost)?;
    let failure = InstanceBootstrap::initialize(
        &roots.paths().map_err(|code| format!("paths: {code:?}"))?,
        InitializationPlan::non_interactive(),
    )
    .expect_err("existing storage ownership must be refused");
    assert_eq!(failure.code(), BootstrapFailureCode::StorageUnavailable);
    assert_eq!(fs::read_dir(&roots.secrets)?.count(), 0);
    assert_eq!(
        fs::read_dir(&roots.data)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() != ".positron-volume.lock")
            .count(),
        0
    );
    drop(ownership);
    Ok(())
}

#[test]
fn initialized_handoff_keeps_the_primary_volume_owned() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;

    assert!(PrimaryDataVolume::acquire(&roots.data, MountQualification::LocalHost).is_err());
    drop(initialized);
    assert!(PrimaryDataVolume::acquire(&roots.data, MountQualification::LocalHost).is_ok());
    Ok(())
}

#[test]
fn classification_rejects_corrupt_catalog_authority() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);

    let marker = fs::read_dir(roots.data.join("catalog/generations"))?
        .next()
        .ok_or("initialized catalog must publish a generation")??
        .path();
    let mut encoded = fs::read(&marker)?;
    let last = encoded.last_mut().ok_or("marker must not be empty")?;
    *last ^= 0x01;
    fs::write(marker, encoded)?;

    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Inconsistent
    );
    Ok(())
}

#[test]
fn repeated_classification_is_strictly_read_only() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    fs::remove_file(roots.data.join(".positron-volume.lock"))?;
    let before = durable_tree(&roots.data)?;

    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Initialized
    );
    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Initialized
    );

    assert_eq!(durable_tree(&roots.data)?, before);
    assert!(!roots.data.join(".positron-volume.lock").exists());
    Ok(())
}

#[test]
fn live_owned_initialized_root_is_classified_truthfully() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;

    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Initialized
    );
    drop(initialized);
    Ok(())
}

#[test]
fn inspection_permission_failure_is_operational_not_corruption() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    fs::set_permissions(&roots.secrets, fs::Permissions::from_mode(0o000))?;
    let classified = InstanceBootstrap::classify(&paths);
    fs::set_permissions(&roots.secrets, fs::Permissions::from_mode(0o700))?;

    assert_eq!(
        classified
            .expect_err("unreadable inspection root must be operational failure")
            .code(),
        BootstrapFailureCode::StorageUnavailable
    );
    Ok(())
}

fn durable_tree(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, std::io::Error> {
    fn visit(
        root: &Path,
        current: &Path,
        observed: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<(), std::io::Error> {
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            if entry.file_type()?.is_dir() {
                observed.insert(relative.clone(), Vec::new());
                visit(root, &path, observed)?;
            } else {
                observed.insert(relative, fs::read(path)?);
            }
        }
        Ok(())
    }

    let mut observed = BTreeMap::new();
    visit(root, root, &mut observed)?;
    Ok(observed)
}
