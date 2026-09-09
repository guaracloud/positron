use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{
    BootstrapFailureCode, BootstrapPaths, BootstrapState, InitializationPlan, InstanceBootstrap,
};
use positron_domain::identity::Scope;
use positron_governance::{AdministrativeIdempotencyKey, ResourceGeneration};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{
    CatalogPublicationFault, MountQualification, PrimaryDataVolume,
    with_catalog_publication_fault_after,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

pub(super) struct Roots {
    parent: PathBuf,
    pub(super) data: PathBuf,
    secrets: PathBuf,
}

impl Roots {
    pub(super) fn new() -> Result<Self, std::io::Error> {
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

    pub(super) fn paths(&self) -> Result<BootstrapPaths, BootstrapFailureCode> {
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
fn reopened_identity_authenticates_the_hash_only_administrator_without_impersonation()
-> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let administrator = initialized.system_administrator_id();
    drop(initialized);

    let claim = InstanceBootstrap::claim(&paths)?;
    let reopened = InstanceBootstrap::reopen(&paths)?;
    let authorized = reopened.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;

    assert_eq!(authorized.principal_id(), administrator);
    assert_eq!(authorized.tenant_attribution(), None);
    let rejected = reopened
        .attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::Ingest,
            CompatibilityHints::none(),
        )
        .expect_err("a system administrator cannot impersonate a tenant principal");
    assert_eq!(rejected.to_string(), "credential or authority was rejected");
    Ok(())
}

#[test]
fn administrator_creates_a_one_time_tenant_administration_key_that_survives_reopen()
-> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let bootstrap = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let administrator = initialized.attribute(
        PresentedCredential::parse(bootstrap.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let created = initialized
        .create_api_key(
            administrator,
            Scope::TenantAdministration,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([42; 16])?,
        )
        .expect("administrator key creation commits");
    let secret = created.secret().ok_or("creation secret")?.to_owned();
    assert!(!format!("{created:?}").contains(&secret));
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths).expect("created key state reopens");
    let authorized = reopened
        .attribute(
            PresentedCredential::parse(&secret)?,
            RequestedIntent::TenantAdministration,
            CompatibilityHints::none(),
        )
        .expect("created tenant administrator attributes");
    assert_eq!(authorized.scope(), Scope::TenantAdministration);
    assert_eq!(
        authorized
            .tenant_attribution()
            .map(|tenant| tenant.tenant_id()),
        Some(reopened.default_tenant_id())
    );
    reopened
        .governance_fixture_for_test()
        .expect("the current V5 governance object remains available to integration fixtures");
    Ok(())
}

#[test]
fn tenant_key_rotation_keeps_both_credentials_live_until_explicit_revocation()
-> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let first = instance.create_api_key(
        administrator,
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([43; 16])?,
    )?;
    let first_secret = first.secret().ok_or("first key secret")?.to_owned();
    let successor = instance.rotate_api_key(
        administrator,
        first.principal_id(),
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([44; 16])?,
    )?;
    let successor_secret = successor.secret().ok_or("successor secret")?.to_owned();
    let rotation_replay = instance.rotate_api_key(
        administrator,
        first.principal_id(),
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([44; 16])?,
    )?;
    assert_eq!(rotation_replay.principal_id(), successor.principal_id());
    assert!(rotation_replay.secret().is_none());

    let descriptors = instance.list_api_keys(administrator)?;
    assert!(descriptors.iter().any(|descriptor| {
        descriptor.principal_id() == first.principal_id()
            && descriptor.scope() == Scope::Query
            && descriptor.is_active()
    }));
    assert!(!format!("{descriptors:?}").contains(&first_secret));

    for secret in [&first_secret, &successor_secret] {
        instance.attribute(
            PresentedCredential::parse(secret)?,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        )?;
    }
    instance.revoke_api_key(
        administrator,
        first.principal_id(),
        ResourceGeneration::new(3)?,
        AdministrativeIdempotencyKey::new([45; 16])?,
    )?;
    instance.revoke_api_key(
        administrator,
        first.principal_id(),
        ResourceGeneration::new(3)?,
        AdministrativeIdempotencyKey::new([45; 16])?,
    )?;
    let revoke_conflict = instance
        .revoke_api_key(
            administrator,
            successor.principal_id(),
            ResourceGeneration::new(3)?,
            AdministrativeIdempotencyKey::new([45; 16])?,
        )
        .expect_err("idempotency cannot bind a different revoked credential");
    assert_eq!(
        revoke_conflict.code(),
        BootstrapFailureCode::ApiKeyIdempotencyConflict
    );
    let descriptors = instance.list_api_keys(administrator)?;
    assert!(descriptors.iter().any(|descriptor| {
        descriptor.principal_id() == first.principal_id() && !descriptor.is_active()
    }));
    assert!(
        instance
            .attribute(
                PresentedCredential::parse(&first_secret)?,
                RequestedIntent::Query,
                CompatibilityHints::none(),
            )
            .is_err()
    );
    instance.attribute(
        PresentedCredential::parse(&successor_secret)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    Ok(())
}

#[test]
fn expired_tenant_key_is_rejected_using_the_lifecycle_clock() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let expired = instance.create_api_key(
        administrator,
        Scope::Query,
        Some(1),
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([46; 16])?,
    )?;
    let expired_secret = expired.secret().ok_or("expiry secret")?.to_owned();
    drop(instance);
    let instance = InstanceBootstrap::reopen(&paths)?;
    assert!(
        instance
            .attribute(
                PresentedCredential::parse(&expired_secret)?,
                RequestedIntent::Query,
                CompatibilityHints::none(),
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn identical_api_key_create_retry_resolves_the_original_redacted_result()
-> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        instance.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let idempotency = AdministrativeIdempotencyKey::new([47; 16])?;
    let first = instance.create_api_key(
        administrator()?,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        idempotency,
    )?;
    let replay = instance.create_api_key(
        administrator()?,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        idempotency,
    )?;
    assert_eq!(replay.principal_id(), first.principal_id());
    assert!(replay.secret().is_none());
    Ok(())
}

#[test]
fn api_key_create_rejects_stale_generation_and_mismatched_idempotency_reuse()
-> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        instance.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let idempotency = AdministrativeIdempotencyKey::new([48; 16])?;
    instance.create_api_key(
        administrator()?,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        idempotency,
    )?;
    let descriptors_before_failure = instance.list_api_keys(administrator()?)?;
    let mismatch = instance
        .create_api_key(
            administrator()?,
            Scope::Query,
            None,
            ResourceGeneration::new(1)?,
            idempotency,
        )
        .expect_err("idempotency key cannot bind a different scope");
    assert_eq!(
        mismatch.code(),
        BootstrapFailureCode::ApiKeyIdempotencyConflict
    );
    let stale = instance
        .create_api_key(
            administrator()?,
            Scope::Query,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([49; 16])?,
        )
        .expect_err("new mutation cannot overwrite a stale credential generation");
    assert_eq!(stale.code(), BootstrapFailureCode::ApiKeyStaleGeneration);
    assert_eq!(
        instance.list_api_keys(administrator()?)?,
        descriptors_before_failure,
        "failed lifecycle mutations must not publish a partial credential set"
    );
    Ok(())
}

#[test]
fn ambiguous_api_key_publication_recovers_one_consistent_idempotent_outcome()
-> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        instance.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let idempotency = AdministrativeIdempotencyKey::new([50; 16])?;
    let before = instance.list_api_keys(administrator()?)?;
    let failed = with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        0,
        || {
            instance.create_api_key(
                administrator().expect("administrator"),
                Scope::Query,
                None,
                ResourceGeneration::new(1).expect("generation"),
                idempotency,
            )
        },
    )
    .expect_err("catalog publication fault must reject the lifecycle mutation");
    assert_eq!(failed.code(), BootstrapFailureCode::CatalogUnavailable);
    drop(instance);
    let recovered = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        recovered.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let after = recovered.list_api_keys(administrator()?)?;
    assert!(
        after == before || after.len() == before.len() + 1,
        "recovery must expose either the predecessor or the one complete successor"
    );
    let retried = recovered.create_api_key(
        administrator()?,
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        idempotency,
    )?;
    assert_eq!(
        retried.secret().is_some(),
        after == before,
        "only an unpublished mutation may create and show a new secret on retry"
    );
    assert_eq!(
        recovered.list_api_keys(administrator()?)?.len(),
        before.len() + 1
    );
    Ok(())
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
