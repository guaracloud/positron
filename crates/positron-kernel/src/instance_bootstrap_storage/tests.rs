use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    BootstrapArtifact, BootstrapKeyCustody, BootstrapStorageFailure, InstanceBootstrapStorage,
    MountQualification,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Roots {
    parent: PathBuf,
}

impl Roots {
    fn new() -> Self {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let parent = std::env::temp_dir().join(format!(
            "positron-bootstrap-storage-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&parent).expect("unique parent");
        fs::create_dir(parent.join("data")).expect("data root");
        fs::create_dir(parent.join("secrets")).expect("secrets root");
        fs::set_permissions(parent.join("secrets"), fs::Permissions::from_mode(0o700))
            .expect("owner-only secrets root");
        Self { parent }
    }

    fn storage(&self) -> InstanceBootstrapStorage {
        InstanceBootstrapStorage::new(
            &self.parent.join("data"),
            &self.parent.join("secrets"),
            MountQualification::LocalHost,
        )
        .expect("valid test roots")
    }

    fn data(&self) -> PathBuf {
        self.parent.join("data")
    }

    fn secrets(&self) -> PathBuf {
        self.parent.join("secrets")
    }

    fn replacement_secrets(&self) -> PathBuf {
        self.parent.join("replacement-secrets")
    }
}

impl Drop for Roots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

#[test]
fn initialized_publication_never_replaces_a_racing_final_marker() {
    let roots = Roots::new();
    let storage = roots.storage();
    let (_volume, access) = storage.acquire().expect("acquire test PDV");
    access
        .write_new(BootstrapArtifact::InitializedStaging, b"candidate")
        .expect("write candidate");
    access
        .write_new(BootstrapArtifact::Initialized, b"racing-final")
        .expect("create racing final");

    assert_eq!(
        access.publish_initialized(),
        Err(BootstrapStorageFailure::AlreadyExists)
    );
    assert_eq!(
        access
            .read(BootstrapArtifact::Initialized)
            .expect("read preserved final"),
        b"racing-final"
    );
    assert_eq!(
        access
            .read(BootstrapArtifact::InitializedStaging)
            .expect("candidate remains resumable"),
        b"candidate"
    );
}

#[test]
fn held_inspection_opens_key_from_original_secrets_directory_after_path_swap() {
    let roots = Roots::new();
    let original = BootstrapKeyCustody::initialize(&roots.secrets()).expect("original key");
    fs::create_dir(roots.replacement_secrets()).expect("replacement secrets root");
    fs::set_permissions(
        roots.replacement_secrets(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("owner-only replacement");
    let replacement =
        BootstrapKeyCustody::initialize(&roots.replacement_secrets()).expect("replacement key");
    let replacement_bytes = fs::read(roots.replacement_secrets().join("local-root-key.v1"))
        .expect("replacement key bytes");
    let access = roots.storage().inspect().expect("inspect original roots");
    let detached = roots.parent.join("detached-secrets");
    fs::rename(roots.secrets(), &detached).expect("detach original secrets root");
    fs::rename(roots.replacement_secrets(), roots.secrets()).expect("install replacement root");

    let opened = access.open_key().expect("open through held directory");

    assert_eq!(opened.identity(), original.identity());
    assert_ne!(opened.identity(), replacement.identity());
    assert_eq!(
        fs::read(roots.secrets().join("local-root-key.v1")).expect("replacement preserved"),
        replacement_bytes
    );
}

#[test]
fn held_acquisition_initializes_key_in_original_secrets_directory_after_path_swap() {
    let roots = Roots::new();
    let storage = roots.storage();
    let (_volume, access) = storage.acquire().expect("acquire original roots");
    fs::create_dir(roots.replacement_secrets()).expect("replacement secrets root");
    fs::set_permissions(
        roots.replacement_secrets(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("owner-only replacement");
    BootstrapKeyCustody::initialize(&roots.replacement_secrets()).expect("replacement key");
    let replacement_bytes = fs::read(roots.replacement_secrets().join("local-root-key.v1"))
        .expect("replacement key bytes");
    let detached = roots.parent.join("detached-secrets");
    fs::rename(roots.secrets(), &detached).expect("detach original secrets root");
    fs::rename(roots.replacement_secrets(), roots.secrets()).expect("install replacement root");

    let initialized = access
        .initialize_key()
        .expect("initialize through held directory");

    assert_eq!(
        access.open_key().expect("reopen original key").identity(),
        initialized.identity()
    );
    assert!(detached.join("local-root-key.v1").is_file());
    assert_eq!(
        fs::read(roots.secrets().join("local-root-key.v1")).expect("replacement preserved"),
        replacement_bytes
    );
}

#[test]
fn artifact_symlink_is_rejected_without_touching_its_target() {
    let roots = Roots::new();
    let target = roots.parent.join("outside-target");
    fs::write(&target, b"protected").expect("target");
    std::os::unix::fs::symlink(
        Path::new("..").join("outside-target"),
        roots.data().join(BootstrapArtifact::Pending.name()),
    )
    .expect("symlink fixture");
    let access = roots.storage().inspect().expect("inspect roots");

    assert_eq!(
        access.read(BootstrapArtifact::Pending),
        Err(BootstrapStorageFailure::UnsafeOrCorrupt)
    );
    assert_eq!(
        access.exists(BootstrapArtifact::Pending),
        Err(BootstrapStorageFailure::UnsafeOrCorrupt)
    );
    assert_eq!(fs::read(target).expect("target preserved"), b"protected");
}

#[test]
fn invalid_replaced_and_unsafe_roots_fail_closed() {
    let roots = Roots::new();
    let data = roots.data();
    assert_eq!(
        InstanceBootstrapStorage::new(
            &roots.parent.join("missing"),
            &roots.parent.join("secrets"),
            MountQualification::LocalHost
        ),
        Err(BootstrapStorageFailure::InvalidRoots)
    );
    assert_eq!(
        InstanceBootstrapStorage::new(&data, &data, MountQualification::LocalHost),
        Err(BootstrapStorageFailure::InvalidRoots)
    );
    let ordinary_file = roots.parent.join("ordinary-file");
    fs::write(&ordinary_file, b"not a root").expect("ordinary file");
    assert_eq!(
        InstanceBootstrapStorage::new(
            &ordinary_file,
            &roots.parent.join("secrets"),
            MountQualification::LocalHost
        ),
        Err(BootstrapStorageFailure::InvalidRoots)
    );

    let storage = roots.storage();
    fs::rename(&data, roots.parent.join("detached-data")).expect("detach bound root");
    fs::create_dir(&data).expect("replacement data root");
    assert!(matches!(
        storage.inspect(),
        Err(BootstrapStorageFailure::UnsafeOrCorrupt)
    ));
}

#[test]
fn layout_and_artifact_aliases_are_rejected() {
    let roots = Roots::new();
    let storage = roots.storage();
    let access = storage.inspect().expect("inspect roots");
    access
        .write_new(BootstrapArtifact::Pending, b"intent")
        .expect("new pending");
    assert_eq!(
        access.write_new(BootstrapArtifact::Pending, b"replacement"),
        Err(BootstrapStorageFailure::AlreadyExists)
    );
    let hard_link = roots.data().join("hard-link");
    fs::hard_link(
        roots.data().join(BootstrapArtifact::Pending.name()),
        &hard_link,
    )
    .expect("hard link fixture");
    assert_eq!(
        access.read(BootstrapArtifact::Pending),
        Err(BootstrapStorageFailure::UnsafeOrCorrupt)
    );
    let layout = access.layout().expect("bounded layout scan");
    assert!(layout.unknown_or_unsafe());
}

#[test]
fn recognized_entries_with_wrong_kinds_and_missing_publication_fail_closed() {
    let roots = Roots::new();
    fs::write(roots.data().join("catalog"), b"not a directory").expect("catalog file fixture");
    fs::create_dir(roots.data().join(BootstrapArtifact::Pending.name()))
        .expect("pending directory fixture");
    let access = roots.storage().inspect().expect("inspect roots");
    assert!(access.layout().expect("bounded scan").unknown_or_unsafe());
    assert_eq!(
        access.publish_initialized(),
        Err(BootstrapStorageFailure::Unavailable)
    );
    assert_eq!(
        super::io::map_open_error(rustix::io::Errno::IO),
        BootstrapStorageFailure::Unavailable
    );
}
