use super::{memberships, meminfo, mounts, resolve};
use crate::{CapacityObservationFailure, CapacityObservationSource};

#[test]
fn parses_host_available_memory() {
    assert_eq!(
        meminfo(b"MemTotal: 100 kB\nMemAvailable: 40 kB\n"),
        Ok(40 * 1_024)
    );
}

#[test]
fn resolves_normalized_v2_membership_beneath_its_mount_root() {
    let memberships = memberships(b"0::/tenant/worker\n").expect("valid membership");
    let mounts = mounts(b"36 29 0:32 /tenant /sys/fs/cgroup rw - cgroup2 cgroup rw\n")
        .expect("valid mountinfo");
    let resolved = resolve(memberships, mounts).expect("hierarchy resolves");
    let hierarchy = resolved.iter().next().expect("one v2 hierarchy");
    assert_eq!(hierarchy.mount_point, "/sys/fs/cgroup");
    assert_eq!(hierarchy.relative.len, 1);
    assert_eq!(hierarchy.relative.components[0], Some("worker"));
}

#[test]
fn rejects_traversal_ambiguous_mounts_and_malformed_limits_without_echoing_input() {
    assert!(memberships(b"0::/../../escape\n").is_err());
    let memberships = memberships(b"0::/tenant\n").expect("valid membership");
    let mounts =
        mounts(b"1 0 0:1 / /a rw - cgroup2 cgroup rw\n2 0 0:2 / /b rw - cgroup2 cgroup rw\n")
            .expect("valid mountinfo");
    assert_eq!(
        resolve(memberships, mounts),
        Err(CapacityObservationFailure::AmbiguousHierarchy)
    );
}

#[test]
fn rejects_invalid_paths_and_accepts_only_the_unambiguous_root() {
    for invalid in [
        "relative",
        "C:/prefix",
        "/../parent",
        "/./current",
        "/double//slash",
    ] {
        assert!(memberships(format!("0::{invalid}\n").as_bytes()).is_err());
    }
    let root = memberships(b"0::/\n").expect("root membership");
    assert_eq!(root.unified.expect("v2 root").len, 0);
}

#[test]
fn rejects_duplicate_memberships_and_oversized_entries() {
    assert_eq!(
        memberships(b"0::/first\n0::/second\n"),
        Err(CapacityObservationFailure::AmbiguousHierarchy)
    );
    let oversized = format!("0::/{}\n", "a".repeat(4_097));
    assert!(memberships(oversized.as_bytes()).is_err());
    let oversized = format!("1 0 0:1 / /{} rw - cgroup2 cgroup rw\n", "a".repeat(65_537));
    assert!(mounts(oversized.as_bytes()).is_err());
}

#[test]
fn rejects_memberships_deeper_than_the_ancestor_walk_bound() {
    let mut membership = String::from("0::");
    for _ in 0..=super::super::MAX_PATH_COMPONENTS {
        membership.push_str("/a");
    }
    membership.push('\n');
    assert!(memberships(membership.as_bytes()).is_err());
}

#[test]
fn decodes_mountinfo_escapes_without_allocating_component_strings() {
    assert!(
        super::normalized_absolute(
            "/tenant\\040name",
            true,
            CapacityObservationSource::CgroupMounts
        )
        .is_ok()
    );
    assert!(
        super::normalized_absolute(
            "/sys/fs/cgroup\\040safe",
            true,
            CapacityObservationSource::CgroupMounts
        )
        .is_ok()
    );
    let memberships = memberships(b"0::/tenant name/leaf\n").expect("valid membership");
    let mounts =
        mounts(b"36 29 0:32 /tenant\\040name /sys/fs/cgroup\\040safe rw - cgroup2 cgroup rw\n")
            .expect("valid escaped mountinfo");
    let resolved = resolve(memberships, mounts).expect("escaped root resolves");
    let hierarchy = resolved.iter().next().expect("hierarchy");
    assert_eq!(hierarchy.mount_point, "/sys/fs/cgroup\\040safe");
    assert_eq!(hierarchy.relative.components[0], Some("leaf"));
}

#[test]
fn error_display_never_echoes_untrusted_path_input() {
    let canary = "private-cgroup-canary";
    let error =
        memberships(format!("0::/../{canary}\n").as_bytes()).expect_err("traversal is malformed");
    assert!(!error.to_string().contains(canary));
    assert_eq!(
        error,
        CapacityObservationFailure::MalformedLimit {
            source: CapacityObservationSource::CgroupMembership
        }
    );
}
