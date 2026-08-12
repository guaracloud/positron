use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{
    CapacityObservationFailure, CapacityObservationSource, FileReader, observe_cgroups,
    observe_cpu_with, observe_memory_with,
};

#[derive(Default)]
struct FakeReader(BTreeMap<PathBuf, Vec<u8>>);

impl FakeReader {
    fn with(mut self, path: &str, contents: &[u8]) -> Self {
        self.0.insert(PathBuf::from(path), contents.to_vec());
        self
    }
}

impl FileReader for FakeReader {
    fn read(
        &self,
        path: &Path,
        maximum: u64,
        source: CapacityObservationSource,
    ) -> Result<super::allocation::BoundedBytes, CapacityObservationFailure> {
        let contents = self
            .0
            .get(path)
            .ok_or(CapacityObservationFailure::ObservationUnavailable { source })?;
        super::allocation::BoundedBytes::from_slice(contents, maximum, source)
    }
}

fn v2() -> FakeReader {
    FakeReader::default()
        .with(
            "/proc/meminfo",
            b"MemTotal: 1000 kB\nMemAvailable: 800 kB\n",
        )
        .with("/proc/self/cgroup", b"0::/worker\n")
        .with(
            "/proc/self/mountinfo",
            b"36 29 0:32 / /control rw - cgroup2 cgroup rw\n",
        )
        .with("/control/worker/cpu.max", b"50000 100000\n")
        .with("/control/worker/memory.max", b"600000\n")
        .with("/control/worker/memory.current", b"100000\n")
        .with("/control/cpu.max", b"max 100000\n")
        .with("/control/memory.max", b"max\n")
        .with("/control/memory.current", b"100000\n")
}

#[test]
fn fake_v2_observer_applies_memory_headroom_and_cpu_quota() {
    let reader = v2();
    assert_eq!(observe_memory_with(&reader), Ok(500_000));
    let limits = observe_cgroups(&reader).expect("fake hierarchy is valid");
    assert_eq!(limits.cpu, Some(500));
    assert_eq!(limits.memory, Some(500_000));
    assert_eq!(observe_cpu_with(&reader, 8_000), Ok(500));
}

#[test]
fn nested_v2_uses_minimum_finite_ancestor_limits() {
    let reader = FakeReader::default()
        .with("/proc/self/cgroup", b"0::/parent/leaf\n")
        .with(
            "/proc/self/mountinfo",
            b"36 29 0:32 / /control rw - cgroup2 cgroup rw\n",
        )
        .with("/control/cpu.max", b"max 100000\n")
        .with("/control/memory.max", b"max\n")
        .with("/control/memory.current", b"300000\n")
        .with("/control/parent/cpu.max", b"75000 100000\n")
        .with("/control/parent/memory.max", b"900000\n")
        .with("/control/parent/memory.current", b"400000\n")
        .with("/control/parent/leaf/cpu.max", b"50000 100000\n")
        .with("/control/parent/leaf/memory.max", b"800000\n")
        .with("/control/parent/leaf/memory.current", b"100000\n");
    let limits = observe_cgroups(&reader).expect("complete hierarchy");
    assert_eq!(limits.cpu, Some(500));
    assert_eq!(limits.memory, Some(500_000));
}

#[test]
fn v2_controller_root_needs_no_resource_control_files() {
    let reader = FakeReader::default()
        .with("/proc/self/cgroup", b"0::/actions_job/leaf\n")
        .with(
            "/proc/self/mountinfo",
            b"36 29 0:32 / /control rw - cgroup2 cgroup rw\n",
        )
        .with("/control/actions_job/cpu.max", b"max 100000\n")
        .with("/control/actions_job/memory.max", b"max\n")
        .with("/control/actions_job/memory.current", b"300000\n")
        .with("/control/actions_job/leaf/cpu.max", b"50000 100000\n")
        .with("/control/actions_job/leaf/memory.max", b"800000\n")
        .with("/control/actions_job/leaf/memory.current", b"100000\n");

    let limits = observe_cgroups(&reader).expect("global v2 root has no controller files");
    assert_eq!(limits.cpu, Some(500));
    assert_eq!(limits.memory, Some(700_000));
}

#[test]
fn missing_or_overused_governed_ancestor_fails_closed() {
    let base = FakeReader::default()
        .with("/proc/self/cgroup", b"0::/parent/leaf\n")
        .with(
            "/proc/self/mountinfo",
            b"36 29 0:32 / /control rw - cgroup2 cgroup rw\n",
        )
        .with("/control/parent/leaf/cpu.max", b"max 100000\n")
        .with("/control/parent/leaf/memory.max", b"max\n")
        .with("/control/parent/leaf/memory.current", b"100000\n");
    assert_eq!(
        observe_cgroups(&base).map(|_| ()),
        Err(CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::CgroupCpu
        })
    );
    let overused = base
        .with("/control/parent/cpu.max", b"100000 100000\n")
        .with("/control/parent/memory.max", b"100000\n")
        .with("/control/parent/memory.current", b"100001\n");
    assert_eq!(
        observe_cgroups(&overused).map(|_| ()),
        Err(CapacityObservationFailure::Arithmetic {
            source: CapacityObservationSource::CgroupMemory
        })
    );
}

#[test]
fn split_v1_walks_each_controller_to_mount_root() {
    let reader = FakeReader::default()
        .with("/proc/self/cgroup", b"2:cpu:/group/leaf\n3:memory:/group/leaf\n")
        .with("/proc/self/mountinfo", b"10 1 0:10 / /cpu rw - cgroup cgroup rw,cpu\n11 1 0:11 / /memory rw - cgroup cgroup rw,memory\n")
        .with("/cpu/cpu.cfs_quota_us", b"-1\n")
        .with("/cpu/cpu.cfs_period_us", b"100000\n")
        .with("/cpu/group/cpu.cfs_quota_us", b"20000\n")
        .with("/cpu/group/cpu.cfs_period_us", b"100000\n")
        .with("/cpu/group/leaf/cpu.cfs_quota_us", b"50000\n")
        .with("/cpu/group/leaf/cpu.cfs_period_us", b"100000\n")
        .with("/memory/memory.limit_in_bytes", b"1000000\n")
        .with("/memory/memory.usage_in_bytes", b"100000\n")
        .with("/memory/group/memory.limit_in_bytes", b"600000\n")
        .with("/memory/group/memory.usage_in_bytes", b"200000\n")
        .with("/memory/group/leaf/memory.limit_in_bytes", b"700000\n")
        .with("/memory/group/leaf/memory.usage_in_bytes", b"100000\n");
    let limits = observe_cgroups(&reader).expect("split v1 hierarchy");
    assert_eq!(limits.cpu, Some(200));
    assert_eq!(limits.memory, Some(400_000));
}

#[test]
fn root_unlimited_and_host_only_are_valid() {
    let root = FakeReader::default()
        .with(
            "/proc/meminfo",
            b"MemTotal: 1000 kB\nMemAvailable: 800 kB\n",
        )
        .with("/proc/self/cgroup", b"0::/\n")
        .with(
            "/proc/self/mountinfo",
            b"36 29 0:32 / /control rw - cgroup2 cgroup rw\n",
        )
        .with("/control/cpu.max", b"max 100000\n")
        .with("/control/memory.max", b"max\n")
        .with("/control/memory.current", b"100000\n");
    assert_eq!(observe_memory_with(&root), Ok(800 * 1_024));
    assert_eq!(observe_cpu_with(&root, 8_000), Ok(8_000));

    let host_only = FakeReader::default()
        .with(
            "/proc/meminfo",
            b"MemTotal: 1000 kB\nMemAvailable: 800 kB\n",
        )
        .with("/proc/self/cgroup", b"7:devices:/worker\n")
        .with(
            "/proc/self/mountinfo",
            b"1 0 0:1 / /proc rw - proc proc rw\n",
        );
    assert_eq!(observe_memory_with(&host_only), Ok(800 * 1_024));
}

#[test]
fn declared_controller_missing_state_or_mount_fails_closed() {
    let mut missing_state = v2();
    missing_state
        .0
        .remove(Path::new("/control/worker/memory.current"));
    assert_eq!(
        observe_memory_with(&missing_state),
        Err(CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::CgroupMemory
        })
    );
    let missing_mount = FakeReader::default()
        .with("/proc/self/cgroup", b"0::/worker\n")
        .with(
            "/proc/self/mountinfo",
            b"1 0 0:1 / /proc rw - proc proc rw\n",
        );
    assert_eq!(
        observe_cgroups(&missing_mount).map(|_| ()),
        Err(CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::CgroupMounts
        })
    );
}

#[test]
fn oversized_proc_or_limit_file_fails_before_parsing() {
    let oversized_proc = FakeReader::default()
        .with("/proc/self/cgroup", &vec![b'x'; 64 * 1_024 + 1])
        .with("/proc/self/mountinfo", b"");
    assert_eq!(
        observe_cgroups(&oversized_proc).map(|_| ()),
        Err(CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::CgroupMembership
        })
    );
    let mut oversized_limit = v2();
    oversized_limit
        .0
        .insert(PathBuf::from("/control/worker/cpu.max"), vec![b'1'; 129]);
    assert_eq!(
        observe_cgroups(&oversized_limit).map(|_| ()),
        Err(CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::CgroupCpu
        })
    );
}
