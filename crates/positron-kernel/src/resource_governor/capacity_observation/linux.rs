//! Bounded Linux host and cgroup resource observation.

#[cfg(any(target_os = "linux", test))]
mod allocation;
mod parsers;
mod values;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(any(target_os = "linux", test))]
use std::path::Path;
#[cfg(any(target_os = "linux", test))]
use std::path::PathBuf;

#[cfg(any(target_os = "linux", test))]
use crate::resource_governor::{CapacityObservationFailure, CapacityObservationSource};

#[cfg(any(target_os = "linux", test))]
const MAX_MEMINFO_BYTES: u64 = 64 * 1_024;
#[cfg(any(target_os = "linux", test))]
const MAX_CGROUP_MEMBERSHIP_BYTES: u64 = 64 * 1_024;
#[cfg(any(target_os = "linux", test))]
const MAX_MOUNTINFO_BYTES: u64 = 1024 * 1_024;
#[cfg(any(target_os = "linux", test))]
const MAX_LIMIT_BYTES: u64 = 128;
#[cfg(any(target_os = "linux", test))]
const MAX_RESOLVED_PATH_BYTES: usize = 4_096;
const MAX_PATH_COMPONENTS: usize = 128;
const MAX_CONTROLLER_MOUNTS: usize = 8;
const MAX_HIERARCHIES: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Controller {
    Unified,
    Cpu,
    Memory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Hierarchy<'a> {
    controller: Controller,
    mount_point: &'a str,
    relative: ComponentPath<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ComponentPath<'a> {
    components: [Option<&'a str>; MAX_PATH_COMPONENTS],
    len: usize,
}

impl ComponentPath<'_> {
    const fn empty() -> Self {
        Self {
            components: [None; MAX_PATH_COMPONENTS],
            len: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Mount<'a> {
    root: ComponentPath<'a>,
    mount_point: &'a str,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct Memberships<'a> {
    unified: Option<ComponentPath<'a>>,
    cpu: Option<ComponentPath<'a>>,
    memory: Option<ComponentPath<'a>>,
}

#[derive(Debug, Eq, PartialEq)]
struct Mounts<'a> {
    unified: [Option<Mount<'a>>; MAX_CONTROLLER_MOUNTS],
    cpu: [Option<Mount<'a>>; MAX_CONTROLLER_MOUNTS],
    memory: [Option<Mount<'a>>; MAX_CONTROLLER_MOUNTS],
}

impl Default for Mounts<'_> {
    fn default() -> Self {
        Self {
            unified: [None; MAX_CONTROLLER_MOUNTS],
            cpu: [None; MAX_CONTROLLER_MOUNTS],
            memory: [None; MAX_CONTROLLER_MOUNTS],
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ResolvedHierarchies<'a> {
    entries: [Option<Hierarchy<'a>>; MAX_HIERARCHIES],
}

impl ResolvedHierarchies<'_> {
    #[cfg(any(target_os = "linux", test))]
    fn iter(&self) -> impl Iterator<Item = Hierarchy<'_>> + '_ {
        self.entries.iter().flatten().copied()
    }
}

#[cfg(any(target_os = "linux", test))]
trait FileReader {
    fn read(
        &self,
        path: &Path,
        maximum: u64,
        source: CapacityObservationSource,
    ) -> Result<allocation::BoundedBytes, CapacityObservationFailure>;

    fn read_limit(
        &self,
        hierarchy: Hierarchy<'_>,
        depth: usize,
        name: &str,
        source: CapacityObservationSource,
    ) -> Result<allocation::BoundedBytes, CapacityObservationFailure> {
        let path =
            absolute_limit_path(hierarchy, depth, name, allocation::AllocationControl::NONE)?;
        self.read(&path, MAX_LIMIT_BYTES, source)
    }
}

#[cfg(target_os = "linux")]
struct SystemFileReader;

#[cfg(target_os = "linux")]
impl FileReader for SystemFileReader {
    fn read(
        &self,
        path: &Path,
        maximum: u64,
        source: CapacityObservationSource,
    ) -> Result<allocation::BoundedBytes, CapacityObservationFailure> {
        let file = File::open(path)
            .map_err(|_| CapacityObservationFailure::ObservationUnavailable { source })?;
        allocation::BoundedBytes::read(file, maximum, source, allocation::AllocationControl::NONE)
    }

    fn read_limit(
        &self,
        hierarchy: Hierarchy<'_>,
        depth: usize,
        name: &str,
        source: CapacityObservationSource,
    ) -> Result<allocation::BoundedBytes, CapacityObservationFailure> {
        use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

        // `/proc/self/mountinfo` is a kernel-produced trust boundary. The
        // reported mount point itself is opened once; every cgroup file below
        // it is then resolved descriptor-relatively without symlink traversal
        // or escape from that mount.
        let mount =
            absolute_mount_path(hierarchy.mount_point, allocation::AllocationControl::NONE)?;
        let directory = File::open(mount)
            .map_err(|_| CapacityObservationFailure::ObservationUnavailable { source })?;
        let relative =
            relative_limit_path(hierarchy, depth, name, allocation::AllocationControl::NONE)?;
        let descriptor = openat2(
            &directory,
            relative,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| CapacityObservationFailure::ObservationUnavailable { source })?;
        allocation::BoundedBytes::read(
            File::from(descriptor),
            MAX_LIMIT_BYTES,
            source,
            allocation::AllocationControl::NONE,
        )
    }
}

#[cfg(target_os = "linux")]
fn absolute_mount_path(
    mount_point: &str,
    control: allocation::AllocationControl,
) -> Result<PathBuf, CapacityObservationFailure> {
    let source = CapacityObservationSource::CgroupMounts;
    let mut path = allocation::BoundedPathBytes::new(
        mount_point.len(),
        MAX_RESOLVED_PATH_BYTES,
        source,
        control,
    )?;
    append_encoded(&mut path, mount_point, source)?;
    Ok(path.into_path())
}

#[cfg(target_os = "linux")]
fn relative_limit_path(
    hierarchy: Hierarchy<'_>,
    depth: usize,
    name: &str,
    control: allocation::AllocationControl,
) -> Result<PathBuf, CapacityObservationFailure> {
    build_limit_path(None, hierarchy, depth, name, control)
}

#[cfg(any(target_os = "linux", test))]
fn absolute_limit_path(
    hierarchy: Hierarchy<'_>,
    depth: usize,
    name: &str,
    control: allocation::AllocationControl,
) -> Result<PathBuf, CapacityObservationFailure> {
    build_limit_path(Some(hierarchy.mount_point), hierarchy, depth, name, control)
}

#[cfg(any(target_os = "linux", test))]
fn build_limit_path(
    mount_point: Option<&str>,
    hierarchy: Hierarchy<'_>,
    depth: usize,
    name: &str,
    control: allocation::AllocationControl,
) -> Result<PathBuf, CapacityObservationFailure> {
    let source = match hierarchy.controller {
        Controller::Memory => CapacityObservationSource::CgroupMemory,
        Controller::Unified | Controller::Cpu => CapacityObservationSource::CgroupCpu,
    };
    if depth > hierarchy.relative.len || name.is_empty() || name.as_bytes().contains(&0) {
        return Err(CapacityObservationFailure::MalformedLimit { source });
    }
    let mut required = mount_point.map_or(0, str::len);
    for component in hierarchy.relative.components[..depth].iter().flatten() {
        required = required
            .checked_add(component.len().saturating_add(1))
            .ok_or(CapacityObservationFailure::Arithmetic { source })?;
    }
    required = required
        .checked_add(name.len().saturating_add(1))
        .ok_or(CapacityObservationFailure::Arithmetic { source })?;
    let mut path =
        allocation::BoundedPathBytes::new(required, MAX_RESOLVED_PATH_BYTES, source, control)?;
    if let Some(mount_point) = mount_point {
        append_encoded(&mut path, mount_point, source)?;
    }
    let mut has_bytes = mount_point.is_some();
    for component in hierarchy.relative.components[..depth].iter().flatten() {
        if has_bytes {
            path.push(b'/', source)?;
        }
        path.extend(component.as_bytes(), source)?;
        has_bytes = true;
    }
    if has_bytes {
        path.push(b'/', source)?;
    }
    path.extend(name.as_bytes(), source)?;
    Ok(path.into_path())
}

#[cfg(any(target_os = "linux", test))]
fn append_encoded(
    path: &mut allocation::BoundedPathBytes,
    encoded: &str,
    source: CapacityObservationSource,
) -> Result<(), CapacityObservationFailure> {
    let mut index = 0;
    while index < encoded.len() {
        let (byte, consumed) = parsers::decode_byte(&encoded.as_bytes()[index..])
            .ok_or(CapacityObservationFailure::MalformedLimit { source })?;
        path.push(byte, source)?;
        index += consumed;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn observe_memory_bytes() -> Result<u64, CapacityObservationFailure> {
    observe_memory_with(&SystemFileReader)
}

#[cfg(any(target_os = "linux", test))]
fn observe_memory_with(reader: &impl FileReader) -> Result<u64, CapacityObservationFailure> {
    let host_bytes = reader.read(
        Path::new("/proc/meminfo"),
        MAX_MEMINFO_BYTES,
        CapacityObservationSource::HostMemory,
    )?;
    let host = parsers::meminfo(host_bytes.as_slice())?;
    let limits = observe_cgroups(reader)?;
    let memory = limits.memory.map_or(host, |headroom| host.min(headroom));
    if memory == 0 {
        Err(CapacityObservationFailure::ZeroCapacity {
            dimension: crate::ResourceDimension::MemoryBytes,
        })
    } else {
        Ok(memory)
    }
}

#[cfg(target_os = "linux")]
pub(super) fn observe_cpu_work_units(host: u64) -> Result<u64, CapacityObservationFailure> {
    observe_cpu_with(&SystemFileReader, host)
}

#[cfg(any(target_os = "linux", test))]
fn observe_cpu_with(
    reader: &impl FileReader,
    host: u64,
) -> Result<u64, CapacityObservationFailure> {
    let limits = observe_cgroups(reader)?;
    Ok(limits.cpu.map_or(host, |quota| host.min(quota)))
}

#[cfg(any(target_os = "linux", test))]
#[derive(Default)]
struct CgroupLimits {
    cpu: Option<u64>,
    memory: Option<u64>,
}

#[cfg(any(target_os = "linux", test))]
fn observe_cgroups(reader: &impl FileReader) -> Result<CgroupLimits, CapacityObservationFailure> {
    let membership_bytes = reader.read(
        Path::new("/proc/self/cgroup"),
        MAX_CGROUP_MEMBERSHIP_BYTES,
        CapacityObservationSource::CgroupMembership,
    )?;
    let mount_bytes = reader.read(
        Path::new("/proc/self/mountinfo"),
        MAX_MOUNTINFO_BYTES,
        CapacityObservationSource::CgroupMounts,
    )?;
    let memberships = parsers::memberships(membership_bytes.as_slice())?;
    let mounts = parsers::mounts(mount_bytes.as_slice())?;
    let hierarchies = parsers::resolve(memberships, mounts)?;
    let mut limits = CgroupLimits::default();
    for hierarchy in hierarchies.iter() {
        for depth in (0..=hierarchy.relative.len).rev() {
            match hierarchy.controller {
                Controller::Unified => {
                    let cpu = reader.read_limit(
                        hierarchy,
                        depth,
                        "cpu.max",
                        CapacityObservationSource::CgroupCpu,
                    )?;
                    merge_minimum(&mut limits.cpu, values::v2_cpu(cpu.as_slice())?);
                    let memory_limit = reader.read_limit(
                        hierarchy,
                        depth,
                        "memory.max",
                        CapacityObservationSource::CgroupMemory,
                    )?;
                    let memory_current = reader.read_limit(
                        hierarchy,
                        depth,
                        "memory.current",
                        CapacityObservationSource::CgroupMemory,
                    )?;
                    merge_minimum(
                        &mut limits.memory,
                        values::v2_memory(memory_limit.as_slice(), memory_current.as_slice())?,
                    );
                },
                Controller::Cpu => {
                    let quota = reader.read_limit(
                        hierarchy,
                        depth,
                        "cpu.cfs_quota_us",
                        CapacityObservationSource::CgroupCpu,
                    )?;
                    let period = reader.read_limit(
                        hierarchy,
                        depth,
                        "cpu.cfs_period_us",
                        CapacityObservationSource::CgroupCpu,
                    )?;
                    merge_minimum(
                        &mut limits.cpu,
                        values::v1_cpu(quota.as_slice(), period.as_slice())?,
                    );
                },
                Controller::Memory => {
                    let limit = reader.read_limit(
                        hierarchy,
                        depth,
                        "memory.limit_in_bytes",
                        CapacityObservationSource::CgroupMemory,
                    )?;
                    let usage = reader.read_limit(
                        hierarchy,
                        depth,
                        "memory.usage_in_bytes",
                        CapacityObservationSource::CgroupMemory,
                    )?;
                    merge_minimum(
                        &mut limits.memory,
                        values::v1_memory(limit.as_slice(), usage.as_slice())?,
                    );
                },
            }
        }
    }
    Ok(limits)
}

#[cfg(any(target_os = "linux", test))]
fn merge_minimum(current: &mut Option<u64>, candidate: Option<u64>) {
    if let Some(candidate) = candidate {
        *current = Some(current.map_or(candidate, |current| current.min(candidate)));
    }
}

#[cfg(fuzzing)]
pub(super) fn fuzz_parsers(data: &[u8]) {
    const MAX_FUZZ_INPUT: usize = 1024 * 1_024;
    if data.len() > MAX_FUZZ_INPUT {
        return;
    }
    let split = data.len() / 2;
    let (first, second) = data.split_at(split);
    let _ = parsers::meminfo(data);
    if let (Ok(memberships), Ok(mounts)) = (parsers::memberships(first), parsers::mounts(second)) {
        let _ = parsers::resolve(memberships, mounts);
    }
    let _ = values::v2_cpu(data);
    let _ = values::v1_cpu(first, second);
    let _ = values::v2_memory(first, second);
    let _ = values::v1_memory(first, second);
}

#[cfg(test)]
#[path = "tests/linux.rs"]
mod tests;
