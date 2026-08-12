//! Allocation-free parsing of bounded Linux procfs cgroup descriptions.

use super::{
    ComponentPath, Controller, Hierarchy, MAX_CONTROLLER_MOUNTS, MAX_HIERARCHIES, Memberships,
    Mount, Mounts, ResolvedHierarchies,
};
use crate::resource_governor::{CapacityObservationFailure, CapacityObservationSource};

const MAX_MEMINFO_LINES: usize = 4_096;
const MAX_MEMINFO_LINE_BYTES: usize = 1_024;
const MAX_MEMBERSHIP_LINES: usize = 4_096;
const MAX_MEMBERSHIP_LINE_BYTES: usize = 4_096;
const MAX_MOUNTINFO_LINES: usize = 16_384;
const MAX_MOUNTINFO_LINE_BYTES: usize = 64 * 1_024;

pub(super) fn meminfo(bytes: &[u8]) -> Result<u64, CapacityObservationFailure> {
    let text = text(bytes, CapacityObservationSource::HostMemory)?;
    let mut total = None;
    let mut available = None;
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_MEMINFO_LINES || line.len() > MAX_MEMINFO_LINE_BYTES {
            return Err(malformed(CapacityObservationSource::HostMemory));
        }
        let mut fields = line.split_ascii_whitespace();
        match fields.next() {
            Some("MemTotal:") => total = Some(kilobytes(fields)?),
            Some("MemAvailable:") => available = Some(kilobytes(fields)?),
            _ => {},
        }
    }
    let total = total.ok_or(malformed(CapacityObservationSource::HostMemory))?;
    let available = available.ok_or(malformed(CapacityObservationSource::HostMemory))?;
    let bytes = total.min(available);
    if bytes == 0 {
        Err(CapacityObservationFailure::ZeroCapacity {
            dimension: crate::ResourceDimension::MemoryBytes,
        })
    } else {
        Ok(bytes)
    }
}

fn kilobytes<'a>(
    mut fields: impl Iterator<Item = &'a str>,
) -> Result<u64, CapacityObservationFailure> {
    let value = fields
        .next()
        .ok_or(malformed(CapacityObservationSource::HostMemory))?
        .parse::<u64>()
        .map_err(|_| malformed(CapacityObservationSource::HostMemory))?;
    if fields.next() != Some("kB") || fields.next().is_some() {
        return Err(malformed(CapacityObservationSource::HostMemory));
    }
    value
        .checked_mul(1_024)
        .ok_or(CapacityObservationFailure::Arithmetic {
            source: CapacityObservationSource::HostMemory,
        })
}

pub(super) fn memberships(bytes: &[u8]) -> Result<Memberships<'_>, CapacityObservationFailure> {
    let text = text(bytes, CapacityObservationSource::CgroupMembership)?;
    let mut result = Memberships::default();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_MEMBERSHIP_LINES || line.len() > MAX_MEMBERSHIP_LINE_BYTES {
            return Err(malformed(CapacityObservationSource::CgroupMembership));
        }
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields
            .next()
            .ok_or(malformed(CapacityObservationSource::CgroupMembership))?;
        let controllers = fields
            .next()
            .ok_or(malformed(CapacityObservationSource::CgroupMembership))?;
        let path = fields
            .next()
            .ok_or(malformed(CapacityObservationSource::CgroupMembership))?;
        let path = normalized_absolute(path, false, CapacityObservationSource::CgroupMembership)?;
        if controllers.is_empty() {
            assign_unique(&mut result.unified, path)?;
        } else {
            for controller in controllers.split(',') {
                match controller {
                    "cpu" | "cpuacct" => assign_unique(&mut result.cpu, path)?,
                    "memory" => assign_unique(&mut result.memory, path)?,
                    _ => {},
                }
            }
        }
    }
    Ok(result)
}

fn assign_unique<'a>(
    slot: &mut Option<ComponentPath<'a>>,
    path: ComponentPath<'a>,
) -> Result<(), CapacityObservationFailure> {
    if slot.replace(path).is_some() {
        Err(CapacityObservationFailure::AmbiguousHierarchy)
    } else {
        Ok(())
    }
}

pub(super) fn mounts(bytes: &[u8]) -> Result<Mounts<'_>, CapacityObservationFailure> {
    let text = text(bytes, CapacityObservationSource::CgroupMounts)?;
    let mut mounts = Mounts::default();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_MOUNTINFO_LINES || line.len() > MAX_MOUNTINFO_LINE_BYTES {
            return Err(malformed(CapacityObservationSource::CgroupMounts));
        }
        let (before, after) = line
            .split_once(" - ")
            .ok_or(malformed(CapacityObservationSource::CgroupMounts))?;
        let before = fields::<6>(before)?;
        let after = fields::<3>(after)?;
        let root = normalized_absolute(before[3], true, CapacityObservationSource::CgroupMounts)?;
        let _ = normalized_absolute(before[4], true, CapacityObservationSource::CgroupMounts)?;
        let mount = Mount {
            root,
            mount_point: before[4],
        };
        match after[0] {
            "cgroup2" => push_mount(&mut mounts.unified, mount)?,
            "cgroup" => {
                for option in after[2].split(',') {
                    match option {
                        "cpu" | "cpuacct" => push_mount(&mut mounts.cpu, mount)?,
                        "memory" => push_mount(&mut mounts.memory, mount)?,
                        _ => {},
                    }
                }
            },
            _ => {},
        }
    }
    Ok(mounts)
}

fn fields<const N: usize>(value: &str) -> Result<[&str; N], CapacityObservationFailure> {
    let mut result = [""; N];
    let mut count = 0_usize;
    for field in value.split_ascii_whitespace() {
        if count < N {
            result[count] = field;
        }
        count = count.saturating_add(1);
    }
    if count < N {
        Err(malformed(CapacityObservationSource::CgroupMounts))
    } else {
        Ok(result)
    }
}

fn push_mount<'a>(
    mounts: &mut [Option<Mount<'a>>; MAX_CONTROLLER_MOUNTS],
    mount: Mount<'a>,
) -> Result<(), CapacityObservationFailure> {
    let slot = mounts.iter_mut().find(|slot| slot.is_none()).ok_or(
        CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::CgroupMounts,
        },
    )?;
    *slot = Some(mount);
    Ok(())
}

fn normalized_absolute(
    value: &str,
    encoded: bool,
    source: CapacityObservationSource,
) -> Result<ComponentPath<'_>, CapacityObservationFailure> {
    let relative = value.strip_prefix('/').ok_or(malformed(source))?;
    let mut path = ComponentPath::empty();
    if relative.is_empty() {
        return Ok(path);
    }
    for component in relative.split('/') {
        if component.is_empty() || !valid_component(component, encoded) {
            return Err(malformed(source));
        }
        let slot = path.components.get_mut(path.len).ok_or(malformed(source))?;
        *slot = Some(component);
        path.len += 1;
    }
    Ok(path)
}

fn valid_component(component: &str, encoded: bool) -> bool {
    if component.as_bytes().contains(&0) {
        return false;
    }
    if !encoded {
        return component != "." && component != "..";
    }
    decoded_equals(component, b".") == Some(false)
        && decoded_equals(component, b"..") == Some(false)
}

fn decoded_equals(encoded: &str, expected: &[u8]) -> Option<bool> {
    let mut expected_index = 0;
    let mut index = 0;
    let bytes = encoded.as_bytes();
    while index < bytes.len() {
        let (value, consumed) = decode_byte(&bytes[index..])?;
        if expected.get(expected_index).copied() != Some(value) {
            return Some(false);
        }
        expected_index += 1;
        index += consumed;
    }
    Some(expected_index == expected.len())
}

pub(super) fn decode_byte(bytes: &[u8]) -> Option<(u8, usize)> {
    if bytes.first().copied()? != b'\\' {
        return Some((bytes[0], 1));
    }
    let escape = bytes.get(..4)?;
    Some(match escape {
        b"\\040" => (b' ', 4),
        b"\\011" => (b'\t', 4),
        b"\\012" => (b'\n', 4),
        b"\\134" => (b'\\', 4),
        _ => return None,
    })
}

pub(super) fn resolve<'a>(
    memberships: Memberships<'a>,
    mounts: Mounts<'a>,
) -> Result<ResolvedHierarchies<'a>, CapacityObservationFailure> {
    let mut entries = [None; MAX_HIERARCHIES];
    if let Some(membership) = memberships.unified {
        if memberships.cpu.is_some() || memberships.memory.is_some() {
            return Err(CapacityObservationFailure::AmbiguousHierarchy);
        }
        entries[0] = Some(unique_hierarchy(
            Controller::Unified,
            membership,
            &mounts.unified,
        )?);
        return Ok(ResolvedHierarchies { entries });
    }
    if let Some(membership) = memberships.cpu {
        entries[0] = Some(unique_hierarchy(Controller::Cpu, membership, &mounts.cpu)?);
    }
    if let Some(membership) = memberships.memory {
        entries[usize::from(entries[0].is_some())] = Some(unique_hierarchy(
            Controller::Memory,
            membership,
            &mounts.memory,
        )?);
    }
    Ok(ResolvedHierarchies { entries })
}

fn unique_hierarchy<'a>(
    controller: Controller,
    membership: ComponentPath<'a>,
    mounts: &[Option<Mount<'a>>; MAX_CONTROLLER_MOUNTS],
) -> Result<Hierarchy<'a>, CapacityObservationFailure> {
    let mut result = None;
    for mount in mounts.iter().flatten() {
        if let Some(relative) = strip_prefix(membership, mount.root) {
            if result.is_some() {
                return Err(CapacityObservationFailure::AmbiguousHierarchy);
            }
            result = Some(Hierarchy {
                controller,
                mount_point: mount.mount_point,
                relative,
                first_limit_depth: usize::from(
                    controller == Controller::Unified && mount.root.len == 0,
                ),
            });
        }
    }
    result.ok_or(CapacityObservationFailure::ObservationUnavailable {
        source: CapacityObservationSource::CgroupMounts,
    })
}

fn strip_prefix<'a>(
    membership: ComponentPath<'a>,
    root: ComponentPath<'_>,
) -> Option<ComponentPath<'a>> {
    if root.len > membership.len {
        return None;
    }
    for index in 0..root.len {
        let member = membership.components[index]?;
        let encoded = root.components[index]?;
        if decoded_equals(encoded, member.as_bytes()) != Some(true) {
            return None;
        }
    }
    let mut relative = ComponentPath::empty();
    for index in root.len..membership.len {
        relative.components[relative.len] = membership.components[index];
        relative.len += 1;
    }
    Some(relative)
}

fn text(
    bytes: &[u8],
    source: CapacityObservationSource,
) -> Result<&str, CapacityObservationFailure> {
    std::str::from_utf8(bytes).map_err(|_| malformed(source))
}

const fn malformed(source: CapacityObservationSource) -> CapacityObservationFailure {
    CapacityObservationFailure::MalformedLimit { source }
}

#[cfg(test)]
#[path = "../tests/parsers.rs"]
mod tests;
