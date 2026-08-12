use crate::resource_governor::{
    CPU_WORK_UNITS_PER_LOGICAL_CPU, CapacityObservationFailure, CapacityObservationSource,
};

pub(super) fn v2_cpu(bytes: &[u8]) -> Result<Option<u64>, CapacityObservationFailure> {
    let text = one_line(bytes, CapacityObservationSource::CgroupCpu)?;
    let mut fields = text.split_ascii_whitespace();
    let quota = fields
        .next()
        .ok_or(malformed(CapacityObservationSource::CgroupCpu))?;
    let period = number(fields.next(), CapacityObservationSource::CgroupCpu)?;
    if fields.next().is_some() || period == 0 {
        return Err(malformed(CapacityObservationSource::CgroupCpu));
    }
    if quota == "max" {
        Ok(None)
    } else {
        cpu_work_units(
            number(Some(quota), CapacityObservationSource::CgroupCpu)?,
            period,
        )
        .map(Some)
    }
}

pub(super) fn v1_cpu(
    quota_bytes: &[u8],
    period_bytes: &[u8],
) -> Result<Option<u64>, CapacityObservationFailure> {
    let quota = one_line(quota_bytes, CapacityObservationSource::CgroupCpu)?;
    let period = number(
        Some(one_line(
            period_bytes,
            CapacityObservationSource::CgroupCpu,
        )?),
        CapacityObservationSource::CgroupCpu,
    )?;
    if period == 0 {
        return Err(malformed(CapacityObservationSource::CgroupCpu));
    }
    if quota == "-1" {
        return Ok(None);
    }
    cpu_work_units(
        number(Some(quota), CapacityObservationSource::CgroupCpu)?,
        period,
    )
    .map(Some)
}

fn cpu_work_units(quota: u64, period: u64) -> Result<u64, CapacityObservationFailure> {
    if quota == 0 || period == 0 {
        return Err(malformed(CapacityObservationSource::CgroupCpu));
    }
    let units = quota.checked_mul(CPU_WORK_UNITS_PER_LOGICAL_CPU).ok_or(
        CapacityObservationFailure::Arithmetic {
            source: CapacityObservationSource::CgroupCpu,
        },
    )? / period;
    if units == 0 {
        Err(CapacityObservationFailure::ZeroCapacity {
            dimension: crate::ResourceDimension::CpuWorkUnits,
        })
    } else {
        Ok(units)
    }
}

pub(super) fn v2_memory(
    limit_bytes: &[u8],
    current_bytes: &[u8],
) -> Result<Option<u64>, CapacityObservationFailure> {
    let limit = one_line(limit_bytes, CapacityObservationSource::CgroupMemory)?;
    if limit == "max" {
        return Ok(None);
    }
    numeric_memory(limit, current_bytes)
}

pub(super) fn v1_memory(
    limit_bytes: &[u8],
    current_bytes: &[u8],
) -> Result<Option<u64>, CapacityObservationFailure> {
    let limit = one_line(limit_bytes, CapacityObservationSource::CgroupMemory)?;
    numeric_memory(limit, current_bytes)
}

fn numeric_memory(
    limit: &str,
    current_bytes: &[u8],
) -> Result<Option<u64>, CapacityObservationFailure> {
    let limit = number(Some(limit), CapacityObservationSource::CgroupMemory)?;
    let current = number(
        Some(one_line(
            current_bytes,
            CapacityObservationSource::CgroupMemory,
        )?),
        CapacityObservationSource::CgroupMemory,
    )?;
    let headroom = limit
        .checked_sub(current)
        .ok_or(CapacityObservationFailure::Arithmetic {
            source: CapacityObservationSource::CgroupMemory,
        })?;
    if headroom == 0 {
        Err(CapacityObservationFailure::ZeroCapacity {
            dimension: crate::ResourceDimension::MemoryBytes,
        })
    } else {
        Ok(Some(headroom))
    }
}

fn one_line(
    bytes: &[u8],
    source: CapacityObservationSource,
) -> Result<&str, CapacityObservationFailure> {
    let text = std::str::from_utf8(bytes).map_err(|_| malformed(source))?;
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.contains(['\r', '\n']) {
        Err(malformed(source))
    } else {
        Ok(trimmed)
    }
}

fn number(
    value: Option<&str>,
    source: CapacityObservationSource,
) -> Result<u64, CapacityObservationFailure> {
    value
        .ok_or(malformed(source))?
        .parse::<u64>()
        .map_err(|_| malformed(source))
}

const fn malformed(source: CapacityObservationSource) -> CapacityObservationFailure {
    CapacityObservationFailure::MalformedLimit { source }
}

#[cfg(test)]
#[path = "../tests/values.rs"]
mod tests;
