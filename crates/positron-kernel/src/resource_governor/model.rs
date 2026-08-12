//! Fixed-size resource accounting values.

use super::failure::GovernorFailure;

/// Number of resource dimensions governed atomically by Release 1.
pub const RESOURCE_DIMENSION_COUNT: usize = 11;

/// A closed resource dimension registered with the Resource Governor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ResourceDimension {
    MemoryBytes,
    QueueSlots,
    TaskSlots,
    BufferCacheBytes,
    BatchItems,
    LeaseSlots,
    RetrySlots,
    IoPermits,
    CpuWorkUnits,
    FileDescriptors,
    DiskHeadroomBytes,
}

impl ResourceDimension {
    /// Every mandatory Release 1 resource dimension in canonical order.
    pub const ALL: [Self; RESOURCE_DIMENSION_COUNT] = [
        Self::MemoryBytes,
        Self::QueueSlots,
        Self::TaskSlots,
        Self::BufferCacheBytes,
        Self::BatchItems,
        Self::LeaseSlots,
        Self::RetrySlots,
        Self::IoPermits,
        Self::CpuWorkUnits,
        Self::FileDescriptors,
        Self::DiskHeadroomBytes,
    ];
}

/// A compact, fixed-size resource vector used without hot-path allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceAmounts([u64; RESOURCE_DIMENSION_COUNT]);

impl ResourceAmounts {
    /// Constructs an explicitly populated resource vector.
    #[must_use]
    pub const fn new(values: [u64; RESOURCE_DIMENSION_COUNT]) -> Self {
        Self(values)
    }

    /// Constructs a nonempty claim against exactly one dimension.
    pub fn only(dimension: ResourceDimension, amount: u64) -> Result<Self, GovernorFailure> {
        if amount == 0 {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        let mut values = [0; RESOURCE_DIMENSION_COUNT];
        set_amount(&mut values, dimension, amount);
        Ok(Self(values))
    }

    /// Returns the amount for one dimension.
    #[must_use]
    pub const fn get(self, dimension: ResourceDimension) -> u64 {
        match dimension {
            ResourceDimension::MemoryBytes => self.0[0],
            ResourceDimension::QueueSlots => self.0[1],
            ResourceDimension::TaskSlots => self.0[2],
            ResourceDimension::BufferCacheBytes => self.0[3],
            ResourceDimension::BatchItems => self.0[4],
            ResourceDimension::LeaseSlots => self.0[5],
            ResourceDimension::RetrySlots => self.0[6],
            ResourceDimension::IoPermits => self.0[7],
            ResourceDimension::CpuWorkUnits => self.0[8],
            ResourceDimension::FileDescriptors => self.0[9],
            ResourceDimension::DiskHeadroomBytes => self.0[10],
        }
    }

    pub(super) const fn zero() -> Self {
        Self([0; RESOURCE_DIMENSION_COUNT])
    }

    pub(super) fn all_positive(self) -> bool {
        self.0.iter().all(|amount| *amount > 0)
    }

    pub(super) fn is_empty(self) -> bool {
        self.0.iter().all(|amount| *amount == 0)
    }

    pub(super) fn is_at_most(self, other: Self) -> bool {
        ResourceDimension::ALL
            .iter()
            .all(|dimension| self.get(*dimension) <= other.get(*dimension))
    }

    pub(super) fn minimum(self, other: Self) -> Self {
        self.zip_map(other, u64::min)
    }

    pub(super) fn checked_add(self, other: Self) -> Option<Self> {
        self.try_zip_map(other, u64::checked_add)
    }

    pub(super) fn checked_sub(self, other: Self) -> Option<Self> {
        self.try_zip_map(other, u64::checked_sub)
    }

    pub(super) fn excess_over(self, floor: Self) -> Self {
        // This is the exact positive part used for reserve consumption, not
        // forgiveness of a conservation invariant: dimensions below the
        // ordinary ceiling consume zero protected capacity by definition.
        self.zip_map(floor, u64::saturating_sub)
    }

    pub(super) fn with_amount(self, dimension: ResourceDimension, amount: u64) -> Self {
        let mut values = self.0;
        set_amount(&mut values, dimension, amount);
        Self(values)
    }

    fn zip_map(self, other: Self, operation: fn(u64, u64) -> u64) -> Self {
        let mut values = [0; RESOURCE_DIMENSION_COUNT];
        for dimension in ResourceDimension::ALL {
            set_amount(
                &mut values,
                dimension,
                operation(self.get(dimension), other.get(dimension)),
            );
        }
        Self(values)
    }

    fn try_zip_map(self, other: Self, operation: fn(u64, u64) -> Option<u64>) -> Option<Self> {
        let mut values = [0; RESOURCE_DIMENSION_COUNT];
        for dimension in ResourceDimension::ALL {
            set_amount(
                &mut values,
                dimension,
                operation(self.get(dimension), other.get(dimension))?,
            );
        }
        Some(Self(values))
    }
}

fn set_amount(
    values: &mut [u64; RESOURCE_DIMENSION_COUNT],
    dimension: ResourceDimension,
    amount: u64,
) {
    match dimension {
        ResourceDimension::MemoryBytes => values[0] = amount,
        ResourceDimension::QueueSlots => values[1] = amount,
        ResourceDimension::TaskSlots => values[2] = amount,
        ResourceDimension::BufferCacheBytes => values[3] = amount,
        ResourceDimension::BatchItems => values[4] = amount,
        ResourceDimension::LeaseSlots => values[5] = amount,
        ResourceDimension::RetrySlots => values[6] = amount,
        ResourceDimension::IoPermits => values[7] = amount,
        ResourceDimension::CpuWorkUnits => values[8] = amount,
        ResourceDimension::FileDescriptors => values[9] = amount,
        ResourceDimension::DiskHeadroomBytes => values[10] = amount,
    }
}
