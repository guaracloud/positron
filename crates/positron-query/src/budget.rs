use crate::{QueryFailure, QueryFailureCode};

/// Identifies the effective query-budget limit that stopped execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryBudgetDimension {
    ScannedBytes,
    DecodedRecords,
    OutputRows,
    OutputBytes,
    MemoryBytes,
    CpuWorkUnits,
    WallSeconds,
    MaximumTimeRangeNanoseconds,
}

/// Finite cumulative limits admitted before query text is parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryBudget {
    scanned_bytes: u64,
    decoded_records: u64,
    output_rows: u64,
    output_bytes: u64,
    memory_bytes: u64,
    cpu_work_units: u64,
    wall_seconds: u64,
    maximum_time_range_nanoseconds: u64,
}

const DEFAULT_MAXIMUM_TIME_RANGE_NANOSECONDS: u64 = 31 * 24 * 60 * 60 * 1_000_000_000;

impl QueryBudget {
    pub fn new(
        scanned_bytes: u64,
        decoded_records: u64,
        output_rows: u64,
        output_bytes: u64,
        memory_bytes: u64,
        wall_seconds: u64,
    ) -> Result<Self, QueryFailure> {
        if [
            scanned_bytes,
            decoded_records,
            output_rows,
            output_bytes,
            memory_bytes,
            wall_seconds,
        ]
        .contains(&0)
            || decoded_records > 1_024
            || output_rows > 1_024
        {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        if wall_seconds > positron_kernel::MAX_SNAPSHOT_LEASE_TTL_SECONDS {
            return Err(QueryFailure::for_budget(
                QueryFailureCode::InvalidBudget,
                QueryBudgetDimension::WallSeconds,
            ));
        }
        Ok(Self {
            scanned_bytes,
            decoded_records,
            output_rows,
            output_bytes,
            memory_bytes,
            cpu_work_units: 6,
            wall_seconds,
            maximum_time_range_nanoseconds: DEFAULT_MAXIMUM_TIME_RANGE_NANOSECONDS,
        })
    }

    pub fn with_cpu_work_units(mut self, maximum: u64) -> Result<Self, QueryFailure> {
        if maximum == 0 || maximum > 1_024 {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        self.cpu_work_units = maximum;
        Ok(self)
    }

    pub fn with_maximum_time_range_nanoseconds(
        mut self,
        maximum: u64,
    ) -> Result<Self, QueryFailure> {
        if maximum == 0 || maximum > DEFAULT_MAXIMUM_TIME_RANGE_NANOSECONDS {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        self.maximum_time_range_nanoseconds = maximum;
        Ok(self)
    }

    #[must_use]
    pub const fn scanned_bytes(self) -> u64 {
        self.scanned_bytes
    }

    #[must_use]
    pub const fn decoded_records(self) -> u64 {
        self.decoded_records
    }

    #[must_use]
    pub const fn output_rows(self) -> u64 {
        self.output_rows
    }

    #[must_use]
    pub const fn output_bytes(self) -> u64 {
        self.output_bytes
    }

    #[must_use]
    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    #[must_use]
    pub const fn wall_seconds(self) -> u64 {
        self.wall_seconds
    }

    #[must_use]
    pub const fn cpu_work_units(self) -> u64 {
        self.cpu_work_units
    }

    #[must_use]
    pub const fn maximum_time_range_nanoseconds(self) -> u64 {
        self.maximum_time_range_nanoseconds
    }
}
