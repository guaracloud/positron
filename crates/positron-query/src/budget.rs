use crate::{QueryFailure, QueryFailureCode};

/// Finite cumulative limits admitted before query text is parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryBudget {
    scanned_bytes: u64,
    decoded_records: u64,
    output_rows: u64,
    output_bytes: u64,
    memory_bytes: u64,
    wall_seconds: u64,
}

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
        Ok(Self {
            scanned_bytes,
            decoded_records,
            output_rows,
            output_bytes,
            memory_bytes,
            wall_seconds,
        })
    }

    pub(crate) const fn scanned_bytes(self) -> u64 {
        self.scanned_bytes
    }

    pub(crate) const fn decoded_records(self) -> u64 {
        self.decoded_records
    }

    pub(crate) const fn output_rows(self) -> u64 {
        self.output_rows
    }

    pub(crate) const fn output_bytes(self) -> u64 {
        self.output_bytes
    }

    pub(crate) const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    pub(crate) const fn wall_seconds(self) -> u64 {
        self.wall_seconds
    }
}
