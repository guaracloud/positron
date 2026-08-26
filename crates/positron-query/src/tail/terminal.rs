use super::cursor::TailCursor;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TailStats {
    pub(super) scanned_bytes: u64,
    pub(super) decoded_records: u64,
    pub(super) emitted_records: u64,
    pub(super) emitted_bytes: u64,
    pub(super) memory_peak_bytes: u64,
    pub(super) cpu_work_units: u64,
    pub(super) elapsed_seconds: u64,
    pub(super) last_sequence: Option<u64>,
    pub(super) result_digest: [u8; 32],
    pub(super) cumulative_budget: crate::QueryBudget,
    pub(super) resume_count: u64,
    pub(super) repeated_batch_count: u64,
    pub(super) reduced_pruning: bool,
    pub(super) limiting_budget: Option<crate::QueryBudgetDimension>,
}

impl TailStats {
    #[must_use]
    pub const fn scanned_bytes(self) -> u64 {
        self.scanned_bytes
    }

    #[must_use]
    pub const fn decoded_records(self) -> u64 {
        self.decoded_records
    }

    #[must_use]
    pub const fn emitted_records(self) -> u64 {
        self.emitted_records
    }

    #[must_use]
    pub const fn emitted_bytes(self) -> u64 {
        self.emitted_bytes
    }

    #[must_use]
    pub const fn memory_peak_bytes(self) -> u64 {
        self.memory_peak_bytes
    }

    #[must_use]
    pub const fn cpu_work_units(self) -> u64 {
        self.cpu_work_units
    }

    #[must_use]
    pub const fn elapsed_seconds(self) -> u64 {
        self.elapsed_seconds
    }

    #[must_use]
    pub const fn last_sequence(self) -> Option<u64> {
        self.last_sequence
    }

    #[must_use]
    pub const fn result_digest(self) -> [u8; 32] {
        self.result_digest
    }

    #[must_use]
    pub const fn cumulative_budget(self) -> crate::QueryBudget {
        self.cumulative_budget
    }

    #[must_use]
    pub const fn resume_count(self) -> u64 {
        self.resume_count
    }

    #[must_use]
    pub const fn repeated_batch_count(self) -> u64 {
        self.repeated_batch_count
    }

    #[must_use]
    pub const fn reduced_pruning(self) -> bool {
        self.reduced_pruning
    }

    #[must_use]
    pub const fn limiting_budget(self) -> Option<crate::QueryBudgetDimension> {
        self.limiting_budget
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TailTerminal {
    ConsumerLagged {
        cursor: Option<TailCursor>,
        stats: TailStats,
    },
    BudgetExhausted {
        cursor: Option<TailCursor>,
        stats: TailStats,
    },
    Expired {
        cursor: Option<TailCursor>,
        stats: TailStats,
    },
    AuthorizationChanged {
        cursor: Option<TailCursor>,
        stats: TailStats,
    },
    Cancelled {
        cursor: Option<TailCursor>,
        stats: TailStats,
    },
    Disconnected {
        cursor: Option<TailCursor>,
        stats: TailStats,
    },
    StoreUnavailable {
        cursor: Option<TailCursor>,
        stats: TailStats,
    },
}

#[derive(Clone, Copy)]
pub(super) enum TerminalKind {
    Expired,
    AuthorizationChanged,
    Cancelled,
    Disconnected,
    StoreUnavailable,
}

impl TerminalKind {
    pub(super) fn build(self, cursor: Option<TailCursor>, stats: TailStats) -> TailTerminal {
        match self {
            Self::Expired => TailTerminal::Expired { cursor, stats },
            Self::AuthorizationChanged => TailTerminal::AuthorizationChanged { cursor, stats },
            Self::Cancelled => TailTerminal::Cancelled { cursor, stats },
            Self::Disconnected => TailTerminal::Disconnected { cursor, stats },
            Self::StoreUnavailable => TailTerminal::StoreUnavailable { cursor, stats },
        }
    }
}
