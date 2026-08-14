use positron_kernel::CommitReceipt;

/// One independently committed Admission Group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedAdmission {
    pub(super) receipt: CommitReceipt,
    pub(super) records: usize,
}

/// A durable accepted subset plus explicit permanent rejections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartialAdmission {
    committed: CommittedAdmission,
    rejections: [RejectionDetail; 3],
    rejection_class_count: u8,
}

/// One deterministic permanent-rejection class and its bounded record count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RejectionDetail {
    code: IngestFailureCode,
    records: usize,
}

impl RejectionDetail {
    const EMPTY: Self = Self {
        code: IngestFailureCode::PolicyRejected,
        records: 0,
    };

    #[must_use]
    pub const fn code(self) -> IngestFailureCode {
        self.code
    }

    #[must_use]
    pub const fn records(self) -> usize {
        self.records
    }
}

impl PartialAdmission {
    #[must_use]
    pub const fn committed(self) -> CommittedAdmission {
        self.committed
    }

    #[must_use]
    pub fn permanently_rejected(self) -> usize {
        self.rejections().iter().map(|detail| detail.records).sum()
    }

    #[must_use]
    pub fn rejections(&self) -> &[RejectionDetail] {
        self.rejections
            .get(..usize::from(self.rejection_class_count))
            .unwrap_or_default()
    }
}

impl CommittedAdmission {
    #[must_use]
    pub const fn receipt(self) -> CommitReceipt {
        self.receipt
    }

    #[must_use]
    pub const fn records(self) -> usize {
        self.records
    }
}

/// Stable secret-free failure classes at the native ingest seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestFailureCode {
    TenantConflict,
    PolicyRejected,
    InvalidRecord,
    ValueLimitExceeded,
    CapacityUnavailable,
    StorageUnavailable,
    Cancelled,
    IdempotencyConflict,
}

/// Complete outcome for one independently admitted group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestOutcome {
    Full(CommittedAdmission),
    Partial(PartialAdmission),
    Retryable(IngestFailureCode),
    Permanent(IngestFailureCode),
    Ambiguous(IngestFailureCode),
}

impl IngestOutcome {
    /// Converts only a known post-commit producer disconnect into explicit
    /// ambiguity. Pre-commit failures retain their original classification.
    #[must_use]
    pub const fn producer_disconnected_after_commit(self) -> Self {
        match self {
            Self::Full(_) | Self::Partial(_) => {
                Self::Ambiguous(IngestFailureCode::StorageUnavailable)
            },
            other => other,
        }
    }
}

pub(super) fn increment_rejection(counts: &mut [usize; 3], code: IngestFailureCode) {
    let index = match code {
        IngestFailureCode::PolicyRejected => 0,
        IngestFailureCode::InvalidRecord => 1,
        IngestFailureCode::ValueLimitExceeded => 2,
        _ => return,
    };
    if let Some(count) = counts.get_mut(index) {
        *count = count.saturating_add(1);
    }
}

pub(super) fn partial_admission(
    committed: CommittedAdmission,
    counts: [usize; 3],
) -> PartialAdmission {
    let codes = [
        IngestFailureCode::PolicyRejected,
        IngestFailureCode::InvalidRecord,
        IngestFailureCode::ValueLimitExceeded,
    ];
    let mut rejections = [RejectionDetail::EMPTY; 3];
    let mut used = 0_u8;
    for (code, records) in codes.into_iter().zip(counts) {
        if records > 0
            && let Some(detail) = rejections.get_mut(usize::from(used))
        {
            *detail = RejectionDetail { code, records };
            used = used.saturating_add(1);
        }
    }
    PartialAdmission {
        committed,
        rejections,
        rejection_class_count: used,
    }
}
