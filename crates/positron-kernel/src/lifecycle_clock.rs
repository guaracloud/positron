use std::error::Error;
use std::fmt::{Display, Formatter};
use std::num::NonZeroU64;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use positron_domain::time::UnixNanoseconds;

const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// A kernel-assigned timestamp that cannot be constructed from caller values.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IngestTime(UnixNanoseconds);

impl IngestTime {
    #[must_use]
    pub const fn instant(self) -> UnixNanoseconds {
        self.0
    }

    pub(crate) const fn from_authenticated_durable(instant: UnixNanoseconds) -> Self {
        Self(instant)
    }
}

/// Kernel-minted age boundary for one retention evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionCutoff {
    instant: UnixNanoseconds,
    evaluated_at: UnixNanoseconds,
}

impl RetentionCutoff {
    #[must_use]
    pub const fn instant(self) -> UnixNanoseconds {
        self.instant
    }

    #[must_use]
    pub const fn evaluated_at(self) -> UnixNanoseconds {
        self.evaluated_at
    }

    #[must_use]
    pub const fn provenance(self) -> RetentionCutoffProvenance {
        RetentionCutoffProvenance::LifecycleClock
    }
}

/// Stable provenance for destructive age evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionCutoffProvenance {
    LifecycleClock,
}

/// Trusted wall-clock adapter used only by the Storage Kernel Lifecycle Clock.
pub trait LifecycleClockSource: Send + Sync {
    fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure>;
}

/// Trusted production wall-clock source for kernel-assigned time.
pub struct SystemLifecycleClockSource;

impl LifecycleClockSource for SystemLifecycleClockSource {
    fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LifecycleClockFailure::Unavailable)?;
        let nanoseconds =
            i64::try_from(elapsed.as_nanos()).map_err(|_| LifecycleClockFailure::Unavailable)?;
        Ok(UnixNanoseconds::new(nanoseconds))
    }
}

/// Deterministic clock adapter for kernel integration tests and replay fixtures.
#[derive(Clone, Copy, Debug)]
pub struct FixedLifecycleClockSource(UnixNanoseconds);

impl FixedLifecycleClockSource {
    #[must_use]
    pub const fn new(instant: UnixNanoseconds) -> Self {
        Self(instant)
    }
}

impl LifecycleClockSource for FixedLifecycleClockSource {
    fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
        Ok(self.0)
    }
}

/// The kernel time authority that assigns non-decreasing Ingest Time.
pub struct LifecycleClock<S> {
    source: S,
    last: Mutex<Option<UnixNanoseconds>>,
}

impl<S: LifecycleClockSource> LifecycleClock<S> {
    #[must_use]
    pub const fn new(source: S) -> Self {
        Self {
            source,
            last: Mutex::new(None),
        }
    }

    pub fn assign_ingest_time(&self) -> Result<IngestTime, LifecycleClockFailure> {
        let observed = self.source.read()?;
        let mut last = self
            .last
            .lock()
            .map_err(|_| LifecycleClockFailure::Unavailable)?;
        let assigned = last.map_or(observed, |previous| previous.max(observed));
        *last = Some(assigned);
        Ok(IngestTime(assigned))
    }
}

impl LifecycleClock<SystemLifecycleClockSource> {
    /// Mints a destructive retention boundary from the production kernel
    /// clock and a bounded tenant-and-store duration.
    ///
    /// Test and replay clocks may assign deterministic ingest time, but cannot
    /// mint deletion authority.
    pub fn retention_cutoff(
        &self,
        retention_seconds: NonZeroU64,
    ) -> Result<RetentionCutoff, LifecycleClockFailure> {
        let now = self.assign_ingest_time()?.instant();
        let retention_nanos = retention_seconds
            .get()
            .checked_mul(NANOS_PER_SECOND)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(LifecycleClockFailure::OutOfRange)?;
        let instant = now
            .value()
            .checked_sub(retention_nanos)
            .map(UnixNanoseconds::new)
            .ok_or(LifecycleClockFailure::OutOfRange)?;
        Ok(RetentionCutoff {
            instant,
            evaluated_at: now,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleClockFailure {
    Unavailable,
    OutOfRange,
}

impl Display for LifecycleClockFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "lifecycle clock unavailable",
            Self::OutOfRange => "lifecycle clock value is out of range",
        })
    }
}

impl Error for LifecycleClockFailure {}

#[cfg(test)]
mod tests {
    use super::*;

    struct SequenceSource(Mutex<Vec<UnixNanoseconds>>);

    impl LifecycleClockSource for SequenceSource {
        fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
            self.0
                .lock()
                .map_err(|_| LifecycleClockFailure::Unavailable)?
                .pop()
                .ok_or(LifecycleClockFailure::Unavailable)
        }
    }

    #[test]
    fn assignments_are_non_decreasing_and_source_failure_is_typed() {
        let clock = LifecycleClock::new(SequenceSource(Mutex::new(vec![
            UnixNanoseconds::new(4),
            UnixNanoseconds::new(5),
        ])));
        assert_eq!(
            clock.assign_ingest_time().expect("first").instant(),
            UnixNanoseconds::new(5)
        );
        assert_eq!(
            clock.assign_ingest_time().expect("clamped").instant(),
            UnixNanoseconds::new(5)
        );
        assert_eq!(
            clock.assign_ingest_time().expect_err("source exhausted"),
            LifecycleClockFailure::Unavailable
        );
        assert_eq!(
            LifecycleClockFailure::Unavailable.to_string(),
            "lifecycle clock unavailable"
        );
    }

    #[test]
    fn retention_cutoff_is_minted_from_kernel_time_with_explicit_provenance() {
        let clock = LifecycleClock::new(SystemLifecycleClockSource);
        let cutoff = clock
            .retention_cutoff(std::num::NonZeroU64::new(2).expect("positive duration"))
            .expect("representable cutoff");

        assert_eq!(
            cutoff.evaluated_at().value() - cutoff.instant().value(),
            2_000_000_000
        );
        assert_eq!(
            cutoff.provenance(),
            RetentionCutoffProvenance::LifecycleClock
        );
    }

    #[test]
    fn retention_cutoff_rejects_unrepresentable_duration() {
        let duration_overflow = LifecycleClock::new(SystemLifecycleClockSource)
            .retention_cutoff(NonZeroU64::new(u64::MAX).expect("nonzero duration"))
            .expect_err("duration multiplication must remain bounded");
        assert_eq!(duration_overflow, LifecycleClockFailure::OutOfRange);
        assert_eq!(
            duration_overflow.to_string(),
            "lifecycle clock value is out of range"
        );
    }
}
