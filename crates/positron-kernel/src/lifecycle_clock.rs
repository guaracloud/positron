use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use positron_domain::time::UnixNanoseconds;

/// Maximum wall-clock reconciliation movement accepted for age-derived work.
const SAFE_RECONCILIATION_BOUND: UnixNanoseconds = UnixNanoseconds::new(300_000_000_000);

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
    state: Mutex<ClockState>,
    safe_reconciliation_bound: UnixNanoseconds,
}

#[derive(Clone, Copy)]
struct ClockState {
    last: Option<UnixNanoseconds>,
    uncertain: bool,
}

impl<S: LifecycleClockSource> LifecycleClock<S> {
    #[must_use]
    pub const fn new(source: S) -> Self {
        Self {
            source,
            state: Mutex::new(ClockState {
                last: None,
                uncertain: false,
            }),
            safe_reconciliation_bound: SAFE_RECONCILIATION_BOUND,
        }
    }

    pub fn assign_ingest_time(&self) -> Result<IngestTime, LifecycleClockFailure> {
        let observed = self.source.read()?;
        let mut last = self
            .state
            .lock()
            .map_err(|_| LifecycleClockFailure::Unavailable)?;
        if let Some(previous) = last.last {
            if exceeds_bound(previous, observed, self.safe_reconciliation_bound) {
                last.uncertain = true;
                return Ok(IngestTime(previous));
            }
            if last.uncertain {
                last.uncertain = false;
            }
        }
        let assigned = last
            .last
            .map_or(observed, |previous| previous.max(observed));
        last.last = Some(assigned);
        Ok(IngestTime(assigned))
    }

    /// Assigns a lifecycle time only when wall-clock reconciliation is safe.
    /// Ingestion may continue from the last safe anchor while this operation
    /// refuses age-derived destructive work.
    pub fn retention_time(&self) -> Result<IngestTime, LifecycleClockFailure> {
        let observed = self.source.read()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LifecycleClockFailure::Unavailable)?;
        if let Some(previous) = state.last {
            if exceeds_bound(previous, observed, self.safe_reconciliation_bound) {
                state.uncertain = true;
                return Err(LifecycleClockFailure::Uncertain);
            }
            if state.uncertain {
                state.uncertain = false;
            }
        }
        let assigned = state
            .last
            .map_or(observed, |previous| previous.max(observed));
        state.last = Some(assigned);
        Ok(IngestTime(assigned))
    }
}

fn exceeds_bound(
    previous: UnixNanoseconds,
    observed: UnixNanoseconds,
    bound: UnixNanoseconds,
) -> bool {
    let distance = i128::from(observed.value()) - i128::from(previous.value());
    distance.unsigned_abs() > u128::from(bound.value().unsigned_abs())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleClockFailure {
    Unavailable,
    Uncertain,
}

impl Display for LifecycleClockFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "lifecycle clock unavailable",
            Self::Uncertain => "lifecycle clock uncertain",
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
    fn retention_pauses_on_large_wall_clock_movement_until_reconciled() {
        let clock = LifecycleClock::new(SequenceSource(Mutex::new(vec![
            UnixNanoseconds::new(10),
            UnixNanoseconds::new(1_000_000_000_000),
            UnixNanoseconds::new(10),
        ])));
        assert_eq!(
            clock.assign_ingest_time().expect("anchor").instant(),
            UnixNanoseconds::new(10)
        );
        assert_eq!(
            clock
                .retention_time()
                .expect_err("large movement is uncertain"),
            LifecycleClockFailure::Uncertain
        );
        assert_eq!(
            clock.retention_time().expect("return to anchor").instant(),
            UnixNanoseconds::new(10)
        );
        assert_eq!(
            LifecycleClockFailure::Uncertain.to_string(),
            "lifecycle clock uncertain"
        );
    }
}
