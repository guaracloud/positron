use std::error::Error;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use positron_domain::time::UnixNanoseconds;

/// A kernel-assigned timestamp that cannot be constructed from caller values.
#[derive(Clone, Copy)]
pub struct IngestTime {
    instant: UnixNanoseconds,
    retention_authenticated: bool,
}

impl IngestTime {
    #[must_use]
    pub const fn instant(self) -> UnixNanoseconds {
        self.instant
    }

    pub(crate) const fn from_authenticated_durable(instant: UnixNanoseconds) -> Self {
        Self {
            instant,
            retention_authenticated: true,
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) const fn from_unretained_test(instant: UnixNanoseconds) -> Self {
        Self {
            instant,
            retention_authenticated: false,
        }
    }

    pub(crate) const fn retention_authenticated(self) -> bool {
        self.retention_authenticated
    }
}

impl std::fmt::Debug for IngestTime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("IngestTime")
            .field(&self.instant)
            .finish()
    }
}

impl PartialEq for IngestTime {
    fn eq(&self, other: &Self) -> bool {
        self.instant == other.instant
    }
}

impl Eq for IngestTime {}

impl PartialOrd for IngestTime {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IngestTime {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.instant.cmp(&other.instant)
    }
}

impl Hash for IngestTime {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.instant.hash(state);
    }
}

/// Stable provenance for destructive age evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionCutoffProvenance {
    PersistedRetentionFrontier,
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
        Ok(IngestTime::from_authenticated_durable(assigned))
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
}
