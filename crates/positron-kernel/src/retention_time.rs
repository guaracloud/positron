use std::collections::BTreeMap;
#[cfg(any(test, fuzzing, feature = "test-support"))]
use std::sync::Arc;
use std::sync::Mutex;
#[cfg(any(test, fuzzing, feature = "test-support"))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use positron_domain::time::UnixNanoseconds;

use crate::{
    IngestTime, LifecycleClockFailure, LifecycleClockSource, SegmentScope,
    SystemLifecycleClockSource,
};

/// Process-monotonic time authority for the conservative Release 1 retention frontier.
///
/// The external clock is sampled exactly once at establishment. All later
/// movement comes from monotonic elapsed time; per-scope durable frontier
/// recovery is owned by the Active Segment Ledger and Catalog.
pub struct RetentionTimeAuthority {
    epoch: UnixNanoseconds,
    elapsed: ElapsedSource,
    destructive_retention: bool,
    scopes: Mutex<BTreeMap<SegmentScope, ScopeBaseline>>,
}

#[derive(Clone, Copy)]
struct ScopeBaseline {
    instant: UnixNanoseconds,
    elapsed_at_start: u64,
}

enum ElapsedSource {
    System(Instant),
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    Manual(Arc<AtomicU64>),
}

impl ElapsedSource {
    fn nanoseconds(&self) -> Result<u64, LifecycleClockFailure> {
        match self {
            Self::System(started) => u64::try_from(started.elapsed().as_nanos())
                .map_err(|_| LifecycleClockFailure::OutOfRange),
            #[cfg(any(test, fuzzing, feature = "test-support"))]
            Self::Manual(elapsed) => Ok(elapsed.load(Ordering::Acquire)),
        }
    }
}

#[cfg(any(test, fuzzing))]
pub(crate) struct ManualRetentionTime(Arc<AtomicU64>);

#[cfg(any(test, fuzzing))]
impl ManualRetentionTime {
    pub(crate) fn advance(&self, nanoseconds: u64) -> Result<(), LifecycleClockFailure> {
        self.0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |elapsed| {
                elapsed.checked_add(nanoseconds)
            })
            .map(|_| ())
            .map_err(|_| LifecycleClockFailure::OutOfRange)
    }

    #[cfg(fuzzing)]
    pub(crate) fn nanoseconds(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

impl RetentionTimeAuthority {
    pub fn establish() -> Result<Self, LifecycleClockFailure> {
        let epoch = SystemLifecycleClockSource.read()?;
        Ok(Self {
            epoch,
            elapsed: ElapsedSource::System(Instant::now()),
            destructive_retention: true,
            scopes: Mutex::new(BTreeMap::new()),
        })
    }

    #[cfg(any(test, fuzzing))]
    pub(crate) fn establish_with_manual_elapsed(
        epoch: UnixNanoseconds,
    ) -> (Self, ManualRetentionTime) {
        let elapsed = Arc::new(AtomicU64::new(0));
        (
            Self {
                epoch,
                elapsed: ElapsedSource::Manual(Arc::clone(&elapsed)),
                destructive_retention: true,
                scopes: Mutex::new(BTreeMap::new()),
            },
            ManualRetentionTime(elapsed),
        )
    }

    /// Constructs deterministic Ingest Time authority for cross-crate tests.
    ///
    /// This explicitly cannot authorize destructive retention.
    #[cfg(feature = "test-support")]
    pub fn for_test_ingest_time(epoch: UnixNanoseconds) -> Self {
        let elapsed = Arc::new(AtomicU64::new(0));
        Self {
            epoch,
            elapsed: ElapsedSource::Manual(elapsed),
            destructive_retention: false,
            scopes: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn authorizes_destructive_retention(&self) -> bool {
        self.destructive_retention
    }

    pub(crate) fn ingest_time(
        &self,
        scope: SegmentScope,
        durable: Option<IngestTime>,
    ) -> Result<IngestTime, LifecycleClockFailure> {
        let elapsed = self.elapsed.nanoseconds()?;
        let mut scopes = self
            .scopes
            .lock()
            .map_err(|_| LifecycleClockFailure::Unavailable)?;
        if !scopes.contains_key(&scope) && scopes.len() >= crate::MAX_TENANT_QUOTAS {
            return Err(LifecycleClockFailure::OutOfRange);
        }
        let baseline = scopes.entry(scope).or_insert_with(|| ScopeBaseline {
            instant: durable.map_or(self.epoch, IngestTime::instant),
            elapsed_at_start: 0,
        });
        let advanced = elapsed
            .checked_sub(baseline.elapsed_at_start)
            .and_then(|delta| i64::try_from(delta).ok())
            .and_then(|delta| baseline.instant.value().checked_add(delta))
            .map(UnixNanoseconds::new)
            .ok_or(LifecycleClockFailure::OutOfRange)?;
        #[cfg(feature = "test-support")]
        if !self.destructive_retention {
            return Ok(IngestTime::from_unretained_test(advanced));
        }
        Ok(IngestTime::from_authenticated_durable(advanced))
    }

    pub(crate) fn lease_recovery_time(
        &self,
        scope: SegmentScope,
        durable: Option<IngestTime>,
    ) -> Result<Option<u64>, LifecycleClockFailure> {
        let Some(durable) = durable else {
            return Ok(None);
        };
        self.ingest_time(scope, Some(durable))?
            .instant()
            .value()
            .checked_div(1_000_000_000)
            .and_then(|value| u64::try_from(value).ok())
            .map(Some)
            .ok_or(LifecycleClockFailure::OutOfRange)
    }
}

impl std::fmt::Debug for RetentionTimeAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RetentionTimeAuthority { <monotonic> }")
    }
}
