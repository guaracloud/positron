use std::fmt::{Display, Formatter};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Injected monotonic observation seam for deterministic query budget enforcement.
pub trait QueryClock: Send + Sync {
    fn now_seconds(&self) -> Result<u64, QueryClockFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryWorkStage {
    Parse,
    ScanDecode,
    Output,
}

pub trait QueryWorkMeter: Send + Sync {
    fn units(&self, stage: QueryWorkStage) -> Result<u64, QueryWorkFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryWorkFailure;

impl Display for QueryWorkFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("query work meter unavailable")
    }
}

impl std::error::Error for QueryWorkFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryClockFailure;

impl Display for QueryClockFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("query clock unavailable")
    }
}

impl std::error::Error for QueryClockFailure {}

pub(crate) struct SystemQueryClock;
pub(crate) struct FixedQueryWorkMeter;

impl QueryWorkMeter for FixedQueryWorkMeter {
    fn units(&self, _stage: QueryWorkStage) -> Result<u64, QueryWorkFailure> {
        Ok(1)
    }
}

impl QueryClock for SystemQueryClock {
    fn now_seconds(&self) -> Result<u64, QueryClockFailure> {
        static ORIGIN: OnceLock<Result<(Instant, u64), QueryClockFailure>> = OnceLock::new();
        let (instant, unix_seconds) = ORIGIN
            .get_or_init(|| {
                let unix_seconds = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .map_err(|_| QueryClockFailure)?;
                Ok::<_, QueryClockFailure>((Instant::now(), unix_seconds))
            })
            .as_ref()
            .map_err(|_| QueryClockFailure)?;
        unix_seconds
            .checked_add(instant.elapsed().as_secs())
            .ok_or(QueryClockFailure)
    }
}
