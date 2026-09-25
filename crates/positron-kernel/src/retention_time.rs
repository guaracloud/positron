use std::collections::BTreeMap;
#[cfg(any(test, fuzzing, feature = "test-support"))]
use std::sync::Arc;
use std::sync::Mutex;
#[cfg(any(test, fuzzing, feature = "test-support"))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use positron_domain::time::UnixNanoseconds;

use crate::{
    CatalogSnapshot, IngestTime, LifecycleClockFailure, LifecycleClockSource, SegmentScope,
    SystemLifecycleClockSource,
};

const CLOCK_ANCHOR_MAGIC: &[u8; 8] = b"PLIFCLK1";
const CLOCK_ANCHOR_VERSION: u8 = 1;
const CLOCK_ANCHOR_BYTES: usize = 8 + 1 + 1 + 8 + 1 + 8 + 1 + 8;

/// Process-monotonic time authority for the conservative Release 1 retention frontier.
///
/// The external clock is sampled exactly once at establishment. All later
/// movement comes from monotonic elapsed time; per-scope durable frontier
/// recovery is owned by the Active Segment Ledger and Catalog.
pub struct RetentionTimeAuthority {
    epoch: UnixNanoseconds,
    elapsed: ElapsedSource,
    destructive_retention: bool,
    source: Option<Box<dyn LifecycleClockSource>>,
    policy: LifecycleClockPolicy,
    safety: Mutex<LifecycleClockSafety>,
    scopes: Mutex<BTreeMap<SegmentScope, ScopeBaseline>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleClockPolicy {
    maximum_reconciliation_offset_nanoseconds: u64,
}

impl LifecycleClockPolicy {
    pub const DEFAULT_MAXIMUM_RECONCILIATION_OFFSET_NANOSECONDS: u64 = 300_000_000_000;

    pub const fn new(
        maximum_reconciliation_offset_nanoseconds: u64,
    ) -> Result<Self, LifecycleClockFailure> {
        if maximum_reconciliation_offset_nanoseconds == 0 {
            return Err(LifecycleClockFailure::OutOfRange);
        }
        Ok(Self {
            maximum_reconciliation_offset_nanoseconds,
        })
    }

    #[must_use]
    pub const fn maximum_reconciliation_offset_nanoseconds(self) -> u64 {
        self.maximum_reconciliation_offset_nanoseconds
    }
}

impl Default for LifecycleClockPolicy {
    fn default() -> Self {
        Self {
            maximum_reconciliation_offset_nanoseconds:
                Self::DEFAULT_MAXIMUM_RECONCILIATION_OFFSET_NANOSECONDS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleClockState {
    Certain,
    ClockUncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleClockStatus {
    state: LifecycleClockState,
    safe_anchor: UnixNanoseconds,
    last_wall_clock: Option<UnixNanoseconds>,
    observed_offset_nanoseconds: Option<i64>,
}

impl LifecycleClockStatus {
    #[must_use]
    pub const fn state(self) -> LifecycleClockState {
        self.state
    }
    #[must_use]
    pub const fn safe_anchor(self) -> UnixNanoseconds {
        self.safe_anchor
    }
    #[must_use]
    pub const fn last_wall_clock(self) -> Option<UnixNanoseconds> {
        self.last_wall_clock
    }
    #[must_use]
    pub const fn observed_offset_nanoseconds(self) -> Option<i64> {
        self.observed_offset_nanoseconds
    }
}

#[derive(Clone, Copy)]
pub(crate) struct LifecycleClockSafety {
    anchor: UnixNanoseconds,
    anchor_elapsed: u64,
    state: LifecycleClockState,
    last_wall_clock: Option<UnixNanoseconds>,
    observed_offset_nanoseconds: Option<i64>,
    revision: u64,
}

#[derive(Clone, Copy)]
struct LifecycleAnchorCheckpoint(LifecycleClockSafety);

/// A candidate lifecycle observation which becomes authoritative only with
/// the Catalog generation that carries its anchor.  Dropping an unpublished
/// candidate restores its predecessor when no later local observation has
/// intervened; otherwise it fences destructive work rather than rolling a
/// concurrent observation backwards.
pub(crate) struct StagedCatalogAnchor<'authority> {
    authority: &'authority RetentionTimeAuthority,
    checkpoint: LifecycleAnchorCheckpoint,
    candidate_revision: Option<u64>,
    candidate_anchor: Option<UnixNanoseconds>,
    committed: bool,
}

impl StagedCatalogAnchor<'_> {
    pub(crate) fn ingest_time(
        &mut self,
        scope: SegmentScope,
        durable: Option<IngestTime>,
    ) -> Result<IngestTime, LifecycleClockFailure> {
        self.observe_candidate(|authority| authority.ingest_time(scope, durable))
    }

    pub(crate) fn destructive_ingest_time(
        &mut self,
        scope: SegmentScope,
        durable: Option<IngestTime>,
    ) -> Result<IngestTime, LifecycleClockFailure> {
        self.observe_candidate(|authority| authority.destructive_ingest_time(scope, durable))
    }

    pub(crate) fn catalog_anchor_record(
        &self,
        observed: IngestTime,
    ) -> Result<Vec<u8>, LifecycleClockFailure> {
        self.authority.catalog_anchor_record(observed)
    }

    pub(crate) fn catalog_anchor_subsumed(
        &self,
        snapshot: &CatalogSnapshot,
    ) -> Result<bool, LifecycleClockFailure> {
        let Some(candidate_anchor) = self.candidate_anchor else {
            return Ok(false);
        };
        let mut durable = None;
        for bytes in snapshot.plaintext_objects() {
            let Some(record) = decode_catalog_anchor(bytes)? else {
                continue;
            };
            if durable.replace(record).is_some() {
                return Err(LifecycleClockFailure::OutOfRange);
            }
        }
        Ok(durable.is_some_and(|record| record.anchor >= candidate_anchor))
    }

    pub(crate) fn commit(mut self) {
        self.committed = true;
    }

    fn observe_candidate<T>(
        &mut self,
        operation: impl FnOnce(&RetentionTimeAuthority) -> Result<T, LifecycleClockFailure>,
    ) -> Result<T, LifecycleClockFailure> {
        let before = self.authority.safety_revision()?;
        let result = operation(self.authority);
        match self.authority.safety_revision() {
            Ok(after) if after != before => self.candidate_revision = Some(after),
            Ok(_) => {},
            // A poisoned or unavailable safety state already fences callers;
            // make Drop take the same conservative path if it regains the
            // lock after this operation returns.
            Err(_) => self.candidate_revision = Some(u64::MAX),
        }
        if self.candidate_revision.is_some() {
            self.candidate_anchor = Some(self.authority.status().safe_anchor());
        }
        result
    }
}

impl Drop for StagedCatalogAnchor<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.authority
                .abandon_catalog_anchor(self.checkpoint, self.candidate_revision);
        }
    }
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
    #[cfg(test)]
    Stepping {
        elapsed: AtomicU64,
        step: u64,
    },
}

impl ElapsedSource {
    fn nanoseconds(&self) -> Result<u64, LifecycleClockFailure> {
        match self {
            Self::System(started) => u64::try_from(started.elapsed().as_nanos())
                .map_err(|_| LifecycleClockFailure::OutOfRange),
            #[cfg(any(test, fuzzing, feature = "test-support"))]
            Self::Manual(elapsed) => Ok(elapsed.load(Ordering::Acquire)),
            #[cfg(test)]
            Self::Stepping { elapsed, step } => elapsed
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(*step)
                })
                .map_err(|_| LifecycleClockFailure::OutOfRange),
        }
    }
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
/// Deterministic elapsed-time control for kernel integration and fuzz tests.
///
/// This adapter is only available to test-support builds and retains the same
/// destructive-retention authority used by production ledgers.
pub struct ManualRetentionTime(Arc<AtomicU64>);

#[cfg(any(test, fuzzing, feature = "test-support"))]
impl ManualRetentionTime {
    /// Advances the authority's monotonic elapsed time by nanoseconds.
    pub fn advance(&self, nanoseconds: u64) -> Result<(), LifecycleClockFailure> {
        self.0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |elapsed| {
                elapsed.checked_add(nanoseconds)
            })
            .map(|_| ())
            .map_err(|_| LifecycleClockFailure::OutOfRange)
    }
}

impl RetentionTimeAuthority {
    pub fn establish() -> Result<Self, LifecycleClockFailure> {
        Self::establish_with_source(SystemLifecycleClockSource, LifecycleClockPolicy::default())
    }

    pub fn establish_with_source<S: LifecycleClockSource + 'static>(
        source: S,
        policy: LifecycleClockPolicy,
    ) -> Result<Self, LifecycleClockFailure> {
        let epoch = source.read()?;
        Ok(Self::with_parts(
            epoch,
            ElapsedSource::System(Instant::now()),
            true,
            Some(Box::new(source)),
            policy,
        ))
    }

    #[cfg(any(test, fuzzing, feature = "test-support"))]
    /// Establishes a destructive-retention authority with a deterministic epoch.
    pub fn establish_with_manual_elapsed(epoch: UnixNanoseconds) -> (Self, ManualRetentionTime) {
        let elapsed = Arc::new(AtomicU64::new(0));
        (
            Self::with_parts(
                epoch,
                ElapsedSource::Manual(Arc::clone(&elapsed)),
                true,
                None,
                LifecycleClockPolicy::default(),
            ),
            ManualRetentionTime(elapsed),
        )
    }

    #[cfg(test)]
    pub(crate) fn establish_with_stepping_elapsed(epoch: UnixNanoseconds, step: u64) -> Self {
        Self::with_parts(
            epoch,
            ElapsedSource::Stepping {
                elapsed: AtomicU64::new(0),
                step,
            },
            true,
            None,
            LifecycleClockPolicy::default(),
        )
    }

    /// Constructs deterministic Ingest Time authority for cross-crate tests.
    ///
    /// This explicitly cannot authorize destructive retention.
    #[cfg(feature = "test-support")]
    pub fn for_test_ingest_time(epoch: UnixNanoseconds) -> Self {
        let elapsed = Arc::new(AtomicU64::new(0));
        Self::with_parts(
            epoch,
            ElapsedSource::Manual(elapsed),
            false,
            None,
            LifecycleClockPolicy::default(),
        )
    }

    fn with_parts(
        epoch: UnixNanoseconds,
        elapsed: ElapsedSource,
        destructive_retention: bool,
        source: Option<Box<dyn LifecycleClockSource>>,
        policy: LifecycleClockPolicy,
    ) -> Self {
        Self {
            epoch,
            elapsed,
            destructive_retention,
            source,
            policy,
            safety: Mutex::new(LifecycleClockSafety {
                anchor: epoch,
                anchor_elapsed: 0,
                state: LifecycleClockState::Certain,
                last_wall_clock: Some(epoch),
                observed_offset_nanoseconds: Some(0),
                revision: 0,
            }),
            scopes: Mutex::new(BTreeMap::new()),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn establish_with_source_and_manual_elapsed<S: LifecycleClockSource + 'static>(
        source: S,
        policy: LifecycleClockPolicy,
    ) -> Result<(Self, ManualRetentionTime), LifecycleClockFailure> {
        let epoch = source.read()?;
        let elapsed = Arc::new(AtomicU64::new(0));
        Ok((
            Self::with_parts(
                epoch,
                ElapsedSource::Manual(Arc::clone(&elapsed)),
                true,
                Some(Box::new(source)),
                policy,
            ),
            ManualRetentionTime(elapsed),
        ))
    }

    pub(crate) fn authorizes_destructive_retention(&self) -> bool {
        self.destructive_retention && self.status().state == LifecycleClockState::Certain
    }

    pub(crate) const fn is_destructive_authority(&self) -> bool {
        self.destructive_retention
    }

    /// Reconciles this process authority with the one authenticated,
    /// instance-level Catalog anchor before a scope can mint time.
    pub(crate) fn recover_catalog_anchor(
        &self,
        snapshot: &CatalogSnapshot,
    ) -> Result<(), LifecycleClockFailure> {
        let mut record = None;
        for bytes in snapshot.plaintext_objects() {
            let Some(candidate) = decode_catalog_anchor(bytes)? else {
                continue;
            };
            if record.replace(candidate).is_some() {
                return Err(LifecycleClockFailure::OutOfRange);
            }
        }
        let Some(record) = record else {
            return Ok(());
        };
        let elapsed = self.elapsed.nanoseconds()?;
        let mut safety = self
            .safety
            .lock()
            .map_err(|_| LifecycleClockFailure::Unavailable)?;
        // The durable anchor is the comparison baseline. A newly observed wall
        // value must never replace it before reconciliation: doing so would
        // turn a restart-time forward jump into a zero offset.
        safety.anchor = record.anchor;
        safety.anchor_elapsed = elapsed;
        safety.last_wall_clock = record.last_wall_clock;
        safety.observed_offset_nanoseconds = record.observed_offset_nanoseconds;
        safety.state = record.state;
        safety.revision = safety
            .revision
            .checked_add(1)
            .ok_or(LifecycleClockFailure::OutOfRange)?;
        drop(safety);
        self.reconcile(record.anchor, elapsed)
    }

    pub(crate) fn catalog_anchor_record(
        &self,
        observed: IngestTime,
    ) -> Result<Vec<u8>, LifecycleClockFailure> {
        let safety = self
            .safety
            .lock()
            .map_err(|_| LifecycleClockFailure::Unavailable)?;
        encode_catalog_anchor(LifecycleClockSafety {
            anchor: safety.anchor.max(observed.instant()),
            ..*safety
        })
    }

    pub(crate) fn stage_catalog_anchor(
        &self,
    ) -> Result<StagedCatalogAnchor<'_>, LifecycleClockFailure> {
        self.safety
            .lock()
            .map(|safety| StagedCatalogAnchor {
                authority: self,
                checkpoint: LifecycleAnchorCheckpoint(*safety),
                candidate_revision: None,
                candidate_anchor: None,
                committed: false,
            })
            .map_err(|_| LifecycleClockFailure::Unavailable)
    }

    fn abandon_catalog_anchor(
        &self,
        checkpoint: LifecycleAnchorCheckpoint,
        candidate_revision: Option<u64>,
    ) {
        let Ok(mut safety) = self.safety.lock() else {
            return;
        };
        let Some(candidate_revision) = candidate_revision else {
            return;
        };
        if safety.revision == candidate_revision {
            let sampled_uncertainty = safety.state == LifecycleClockState::ClockUncertain;
            *safety = checkpoint.0;
            if sampled_uncertainty {
                safety.state = LifecycleClockState::ClockUncertain;
            }
        } else {
            // Another observation may already be on its way to a committed
            // anchor.  Restoring our predecessor could erase it, so fence
            // irreversible lifecycle work until a durable recovery occurs.
            safety.state = LifecycleClockState::ClockUncertain;
            safety.revision = safety.revision.saturating_add(1);
        }
    }

    fn safety_revision(&self) -> Result<u64, LifecycleClockFailure> {
        self.safety
            .lock()
            .map(|safety| safety.revision)
            .map_err(|_| LifecycleClockFailure::Unavailable)
    }

    pub(crate) fn destructive_ingest_time(
        &self,
        scope: SegmentScope,
        durable: Option<IngestTime>,
    ) -> Result<IngestTime, LifecycleClockFailure> {
        let ingest = self.ingest_time(scope, durable)?;
        if self.authorizes_destructive_retention() {
            Ok(ingest)
        } else {
            Err(LifecycleClockFailure::ClockUncertain)
        }
    }

    #[must_use]
    pub fn status(&self) -> LifecycleClockStatus {
        self.safety.lock().map_or(
            LifecycleClockStatus {
                state: LifecycleClockState::ClockUncertain,
                safe_anchor: self.epoch,
                last_wall_clock: None,
                observed_offset_nanoseconds: None,
            },
            |safety| LifecycleClockStatus {
                state: safety.state,
                safe_anchor: safety.anchor,
                last_wall_clock: safety.last_wall_clock,
                observed_offset_nanoseconds: safety.observed_offset_nanoseconds,
            },
        )
    }

    pub(crate) fn recover_scope(
        &self,
        scope: SegmentScope,
        durable: IngestTime,
    ) -> Result<(), LifecycleClockFailure> {
        let elapsed = self.elapsed.nanoseconds()?;
        self.reconcile(durable.instant(), elapsed)?;
        let mut scopes = self
            .scopes
            .lock()
            .map_err(|_| LifecycleClockFailure::Unavailable)?;
        if !scopes.contains_key(&scope) && scopes.len() >= crate::MAX_TENANT_QUOTAS {
            return Err(LifecycleClockFailure::OutOfRange);
        }
        match scopes.get_mut(&scope) {
            Some(baseline) => {
                let current = advance(*baseline, elapsed)?;
                baseline.instant = current.max(durable.instant());
                baseline.elapsed_at_start = elapsed;
            },
            None => {
                scopes.insert(
                    scope,
                    ScopeBaseline {
                        instant: durable.instant(),
                        elapsed_at_start: 0,
                    },
                );
            },
        }
        Ok(())
    }

    pub(crate) fn ingest_time(
        &self,
        scope: SegmentScope,
        durable: Option<IngestTime>,
    ) -> Result<IngestTime, LifecycleClockFailure> {
        let elapsed = self.elapsed.nanoseconds()?;
        self.reconcile_current(elapsed)?;
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
        let advanced = advance(*baseline, elapsed)?;
        #[cfg(feature = "test-support")]
        if !self.destructive_retention {
            return Ok(IngestTime::from_unretained_observation(advanced));
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

    pub(crate) fn lease_time(&self, scope: SegmentScope) -> Result<u64, LifecycleClockFailure> {
        self.ingest_time(scope, None)?
            .instant()
            .value()
            .checked_div(1_000_000_000)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(LifecycleClockFailure::OutOfRange)
    }

    /// Returns the persisted lifecycle-clock observation used by governed
    /// expiry decisions for one already-established scope.
    pub fn governance_time_seconds(
        &self,
        scope: SegmentScope,
    ) -> Result<u64, LifecycleClockFailure> {
        self.lease_time(scope)
    }

    /// Returns process-monotonic trusted time when a retention preview has no
    /// tenant scopes from which to recover a durable lifecycle frontier.
    pub fn governance_now_seconds(&self) -> Result<u64, LifecycleClockFailure> {
        let elapsed = self.elapsed.nanoseconds()?;
        self.reconcile_current(elapsed)?;
        let safety = self
            .safety
            .lock()
            .map_err(|_| LifecycleClockFailure::Unavailable)?;
        advance_global(*safety, elapsed)?
            .value()
            .checked_div(1_000_000_000)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(LifecycleClockFailure::OutOfRange)
    }

    fn reconcile_current(&self, elapsed: u64) -> Result<(), LifecycleClockFailure> {
        let expected = self
            .safety
            .lock()
            .map_err(|_| LifecycleClockFailure::Unavailable)
            .and_then(|safety| advance_global(*safety, elapsed))?;
        self.reconcile(expected, elapsed)
    }

    fn reconcile(
        &self,
        durable_or_expected: UnixNanoseconds,
        elapsed: u64,
    ) -> Result<(), LifecycleClockFailure> {
        let mut safety = self
            .safety
            .lock()
            .map_err(|_| LifecycleClockFailure::Unavailable)?;
        let expected = advance_global(*safety, elapsed)?.max(durable_or_expected);
        safety.anchor = expected;
        safety.anchor_elapsed = elapsed;
        safety.revision = safety
            .revision
            .checked_add(1)
            .ok_or(LifecycleClockFailure::OutOfRange)?;
        let Some(source) = &self.source else {
            return Ok(());
        };
        let wall = source.read()?;
        let offset = wall
            .value()
            .checked_sub(expected.value())
            .ok_or(LifecycleClockFailure::OutOfRange)?;
        safety.last_wall_clock = Some(wall);
        safety.observed_offset_nanoseconds = Some(offset);
        safety.state = if wall.value().abs_diff(expected.value())
            > self.policy.maximum_reconciliation_offset_nanoseconds
        {
            LifecycleClockState::ClockUncertain
        } else {
            LifecycleClockState::Certain
        };
        Ok(())
    }
}

fn advance_global(
    safety: LifecycleClockSafety,
    elapsed: u64,
) -> Result<UnixNanoseconds, LifecycleClockFailure> {
    elapsed
        .checked_sub(safety.anchor_elapsed)
        .and_then(|delta| i64::try_from(delta).ok())
        .and_then(|delta| safety.anchor.value().checked_add(delta))
        .map(UnixNanoseconds::new)
        .ok_or(LifecycleClockFailure::OutOfRange)
}

fn encode_catalog_anchor(safety: LifecycleClockSafety) -> Result<Vec<u8>, LifecycleClockFailure> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(CLOCK_ANCHOR_BYTES)
        .map_err(|_| LifecycleClockFailure::OutOfRange)?;
    bytes.extend_from_slice(CLOCK_ANCHOR_MAGIC);
    bytes.push(CLOCK_ANCHOR_VERSION);
    bytes.push(match safety.state {
        LifecycleClockState::Certain => 0,
        LifecycleClockState::ClockUncertain => 1,
    });
    bytes.extend_from_slice(&safety.anchor.value().to_be_bytes());
    match safety.last_wall_clock {
        Some(wall) => {
            bytes.push(1);
            bytes.extend_from_slice(&wall.value().to_be_bytes());
        },
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&0_i64.to_be_bytes());
        },
    }
    match safety.observed_offset_nanoseconds {
        Some(offset) => {
            bytes.push(1);
            bytes.extend_from_slice(&offset.to_be_bytes());
        },
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&0_i64.to_be_bytes());
        },
    }
    Ok(bytes)
}

fn decode_catalog_anchor(
    bytes: &[u8],
) -> Result<Option<LifecycleClockSafety>, LifecycleClockFailure> {
    if !bytes.starts_with(CLOCK_ANCHOR_MAGIC) {
        return Ok(None);
    }
    if bytes.len() != CLOCK_ANCHOR_BYTES || bytes.get(8).copied() != Some(CLOCK_ANCHOR_VERSION) {
        return Err(LifecycleClockFailure::OutOfRange);
    }
    let state = match bytes.get(9).copied() {
        Some(0) => LifecycleClockState::Certain,
        Some(1) => LifecycleClockState::ClockUncertain,
        _ => return Err(LifecycleClockFailure::OutOfRange),
    };
    let anchor = UnixNanoseconds::new(read_i64(bytes, 10)?);
    let last_wall_clock = match bytes.get(18).copied() {
        Some(0) => None,
        Some(1) => Some(UnixNanoseconds::new(read_i64(bytes, 19)?)),
        _ => return Err(LifecycleClockFailure::OutOfRange),
    };
    let observed_offset_nanoseconds = match bytes.get(27).copied() {
        Some(0) => None,
        Some(1) => Some(read_i64(bytes, 28)?),
        _ => return Err(LifecycleClockFailure::OutOfRange),
    };
    Ok(Some(LifecycleClockSafety {
        anchor,
        anchor_elapsed: 0,
        state,
        last_wall_clock,
        observed_offset_nanoseconds,
        revision: 0,
    }))
}

pub(crate) fn is_catalog_anchor(bytes: &[u8]) -> bool {
    bytes.starts_with(CLOCK_ANCHOR_MAGIC)
}

fn read_i64(bytes: &[u8], start: usize) -> Result<i64, LifecycleClockFailure> {
    bytes
        .get(start..start.saturating_add(8))
        .and_then(|value| value.try_into().ok())
        .map(i64::from_be_bytes)
        .ok_or(LifecycleClockFailure::OutOfRange)
}

fn advance(
    baseline: ScopeBaseline,
    elapsed: u64,
) -> Result<UnixNanoseconds, LifecycleClockFailure> {
    elapsed
        .checked_sub(baseline.elapsed_at_start)
        .and_then(|delta| i64::try_from(delta).ok())
        .and_then(|delta| baseline.instant.value().checked_add(delta))
        .map(UnixNanoseconds::new)
        .ok_or(LifecycleClockFailure::OutOfRange)
}

impl std::fmt::Debug for RetentionTimeAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RetentionTimeAuthority { <monotonic> }")
    }
}

#[cfg(feature = "test-support")]
/// Exercises the lifecycle-clock state machine and its untrusted durable
/// anchor decoder without a storage fixture.  The public fuzz target supplies
/// arbitrary wall movement, elapsed time, and encoded-anchor bytes.
pub fn fuzz_retention_time_stateful(data: &[u8]) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    struct MutableSource(Arc<AtomicI64>);

    impl LifecycleClockSource for MutableSource {
        fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
            Ok(UnixNanoseconds::new(self.0.load(Ordering::Acquire)))
        }
    }

    let initial = data
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(i64::from_be_bytes)
        .unwrap_or(1_000);
    let wall = Arc::new(AtomicI64::new(initial));
    let Ok(policy) = LifecycleClockPolicy::new(10) else {
        return;
    };
    let Ok((clock, elapsed)) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
        MutableSource(Arc::clone(&wall)),
        policy,
    ) else {
        return;
    };
    let Ok(tenant) = positron_domain::identity::TenantId::from_bytes([0x71; 16]) else {
        return;
    };
    let Ok(shard) = positron_domain::routing::VirtualShardId::new(71) else {
        return;
    };
    let scope = crate::SegmentScope::new(tenant, positron_domain::routing::SignalKind::Logs, shard);
    let mut cursor = 8_usize;
    while let Some(operation) = data.get(cursor).copied() {
        cursor = cursor.saturating_add(1);
        match operation % 5 {
            0 => {
                if let Some(bytes) = data.get(cursor..cursor.saturating_add(8))
                    && let Ok(bytes) = <[u8; 8]>::try_from(bytes)
                {
                    wall.store(i64::from_be_bytes(bytes), Ordering::Release);
                    cursor = cursor.saturating_add(8);
                }
            },
            1 => {
                if let Some(bytes) = data.get(cursor..cursor.saturating_add(8))
                    && let Ok(bytes) = <[u8; 8]>::try_from(bytes)
                {
                    let _ = elapsed.advance(u64::from_be_bytes(bytes));
                    cursor = cursor.saturating_add(8);
                }
            },
            2 => {
                let _ = clock.ingest_time(scope, None);
            },
            3 => {
                let _ = clock.destructive_ingest_time(scope, None);
            },
            _ => {
                if let Ok(mut staged) = clock.stage_catalog_anchor() {
                    let _ = staged.ingest_time(scope, None);
                }
            },
        }
    }
    let _ = clock.catalog_anchor_record(IngestTime::from_authenticated_durable(
        clock.status().safe_anchor(),
    ));
    let _ = decode_catalog_anchor(data);
}

#[cfg(test)]
mod clock_safety_tests {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    struct MutableWallClock(Arc<Mutex<UnixNanoseconds>>);

    impl LifecycleClockSource for MutableWallClock {
        fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
            self.0
                .lock()
                .map(|instant| *instant)
                .map_err(|_| LifecycleClockFailure::Unavailable)
        }
    }

    struct FailingAfterEstablishment(AtomicU8);

    impl LifecycleClockSource for FailingAfterEstablishment {
        fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
            if self.0.fetch_add(1, Ordering::AcqRel) == 0 {
                Ok(UnixNanoseconds::new(1_000))
            } else {
                Err(LifecycleClockFailure::Unavailable)
            }
        }
    }

    #[test]
    fn a_wall_clock_step_pauses_destructive_lifecycle_work_but_not_ingest() {
        let wall = Arc::new(Mutex::new(UnixNanoseconds::new(1_000)));
        let source = MutableWallClock(Arc::clone(&wall));
        let (clock, elapsed) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
            source,
            LifecycleClockPolicy::new(10).expect("bounded policy"),
        )
        .expect("clock establishes");
        let scope = SegmentScope::new(
            positron_domain::identity::TenantId::from_bytes([1; 16]).expect("tenant"),
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::VirtualShardId::new(1).expect("shard"),
        );

        elapsed.advance(1).expect("monotonic elapsed");
        assert!(clock.ingest_time(scope, None).is_ok());
        *wall.lock().expect("wall lock") = UnixNanoseconds::new(2_000);
        assert!(clock.ingest_time(scope, None).is_ok());
        assert_eq!(clock.status().state(), LifecycleClockState::ClockUncertain);
        assert!(!clock.authorizes_destructive_retention());
    }

    #[test]
    fn restart_forward_jump_compares_wall_clock_with_the_durable_anchor() {
        let wall = Arc::new(Mutex::new(UnixNanoseconds::new(2_000)));
        let (clock, _) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
            MutableWallClock(Arc::clone(&wall)),
            LifecycleClockPolicy::new(10).expect("bounded policy"),
        )
        .expect("clock establishes");
        {
            let mut safety = clock.safety.lock().expect("safety lock");
            safety.anchor = UnixNanoseconds::new(1_000);
            safety.anchor_elapsed = 0;
        }

        clock
            .reconcile(UnixNanoseconds::new(1_000), 0)
            .expect("restart observation");

        assert_eq!(clock.status().state(), LifecycleClockState::ClockUncertain);
        assert_eq!(clock.status().safe_anchor(), UnixNanoseconds::new(1_000));
    }

    #[test]
    fn rejected_catalog_candidate_restores_its_unpublished_anchor() {
        let wall = Arc::new(Mutex::new(UnixNanoseconds::new(1_000)));
        let (clock, elapsed) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
            MutableWallClock(Arc::clone(&wall)),
            LifecycleClockPolicy::new(10).expect("bounded policy"),
        )
        .expect("clock establishes");
        let mut checkpoint = clock.stage_catalog_anchor().expect("checkpoint");
        elapsed.advance(5).expect("elapsed");
        checkpoint
            .ingest_time(
                SegmentScope::new(
                    positron_domain::identity::TenantId::from_bytes([2; 16]).expect("tenant"),
                    positron_domain::routing::SignalKind::Logs,
                    positron_domain::routing::VirtualShardId::new(2).expect("shard"),
                ),
                None,
            )
            .expect("candidate observation");
        assert_eq!(clock.status().safe_anchor(), UnixNanoseconds::new(1_005));
        drop(checkpoint);
        assert_eq!(clock.status().safe_anchor(), UnixNanoseconds::new(1_000));
    }

    #[test]
    fn rejected_candidate_never_rolls_back_a_later_observation() {
        let wall = Arc::new(Mutex::new(UnixNanoseconds::new(1_000)));
        let (clock, elapsed) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
            MutableWallClock(Arc::clone(&wall)),
            LifecycleClockPolicy::new(10).expect("bounded policy"),
        )
        .expect("clock establishes");
        let first = SegmentScope::new(
            positron_domain::identity::TenantId::from_bytes([3; 16]).expect("tenant"),
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::VirtualShardId::new(3).expect("shard"),
        );
        let second = SegmentScope::new(
            positron_domain::identity::TenantId::from_bytes([4; 16]).expect("tenant"),
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::VirtualShardId::new(4).expect("shard"),
        );
        let mut candidate = clock.stage_catalog_anchor().expect("candidate");
        elapsed.advance(5).expect("elapsed");
        candidate.ingest_time(first, None).expect("candidate time");
        elapsed.advance(5).expect("elapsed");
        clock.ingest_time(second, None).expect("later observation");

        drop(candidate);

        assert_eq!(clock.status().safe_anchor(), UnixNanoseconds::new(1_010));
        assert_eq!(clock.status().state(), LifecycleClockState::ClockUncertain);
    }

    #[test]
    fn source_failure_after_candidate_mutation_restores_the_durable_anchor() {
        let (clock, elapsed) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
            FailingAfterEstablishment(AtomicU8::new(0)),
            LifecycleClockPolicy::new(10).expect("bounded policy"),
        )
        .expect("clock establishes");
        let scope = SegmentScope::new(
            positron_domain::identity::TenantId::from_bytes([5; 16]).expect("tenant"),
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::VirtualShardId::new(5).expect("shard"),
        );
        let mut candidate = clock.stage_catalog_anchor().expect("candidate");
        elapsed.advance(5).expect("elapsed");
        assert_eq!(
            candidate.ingest_time(scope, None),
            Err(LifecycleClockFailure::Unavailable)
        );
        drop(candidate);
        assert_eq!(clock.status().safe_anchor(), UnixNanoseconds::new(1_000));
        assert_eq!(clock.status().state(), LifecycleClockState::Certain);
    }
}
