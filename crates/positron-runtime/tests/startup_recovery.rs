//! Recoverable startup dependency contract at the public runtime seam.

#[path = "process_lifecycle.rs"]
#[expect(dead_code, reason = "shared public lifecycle fixture")]
mod lifecycle;

use lifecycle::{ObservingListeners, ObservingTasks, TestRoots};
use positron_runtime::{
    ApplicationRuntime, BootstrapFailureCode, ExitOutcome, HostInputs, InitializationMode,
    InitializationPlan, InstanceBootstrap, ListenerRole, ProcessPhase, Readiness, RecoveryAttempt,
    RecoveryAttemptHost, RecoveryDecision, ServeConfiguration, ShutdownTrigger,
};
use std::cell::Cell;

struct ReleaseOwnershipOnRetry<'volume> {
    held: Cell<Option<positron_kernel::OwnedPrimaryDataVolume>>,
    attempts: Cell<u8>,
    _lifetime: std::marker::PhantomData<&'volume ()>,
}

impl RecoveryAttemptHost for ReleaseOwnershipOnRetry<'_> {
    fn after_failure(&self, attempt: RecoveryAttempt) -> RecoveryDecision {
        self.attempts.set(self.attempts.get().saturating_add(1));
        assert_eq!(attempt.number(), 1);
        assert_eq!(attempt.failure(), BootstrapFailureCode::StorageUnavailable);
        assert!(!attempt.ownership_held());
        self.held.take();
        RecoveryDecision::Retry
    }
}

#[test]
fn recoverable_ownership_outage_stays_not_ready_then_serves_after_bounded_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("recoverable-ownership")?;
    let held = roots.bootstrap_paths()?.retain_volume_for_test()?;
    let retries = ReleaseOwnershipOnRetry {
        held: Cell::new(Some(held)),
        attempts: Cell::new(0),
        _lifetime: std::marker::PhantomData,
    };
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();

    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::with_recovery(&listeners, &tasks, &retries),
    )?;

    assert_eq!(retries.attempts.get(), 1);
    assert_eq!(process.health().phase(), ProcessPhase::Serving);
    assert_eq!(process.health().readiness(), Readiness::Ready);
    assert_eq!(listeners.bound.borrow().len(), 6);
    Ok(())
}

struct StopAfterFailure {
    decision: RecoveryDecision,
    attempts: Cell<u8>,
}

impl RecoveryAttemptHost for StopAfterFailure {
    fn after_failure(&self, _attempt: RecoveryAttempt) -> RecoveryDecision {
        self.attempts.set(self.attempts.get().saturating_add(1));
        self.decision
    }
}

#[test]
fn exhausted_recovery_closes_operational_runtime_and_preserves_typed_outage()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("recovery-exhausted")?;
    let held = roots.bootstrap_paths()?.retain_volume_for_test()?;
    let recovery = StopAfterFailure {
        decision: RecoveryDecision::Exhausted,
        attempts: Cell::new(0),
    };
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();

    let outcome = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::with_recovery(&listeners, &tasks, &recovery),
    )
    .expect_err("bounded exhaustion must return the typed dependency outage");

    assert_eq!(
        outcome,
        ExitOutcome::StartupUnavailable(BootstrapFailureCode::StorageUnavailable)
    );
    assert_eq!(recovery.attempts.get(), 1);
    assert_eq!(listeners.bound.borrow().as_slice(), control_plane());
    drop(held);
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn termination_interrupts_recovery_and_releases_operational_runtime()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("recovery-termination")?;
    let held = roots.bootstrap_paths()?.retain_volume_for_test()?;
    let recovery = StopAfterFailure {
        decision: RecoveryDecision::Terminate(ShutdownTrigger::SecondSignal),
        attempts: Cell::new(0),
    };
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();

    let outcome = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::with_recovery(&listeners, &tasks, &recovery),
    )
    .expect_err("termination must interrupt startup recovery");

    assert_eq!(outcome, ExitOutcome::Forced);
    assert_eq!(listeners.bound.borrow().as_slice(), control_plane());
    drop(held);
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

struct RestoreKey<'roots> {
    roots: &'roots TestRoots,
    attempts: Cell<u8>,
    unavailable: Cell<bool>,
}

impl RecoveryAttemptHost for RestoreKey<'_> {
    fn prerequisite_status(&self) -> Result<(), BootstrapFailureCode> {
        if self.unavailable.replace(false) {
            Err(BootstrapFailureCode::KeyCustodyUnavailable)
        } else {
            Ok(())
        }
    }

    fn after_failure(&self, attempt: RecoveryAttempt) -> RecoveryDecision {
        self.attempts.set(self.attempts.get().saturating_add(1));
        assert_eq!(
            attempt.failure(),
            BootstrapFailureCode::KeyCustodyUnavailable
        );
        assert!(attempt.ownership_held());
        assert!(self.roots.acquire_volume_again().is_err());
        RecoveryDecision::Retry
    }
}

#[test]
fn safely_acquired_ownership_is_retained_during_key_outage_backoff()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("retained-recovery-ownership")?;
    let paths = roots.bootstrap_paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let recovery = RestoreKey {
        roots: &roots,
        attempts: Cell::new(0),
        unavailable: Cell::new(true),
    };
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();

    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::with_recovery(&listeners, &tasks, &recovery),
    )?;

    assert_eq!(recovery.attempts.get(), 1);
    assert_eq!(process.health().phase(), ProcessPhase::Serving);
    assert_eq!(listeners.bound.borrow().len(), 6);
    Ok(())
}

#[test]
fn permanent_ambiguity_never_enters_dependency_retry() -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("permanent-no-retry")?;
    std::fs::write(roots.data.join("foreign"), b"ambiguous")?;
    let recovery = StopAfterFailure {
        decision: RecoveryDecision::Retry,
        attempts: Cell::new(0),
    };
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::with_recovery(&listeners, &tasks, &recovery),
    )?;

    assert_eq!(process.health().phase(), ProcessPhase::Fenced);
    assert_eq!(recovery.attempts.get(), 0);
    Ok(())
}

#[test]
fn default_recovery_attempt_host_exhausts_its_published_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("default-recovery-bound")?;
    let held = roots.bootstrap_paths()?.retain_volume_for_test()?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();

    let outcome = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("default recovery must stop at its attempt bound");

    assert_eq!(
        outcome,
        ExitOutcome::StartupUnavailable(BootstrapFailureCode::StorageUnavailable)
    );
    drop(held);
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn first_signal_terminates_recovery_gracefully() -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("recovery-first-signal")?;
    let held = roots.bootstrap_paths()?.retain_volume_for_test()?;
    let recovery = StopAfterFailure {
        decision: RecoveryDecision::Terminate(ShutdownTrigger::FirstSignal),
        attempts: Cell::new(0),
    };
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();

    let outcome = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::with_recovery(&listeners, &tasks, &recovery),
    )
    .expect_err("first signal must interrupt dependency recovery");

    assert_eq!(outcome, ExitOutcome::Graceful);
    drop(held);
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

const fn control_plane() -> &'static [ListenerRole] {
    &[ListenerRole::Control, ListenerRole::Operations]
}
