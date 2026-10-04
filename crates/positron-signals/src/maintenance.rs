use positron_kernel::{MaintenanceCoordinator, MaintenanceExecution};

use crate::{ScanCancellation, ScanObserver};

/// Runtime-owned context for one coordinator-admitted signal compaction.
///
/// The coordinator execution, cancellation boundary, and work observer travel
/// together so the Log and Trace adapters cannot receive mismatched runtime
/// controls for the same durable task.
pub struct MaintenanceCompactionExecution<'runtime, 'authority> {
    coordinator: &'runtime MaintenanceCoordinator,
    execution: &'runtime MaintenanceExecution<'authority>,
    cancellation: &'runtime dyn ScanCancellation,
    observer: &'runtime dyn ScanObserver,
}

impl<'runtime, 'authority> MaintenanceCompactionExecution<'runtime, 'authority> {
    /// Binds the runtime controls for one already-admitted durable task.
    #[must_use]
    pub fn new(
        coordinator: &'runtime MaintenanceCoordinator,
        execution: &'runtime MaintenanceExecution<'authority>,
        cancellation: &'runtime dyn ScanCancellation,
        observer: &'runtime dyn ScanObserver,
    ) -> Self {
        Self {
            coordinator,
            execution,
            cancellation,
            observer,
        }
    }

    pub(crate) const fn coordinator(&self) -> &MaintenanceCoordinator {
        self.coordinator
    }

    pub(crate) const fn task(&self) -> &MaintenanceExecution<'authority> {
        self.execution
    }

    pub(crate) const fn cancellation(&self) -> &dyn ScanCancellation {
        self.cancellation
    }

    pub(crate) const fn observer(&self) -> &dyn ScanObserver {
        self.observer
    }
}
