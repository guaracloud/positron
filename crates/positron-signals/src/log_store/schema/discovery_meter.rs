use super::failure::SchemaFailure;
use super::model::MAX_DISCOVERY_NODES;
use crate::log_store::ScanObserver;

/// Accounts schema discovery in fixed 64-node quanta while preserving the
/// catalog's hard node ceiling.
pub(crate) struct DiscoveryMeter<'a> {
    used: usize,
    observer: Option<&'a dyn ScanObserver>,
}

impl DiscoveryMeter<'_> {
    pub(crate) const fn new() -> Self {
        Self {
            used: 0,
            observer: None,
        }
    }

    pub(crate) const fn observed(observer: &dyn ScanObserver) -> DiscoveryMeter<'_> {
        DiscoveryMeter {
            used: 0,
            observer: Some(observer),
        }
    }

    pub(crate) fn consume(&mut self) -> Result<bool, SchemaFailure> {
        if self.used == MAX_DISCOVERY_NODES {
            return Ok(false);
        }
        if self.used.is_multiple_of(64)
            && let Some(observer) = self.observer
        {
            observer.observe_work(1).map_err(SchemaFailure::Observed)?;
        }
        self.used += 1;
        Ok(true)
    }
}
