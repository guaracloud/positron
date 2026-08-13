use std::sync::Mutex;

use super::{MAX_TENANT_QUOTAS, StorageKernelResourceAuthority};

pub(crate) struct ActiveSegmentLedgerLease<'authority> {
    scopes: &'authority Mutex<[Option<[u8; 22]>; MAX_TENANT_QUOTAS]>,
    key: [u8; 22],
}

pub(crate) enum ActiveSegmentLeaseFailure {
    Duplicate,
    Capacity,
    Unavailable,
}

impl StorageKernelResourceAuthority {
    pub(crate) fn acquire_active_segment_ledger(
        &self,
        key: [u8; 22],
    ) -> Result<ActiveSegmentLedgerLease<'_>, ActiveSegmentLeaseFailure> {
        let mut scopes = self
            .active_segment_scopes
            .lock()
            .map_err(|_| ActiveSegmentLeaseFailure::Unavailable)?;
        if scopes.contains(&Some(key)) {
            return Err(ActiveSegmentLeaseFailure::Duplicate);
        }
        let slot = scopes
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(ActiveSegmentLeaseFailure::Capacity)?;
        *slot = Some(key);
        Ok(ActiveSegmentLedgerLease {
            scopes: &self.active_segment_scopes,
            key,
        })
    }
}

impl Drop for ActiveSegmentLedgerLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut scopes) = self.scopes.lock()
            && let Some(slot) = scopes.iter_mut().find(|slot| **slot == Some(self.key))
        {
            *slot = None;
        }
    }
}
