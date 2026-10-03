use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::{
    Catalog, CatalogObject, CatalogProposal, CatalogSecret, DetectedCapacity, DiskObservation,
    DiskPressureThresholds, FormatEpoch, GovernorPolicy, InstanceId, InventoryCardinalityLimits,
    MountQualification, OperatorLimits, OrdinaryPoolPolicy, PrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, ResourceInventory, StorageKernelResourceAuthority,
    TenantQuota, TransactionId,
};

use support::*;

#[path = "tests/catalog_persistence.rs"]
mod catalog_persistence;
#[path = "tests/conflicts.rs"]
mod conflicts;
#[path = "tests/core.rs"]
mod core;
#[path = "tests/lease_expiry.rs"]
mod lease_expiry;
#[path = "tests/lifecycle.rs"]
mod lifecycle;
#[path = "tests/poison.rs"]
mod poison;
#[path = "tests/retention_publication.rs"]
mod retention_publication;
#[path = "tests/scheduling.rs"]
mod scheduling;
#[path = "tests/support.rs"]
mod support;
