use std::collections::BTreeMap;
use std::num::NonZeroU64;

use super::format::SegmentState;
use super::{
    CommittedLedgerReader, LedgerFailure, LedgerFailureCode, RetentionImpactPreview,
    RetentionImpactTimeRange, RetentionReclamationEstimate, SegmentRetention,
};

impl CommittedLedgerReader<'_, '_, '_> {
    /// Inspects the canonical committed blocks for one scope without publishing a policy or
    /// mutating a segment. The result is bound to the Catalog generation it examined.
    pub fn inspect_retention_impact_at(
        &self,
        proposed_retention_seconds: NonZeroU64,
        evaluated_at: positron_domain::time::UnixNanoseconds,
    ) -> Result<RetentionImpactPreview, LedgerFailure> {
        self.catalog.refresh_state()?;
        let catalog = self.catalog.pin()?;
        let policy = catalog.retention_policy(self.scope.signal)?;
        if proposed_retention_seconds >= policy.retention_seconds() {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let duration = proposed_retention_seconds
            .get()
            .checked_mul(1_000_000_000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let cutoff = evaluated_at
            .value()
            .checked_sub(duration)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let metadata = self
            .storage
            .catalog_segments_observed(&catalog, self.scope)?;
        let reconstruction = super::reconstruction::reconstruct(
            &self.storage,
            &metadata,
            &self.protection,
            self.catalog.instance(),
            super::recovery::RecoveryMode::Observe,
        )?;
        let states = metadata
            .into_iter()
            .map(|segment| (segment.id, segment.state))
            .collect::<BTreeMap<_, _>>();
        let mut affected = 0_u64;
        let mut reclaimable = 0_u64;
        let mut deferred = 0_u64;
        let mut mixed_sealed = 0_u64;
        let mut range: Option<RetentionImpactTimeRange> = None;
        let mut affected_sealed = Vec::new();
        let mut latest_by_segment = BTreeMap::new();
        for block in &reconstruction.blocks {
            let instant = match block.block_retention {
                SegmentRetention::Complete(value) => value.instant(),
                SegmentRetention::Empty | SegmentRetention::Unavailable => {
                    return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
                },
            };
            latest_by_segment
                .entry(block.segment)
                .and_modify(|latest: &mut positron_domain::time::UnixNanoseconds| {
                    *latest = (*latest).max(instant)
                })
                .or_insert(instant);
        }
        for block in &reconstruction.blocks {
            let instant = match block.block_retention {
                SegmentRetention::Complete(value) => value.instant(),
                SegmentRetention::Empty | SegmentRetention::Unavailable => {
                    return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
                },
            };
            let segment_state = states
                .get(&block.segment)
                .copied()
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
            let whole_segment_eligible = match segment_state {
                SegmentState::Sealed => latest_by_segment
                    .get(&block.segment)
                    .is_some_and(|latest| latest.value() <= cutoff),
                SegmentState::Active => false,
                SegmentState::Retired => {
                    return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
                },
            };
            if instant.value() > cutoff {
                continue;
            }
            let bytes = u64::try_from(block.payload.len())
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            affected = affected
                .checked_add(bytes)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            range = Some(match range {
                Some(previous) => RetentionImpactTimeRange {
                    earliest: previous.earliest.min(instant),
                    latest: previous.latest.max(instant),
                },
                None => RetentionImpactTimeRange {
                    earliest: instant,
                    latest: instant,
                },
            });
            match segment_state {
                SegmentState::Sealed => {
                    if whole_segment_eligible {
                        reclaimable = reclaimable
                            .checked_add(bytes)
                            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
                        if !affected_sealed.contains(&block.segment) {
                            affected_sealed.push(block.segment);
                        }
                    } else {
                        mixed_sealed = mixed_sealed
                            .checked_add(bytes)
                            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
                    }
                },
                SegmentState::Active => {
                    deferred = deferred
                        .checked_add(bytes)
                        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?
                },
                SegmentState::Retired => {
                    return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
                },
            }
        }
        let now_seconds = evaluated_at
            .value()
            .checked_div(1_000_000_000)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let earliest_reclamation = if reclaimable == 0 {
            RetentionReclamationEstimate::None
        } else if affected_sealed.iter().try_fold(false, |blocked, segment| {
            super::SnapshotProtection::is_protected(&self.authority.snapshot_protection(), *segment)
                .map(|protected| blocked || protected)
        })? {
            RetentionReclamationEstimate::BlockedByInProcessSnapshot
        } else if let Some(expiry) = affected_sealed.iter().try_fold(None, |latest, segment| {
            super::snapshot_lease::reclamation_lease_expiry(
                &catalog,
                self.scope,
                *segment,
                now_seconds,
            )
            .map(|expiry| {
                expiry.map(|value| latest.map_or(value, |previous: u64| previous.max(value)))
            })
        })? {
            let nanos = expiry
                .checked_mul(1_000_000_000)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            RetentionReclamationEstimate::BlockedByDurableLease(
                positron_domain::time::UnixNanoseconds::new(nanos),
            )
        } else {
            RetentionReclamationEstimate::At(evaluated_at)
        };
        Ok(RetentionImpactPreview {
            scope: self.scope,
            catalog_identity: catalog.identity(),
            catalog_generation: catalog.number(),
            evaluated_at,
            affected_time_range: range,
            approximate_affected_bytes: affected,
            approximate_immediately_reclaimable_bytes: reclaimable,
            deferred_active_segment_bytes: deferred,
            deferred_mixed_sealed_segment_bytes: mixed_sealed,
            earliest_reclamation,
        })
    }
}
