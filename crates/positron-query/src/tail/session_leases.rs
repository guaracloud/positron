use positron_kernel::{
    ActiveSegmentLedger, SnapshotLeaseGrant, SnapshotLeaseId, SnapshotLeaseReplacement,
};

use super::super::cursor::{TailCursorState, TailSourceBinding};
use super::super::lease::TailLeaseOwner;
use super::{QueryFailure, QueryFailureCode, TailSession};

struct SourceLeaseReplacement<'kernel, 'catalog, 'ledger> {
    old_identity: SnapshotLeaseId,
    authority: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    replacement: SnapshotLeaseReplacement<'ledger, 'kernel, 'catalog>,
}

pub(super) struct LeaseRotation<'kernel, 'catalog, 'ledger> {
    primary: Option<SourceLeaseReplacement<'kernel, 'catalog, 'ledger>>,
    secondary: Vec<SourceLeaseReplacement<'kernel, 'catalog, 'ledger>>,
}

impl LeaseRotation<'_, '_, '_> {
    fn empty() -> Self {
        Self {
            primary: None,
            secondary: Vec::new(),
        }
    }

    fn validate<'service, 'kernel, 'catalog, 'ledger>(
        &self,
        session: &TailSession<'service, 'kernel, 'catalog, 'ledger>,
    ) -> Result<(), QueryFailure> {
        if let Some(replacement) = &self.primary
            && session.lease_owner.identity() != replacement.old_identity
        {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        if self.secondary.iter().any(|replacement| {
            !session
                .source_lease_owners
                .contains(replacement.old_identity)
        }) {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        Ok(())
    }
}

impl<'service, 'kernel, 'catalog, 'ledger> TailSession<'service, 'kernel, 'catalog, 'ledger> {
    pub(super) fn prepare_lease_rotation(
        &self,
        state: &mut TailCursorState,
        force_refresh: bool,
    ) -> Result<LeaseRotation<'kernel, 'catalog, 'ledger>, QueryFailure> {
        let Some(existing_bindings) = state.source_bindings() else {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        };
        let mut bindings = Vec::new();
        bindings
            .try_reserve_exact(existing_bindings.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        bindings.extend_from_slice(existing_bindings);
        let mut rotation = LeaseRotation::empty();
        rotation
            .secondary
            .try_reserve_exact(self.sources.readers().len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let now = self.service.now()?;
        for reader in self.sources.readers() {
            let shard = reader.scope().shard_id();
            let position = state
                .positions()
                .iter()
                .find(|position| position.shard() == shard)
                .copied()
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
            let binding = bindings
                .iter()
                .find(|binding| binding.shard() == shard)
                .copied()
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
            if !force_refresh && position.position() <= binding.frontier() {
                continue;
            }
            let authority = reader
                .lease_authority()
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
            let lease_now = now.max(
                authority
                    .snapshot_lease_time()
                    .map_err(crate::execution_support::map_ledger_failure)?,
            );
            if lease_now >= state.expiry() {
                return Err(QueryFailure::new(QueryFailureCode::SnapshotExpired));
            }
            let replacement = authority
                .prepare_snapshot_lease_replacement(binding.lease(), lease_now, state.expiry())
                .map_err(crate::execution_support::map_ledger_failure)?;
            if replacement
                .snapshot()
                .is_none_or(|snapshot| snapshot.frontier() < position.position())
            {
                return Err(QueryFailure::new(QueryFailureCode::StoreUnavailable));
            }
            let replacement = SourceLeaseReplacement {
                old_identity: binding.lease(),
                authority,
                replacement,
            };
            let new_binding = TailSourceBinding::new(
                shard,
                replacement.replacement.identity(),
                replacement
                    .replacement
                    .snapshot()
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?
                    .frontier(),
            );
            if let Some(existing) = bindings
                .iter_mut()
                .find(|candidate| candidate.shard() == shard)
            {
                *existing = new_binding;
            }
            if reader.scope() == self.service.ledger.scope() {
                rotation.primary = Some(replacement);
            } else {
                rotation.secondary.push(replacement);
            }
        }
        state.set_source_bindings(
            state.snapshot_identity(),
            state.snapshot_generation(),
            bindings,
        )?;
        Ok(rotation)
    }

    pub(super) fn commit_lease_rotation(
        &mut self,
        rotation: LeaseRotation<'kernel, 'catalog, 'ledger>,
    ) -> Result<(), QueryFailure> {
        rotation.validate(self)?;
        let LeaseRotation {
            mut primary,
            mut secondary,
        } = rotation;
        let mut secondary_grants: Vec<Option<SnapshotLeaseGrant<'kernel>>> = Vec::new();
        secondary_grants
            .try_reserve_exact(secondary.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut committed_secondary = Vec::new();
        committed_secondary
            .try_reserve_exact(secondary.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut primary_grant = if let Some(replacement) = primary.as_mut() {
            Some(
                replacement
                    .replacement
                    .commit()
                    .map_err(crate::execution_support::map_ledger_failure)?,
            )
        } else {
            None
        };
        for index in 0..secondary.len() {
            let replacement = secondary
                .get_mut(index)
                .ok_or_else(super::super::internal)?;
            match replacement.replacement.commit() {
                Ok(grant) => {
                    secondary_grants.push(Some(grant));
                    committed_secondary.push(index);
                },
                Err(failure) => {
                    let mut rollback_failure = None;
                    for index in committed_secondary.into_iter().rev() {
                        let Some(replacement) = secondary.get_mut(index) else {
                            crate::failure::retain_internal(&mut rollback_failure);
                            continue;
                        };
                        if let Err(failure) = replacement.replacement.rollback() {
                            self.terminal_cursor_allowed = false;
                            crate::failure::retain_stronger(
                                &mut rollback_failure,
                                crate::execution_support::map_ledger_failure(failure),
                            );
                            if let Some(grant) =
                                secondary_grants.get_mut(index).and_then(Option::take)
                            {
                                let owner =
                                    TailLeaseOwner::new(replacement.authority, grant.identity());
                                match self
                                    .source_lease_owners
                                    .replace(replacement.old_identity, owner)
                                {
                                    Ok(old) => drop(old),
                                    Err(failure) => crate::failure::retain_stronger(
                                        &mut rollback_failure,
                                        failure,
                                    ),
                                }
                            } else {
                                crate::failure::retain_internal(&mut rollback_failure);
                            }
                        }
                    }
                    if let Some(replacement) = primary.as_mut()
                        && primary_grant.is_some()
                        && let Err(failure) = replacement.replacement.rollback()
                    {
                        self.terminal_cursor_allowed = false;
                        crate::failure::retain_stronger(
                            &mut rollback_failure,
                            crate::execution_support::map_ledger_failure(failure),
                        );
                        if let Some(grant) = primary_grant.take() {
                            let owner =
                                TailLeaseOwner::new(replacement.authority, grant.identity());
                            let old = std::mem::replace(&mut self.lease_owner, owner);
                            drop(old);
                        } else {
                            crate::failure::retain_internal(&mut rollback_failure);
                        }
                    }
                    let failure = crate::execution_support::map_ledger_failure(failure);
                    return Err(rollback_failure.map_or(failure.clone(), |rollback| {
                        crate::failure::stronger_failure(rollback, failure)
                    }));
                },
            }
        }
        if let (Some(replacement), Some(grant)) = (primary, primary_grant.take()) {
            let owner = TailLeaseOwner::new(replacement.authority, grant.identity());
            let old = std::mem::replace(&mut self.lease_owner, owner);
            self._lease = Some(grant);
            drop(old);
        }
        for (replacement, grant) in secondary
            .into_iter()
            .zip(secondary_grants.into_iter().flatten())
        {
            let owner = TailLeaseOwner::new(replacement.authority, grant.identity());
            let old = self
                .source_lease_owners
                .replace(replacement.old_identity, owner)?;
            drop(old);
            if let Some(index) = self
                .source_lease_grants
                .iter()
                .position(|existing| existing.identity() == replacement.old_identity)
            {
                drop(self.source_lease_grants.swap_remove(index));
            }
            drop(grant);
        }
        Ok(())
    }
}
