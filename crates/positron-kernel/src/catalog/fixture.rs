use super::{
    Catalog, CatalogFailure, CatalogFailureCode, CatalogObject, CatalogProposal, FormatEpoch,
    GovernanceFixtureObject, TransactionId,
};

/// Destination for the opaque governance fixture capability.
pub trait GovernanceFixtureTarget {
    fn install_governance_fixture(
        &self,
        fixture: &GovernanceFixtureObject,
    ) -> Result<(), CatalogFailure>;

    #[doc(hidden)]
    fn replace_governance_fixture(
        &self,
        fixture: &GovernanceFixtureObject,
    ) -> Result<(), CatalogFailure> {
        self.install_governance_fixture(fixture)
    }
}

impl GovernanceFixtureTarget for Catalog<'_> {
    fn install_governance_fixture(
        &self,
        fixture: &GovernanceFixtureObject,
    ) -> Result<(), CatalogFailure> {
        let basis = self.pin()?;
        let capacity = usize::try_from(basis.number())
            .ok()
            .and_then(|number| number.checked_add(1))
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(capacity)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        for object_id in basis.object_identities() {
            let object = basis
                .object(object_id)?
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
            objects.push(CatalogObject::new(object.to_vec())?);
        }
        objects.push(CatalogObject::new(fixture.plaintext.clone())?);
        let transaction = TransactionId::new([0x41; 16])?;
        let proposal = CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)?;
        self.commit(basis.identity(), proposal, None).map(|_| ())
    }

    fn replace_governance_fixture(
        &self,
        fixture: &GovernanceFixtureObject,
    ) -> Result<(), CatalogFailure> {
        let basis = self.pin()?;
        let capacity = usize::try_from(basis.number())
            .ok()
            .and_then(|number| number.checked_add(1))
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(capacity)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        for object_id in basis.object_identities() {
            let object = basis
                .object(object_id)?
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
            if object.starts_with(b"POSGOV01")
                || object.starts_with(b"POSGOV02")
                || object.starts_with(b"POSGOV03")
            {
                continue;
            }
            objects.push(CatalogObject::new(object.to_vec())?);
        }
        objects.push(CatalogObject::new(fixture.plaintext.clone())?);
        let mut transaction_bytes = [0x42; 16];
        transaction_bytes[..8].copy_from_slice(
            &basis
                .number()
                .checked_add(1)
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?
                .to_be_bytes(),
        );
        let transaction = TransactionId::new(transaction_bytes)?;
        let proposal = CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)?;
        self.commit(basis.identity(), proposal, None).map(|_| ())
    }
}
