pub fn session(
    fixture: &super::support::Fixture,
) -> Result<positron_ingest::TenantSchemaSession, positron_ingest::SchemaSessionFailure> {
    positron_ingest::TenantSchemaRegistry::new(1)?
        .session(fixture.tenant, fixture.authority.governor())
}
