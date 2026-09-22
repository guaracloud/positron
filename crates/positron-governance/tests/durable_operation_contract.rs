use positron_domain::identity::PrincipalId;
use positron_governance::{
    AdministrativeIdempotencyKey, DurableOperationKind, DurableOperationRequest, OperationId,
};

#[test]
fn operation_identity_is_stable_for_an_exact_administrative_request()
-> Result<(), Box<dyn std::error::Error>> {
    let request = DurableOperationRequest::catalog_format_migration(
        PrincipalId::from_bytes([0x11; 16])?,
        AdministrativeIdempotencyKey::new([0x22; 16])?,
        [0x33; 16],
        1,
        17,
    )?;
    assert_eq!(request.kind(), DurableOperationKind::CatalogFormatMigration);
    assert_eq!(request.operation_id(), OperationId::from_request(&request));
    Ok(())
}
