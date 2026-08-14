use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, VirtualShardId};
use positron_kernel::StoreBlockIdentity;

use super::super::{SchemaBudget, SchemaCatalog, SchemaCheckpointFrontier, SchemaFailure};

#[test]
fn checkpoint_frontiers_are_canonical_bounded_and_corruption_checked() {
    let tenant = TenantId::from_bytes([0x81; 16]).expect("tenant");
    let catalog =
        SchemaCatalog::new(tenant, SchemaBudget::release_1().expect("budget")).expect("catalog");
    let first = frontier(2, 2, 0x82);
    let second = frontier(1, 1, 0x83);
    let left = catalog
        .encode_checkpoint_object(&[first, second])
        .expect("checkpoint");
    let right = catalog
        .encode_checkpoint_object(&[second, first])
        .expect("checkpoint");
    assert_eq!(left, right);
    let (decoded, frontiers) = SchemaCatalog::decode_checkpoint_object(&left).expect("decode");
    assert_eq!(decoded.tenant(), tenant);
    assert_eq!(frontiers, vec![second, first]);

    assert_eq!(
        catalog.encode_checkpoint_object(&[first, first]),
        Err(SchemaFailure::InvalidValue)
    );
    let mut corrupt = left;
    corrupt.push(0);
    assert_eq!(
        SchemaCatalog::decode_checkpoint_object(&corrupt),
        Err(SchemaFailure::MalformedCatalog)
    );
}

#[test]
fn checkpoint_frontier_system_maximum_is_exact() {
    let tenant = TenantId::from_bytes([0x84; 16]).expect("tenant");
    let catalog =
        SchemaCatalog::new(tenant, SchemaBudget::release_1().expect("budget")).expect("catalog");
    let frontiers: Vec<_> = (1..=4_096).map(|shard| frontier(shard, 1, 0x85)).collect();
    let bytes = catalog
        .encode_checkpoint_object(&frontiers)
        .expect("the exact frontier maximum fits");
    let (_, decoded) = SchemaCatalog::decode_checkpoint_object(&bytes).expect("maximum decodes");
    assert_eq!(decoded.len(), 4_096);

    let mut over = frontiers;
    over.push(frontier(4_097, 1, 0x86));
    assert_eq!(
        catalog.encode_checkpoint_object(&over),
        Err(SchemaFailure::LimitExceeded)
    );
}

#[test]
fn checkpoint_rejects_invalid_frontiers_and_trailer_fields() {
    let tenant = TenantId::from_bytes([0x87; 16]).expect("tenant");
    let catalog =
        SchemaCatalog::new(tenant, SchemaBudget::release_1().expect("budget")).expect("catalog");
    let valid = frontier(1, 1, 0x88);
    assert_eq!(
        SchemaCheckpointFrontier::new(
            VirtualShardId::new(1).expect("shard"),
            CommitPosition::origin(),
            StoreBlockIdentity::new([0x88; 16]).expect("identity"),
            [0x88; 32],
        ),
        Err(SchemaFailure::InvalidValue)
    );
    assert_eq!(
        SchemaCheckpointFrontier::new(
            VirtualShardId::new(1).expect("shard"),
            CommitPosition::origin().next().expect("position"),
            StoreBlockIdentity::new([0x88; 16]).expect("identity"),
            [0; 32],
        ),
        Err(SchemaFailure::InvalidValue)
    );

    let prefix = catalog.encode_catalog_object().expect("catalog").len();
    let encoded = catalog
        .encode_checkpoint_object(&[valid])
        .expect("checkpoint");
    for malformed in [
        {
            let mut bytes = encoded.clone();
            bytes[prefix] ^= 1;
            bytes
        },
        {
            let mut bytes = encoded.clone();
            let digest = bytes.len() - 32;
            bytes[digest..].fill(0);
            bytes
        },
    ] {
        assert_eq!(
            SchemaCatalog::decode_checkpoint_object(&malformed),
            Err(SchemaFailure::MalformedCatalog)
        );
    }
}

fn frontier(shard: u32, position: u64, marker: u8) -> SchemaCheckpointFrontier {
    let mut committed = CommitPosition::origin();
    for _ in 0..position {
        committed = committed.next().expect("position");
    }
    SchemaCheckpointFrontier::new(
        VirtualShardId::new(shard).expect("shard"),
        committed,
        StoreBlockIdentity::new([marker; 16]).expect("identity"),
        [marker; 32],
    )
    .expect("frontier")
}
