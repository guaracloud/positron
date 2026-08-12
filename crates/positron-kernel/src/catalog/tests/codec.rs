use std::collections::BTreeMap;
use std::sync::Arc;

use super::super::codec::{
    CommitRecord, decode_audit, decode_commit, encode_commit, generation_identity,
    object_set_digest, prepare_audit, snapshot_from_record, transaction_digest,
};
use super::super::types::{
    AuditFrontier, CatalogFailureCode, CatalogGenerationId, CatalogObjectId, FormatEpoch,
    InstanceId, TransactionId,
};

fn transaction(last: u8) -> TransactionId {
    let mut bytes = [0_u8; 16];
    bytes[15] = last;
    TransactionId(bytes)
}

fn instance(last: u8) -> InstanceId {
    let mut bytes = [0_u8; 16];
    bytes[15] = last;
    InstanceId(bytes)
}

fn object(last: u8) -> CatalogObjectId {
    let mut bytes = [0_u8; 32];
    bytes[31] = last;
    CatalogObjectId(bytes)
}

fn commit(objects: Vec<CatalogObjectId>) -> CommitRecord {
    let format_epoch = FormatEpoch(3);
    CommitRecord {
        generation: CatalogGenerationId::ORIGIN,
        number: 1,
        predecessor: CatalogGenerationId::ORIGIN,
        instance: instance(1),
        format_epoch,
        transaction: transaction(2),
        transaction_digest: transaction_digest(format_epoch, &objects, None)
            .expect("test transaction digest"),
        object_set_digest: object_set_digest(&objects).expect("test object-set digest"),
        audit_frontier: AuditFrontier::ORIGIN,
        objects,
    }
}

fn decode_rehashed(encoded: &[u8]) -> Result<CommitRecord, super::super::CatalogFailure> {
    decode_commit(generation_identity(encoded)?, encoded)
}

#[test]
fn commit_codec_round_trips_and_builds_the_pinned_snapshot() {
    let objects = vec![object(1), object(2)];
    let record = commit(objects.clone());
    let encoded = encode_commit(&record);
    let generation = generation_identity(&encoded).expect("test generation digest");
    let decoded = decode_commit(generation, &encoded).expect("valid commit must decode");

    assert_eq!(decoded.generation, generation);
    assert_eq!(decoded.number, 1);
    assert_eq!(decoded.predecessor, CatalogGenerationId::ORIGIN);
    assert_eq!(decoded.instance, instance(1));
    assert_eq!(decoded.format_epoch, FormatEpoch(3));
    assert_eq!(decoded.transaction, transaction(2));
    assert_eq!(decoded.objects, objects);

    let plaintext: Arc<[u8]> = Arc::from(b"catalog object".as_slice());
    let snapshot = snapshot_from_record(
        &decoded,
        BTreeMap::from([(object(1), Arc::clone(&plaintext))]),
    );
    assert_eq!(snapshot.identity(), generation);
    assert_eq!(snapshot.number(), 1);
    assert_eq!(snapshot.format_epoch(), Some(FormatEpoch(3)));
    assert_eq!(
        snapshot.object(object(1)).expect("lookup succeeds"),
        Some(&*plaintext)
    );
    assert_eq!(snapshot.object(object(9)).expect("lookup succeeds"), None);
}

#[test]
fn commit_decoder_rejects_every_truncation_and_structural_corruption() {
    let record = commit(vec![object(1), object(2)]);
    let encoded = encode_commit(&record);

    for length in 0..encoded.len() {
        let failure = decode_rehashed(&encoded[..length])
            .err()
            .expect("truncation must fail");
        assert!(matches!(
            failure.code(),
            CatalogFailureCode::IntegrityCorruption | CatalogFailureCode::LimitExceeded
        ));
    }

    let wrong_generation = decode_commit(CatalogGenerationId::ORIGIN, &encoded)
        .err()
        .expect("commit identity mismatch must fail");
    assert_eq!(
        wrong_generation.code(),
        CatalogFailureCode::IntegrityCorruption
    );

    for range in [0..1, 8..10, 10..18, 50..66, 66..70, 70..86] {
        let mut corrupt = encoded.clone();
        corrupt[range].fill(0);
        assert!(decode_rehashed(&corrupt).is_err());
    }

    let mut zero_count = encoded.clone();
    zero_count[190..194].fill(0);
    assert_eq!(
        decode_rehashed(&zero_count)
            .err()
            .expect("empty object set must fail")
            .code(),
        CatalogFailureCode::LimitExceeded
    );

    let mut excessive_count = encoded.clone();
    excessive_count[190..194].copy_from_slice(&1_025_u32.to_be_bytes());
    assert_eq!(
        decode_rehashed(&excessive_count)
            .err()
            .expect("excessive object count must fail")
            .code(),
        CatalogFailureCode::LimitExceeded
    );

    let mut unsorted = encoded.clone();
    unsorted[194..226].copy_from_slice(&object(2).0);
    unsorted[226..258].copy_from_slice(&object(1).0);
    assert_eq!(
        decode_rehashed(&unsorted)
            .err()
            .expect("unsorted identities must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );

    let mut wrong_object_digest = encoded.clone();
    wrong_object_digest[118] ^= 1;
    assert_eq!(
        decode_rehashed(&wrong_object_digest)
            .err()
            .expect("object-set digest mismatch must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        decode_rehashed(&trailing)
            .err()
            .expect("trailing bytes must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );
}

#[test]
fn audit_codec_round_trips_and_rejects_bounded_corruption() {
    let predecessor = AuditFrontier {
        position: 6,
        hash: [0x61; 32],
    };
    let (record, encoded) =
        prepare_audit(predecessor, transaction(7), b"redacted intent").expect("valid audit");
    let decoded = decode_audit(&encoded).expect("valid audit must decode");
    assert_eq!(decoded, record);
    assert_eq!(decoded.position(), 7);
    assert_eq!(decoded.predecessor_hash(), [0x61; 32]);
    assert_eq!(decoded.transaction(), transaction(7));
    assert_eq!(decoded.intent(), b"redacted intent");

    for length in 0..encoded.len() {
        assert!(decode_audit(&encoded[..length]).is_err());
    }

    for range in [0..1, 8..10, 10..18, 50..66] {
        let mut corrupt = encoded.clone();
        corrupt[range].fill(0);
        assert!(decode_audit(&corrupt).is_err());
    }

    for length in [0_u32, 65_537] {
        let mut corrupt = encoded.clone();
        corrupt[66..70].copy_from_slice(&length.to_be_bytes());
        assert_eq!(
            decode_audit(&corrupt)
                .expect_err("invalid intent length must fail")
                .code(),
            CatalogFailureCode::LimitExceeded
        );
    }

    let mut wrong_hash = encoded.clone();
    let last = wrong_hash.len() - 1;
    wrong_hash[last] ^= 1;
    assert_eq!(
        decode_audit(&wrong_hash)
            .expect_err("audit hash mismatch must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        decode_audit(&trailing)
            .expect_err("trailing bytes must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );
}

#[test]
fn audit_preparation_enforces_bounds_and_monotonic_position() {
    for intent in [Vec::new(), vec![0_u8; 65_537]] {
        assert_eq!(
            prepare_audit(AuditFrontier::ORIGIN, transaction(1), &intent)
                .expect_err("invalid audit intent must fail")
                .code(),
            CatalogFailureCode::LimitExceeded
        );
    }
    assert_eq!(
        prepare_audit(
            AuditFrontier {
                position: u64::MAX,
                hash: [0; 32],
            },
            transaction(1),
            b"intent",
        )
        .expect_err("audit position overflow must fail")
        .code(),
        CatalogFailureCode::LimitExceeded
    );
}
