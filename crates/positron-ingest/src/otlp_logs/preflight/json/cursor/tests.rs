use super::validated_utf8_scalar;
use crate::ReceiveFailure;

#[test]
fn utf8_scalar_validation_reads_only_one_bounded_scalar() {
    assert_eq!(validated_utf8_scalar("érest".as_bytes()), Ok((2, 2)));
    assert_eq!(validated_utf8_scalar("€rest".as_bytes()), Ok((3, 3)));
    assert_eq!(validated_utf8_scalar("😀rest".as_bytes()), Ok((4, 4)));

    for malformed in [
        &[0xc2][..],
        &[0xc0, 0xaf],
        &[0x80],
        &[0xed, 0xa0, 0x80],
        &[0xf4, 0x90, 0x80, 0x80],
    ] {
        assert_eq!(
            validated_utf8_scalar(malformed),
            Err(ReceiveFailure::MalformedPayload),
        );
    }
}
