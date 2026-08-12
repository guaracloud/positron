use super::{
    AES_256_GCM_ALGORITHM, AES_256_GCM_TAG_BYTES, FRAME_AAD_DOMAIN, FRAME_HEADER_BYTES,
    FRAME_MAGIC, FRAME_NONCE_DOMAIN, FRAME_VERSION, FrameContext, FrameFailure, FrameFailureCode,
    FrameLimits, FrameSequence,
};

pub(super) struct ParsedFrame<'a> {
    pub(super) authenticated_header: &'a [u8],
    pub(super) sequence: FrameSequence,
    pub(super) checksum: [u8; 32],
    pub(super) ciphertext: &'a [u8],
}

pub(super) fn parse_frame(
    encoded: &[u8],
    limits: FrameLimits,
) -> Result<ParsedFrame<'_>, FrameFailure> {
    let header: &[u8; 20] = encoded
        .get(..20)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| FrameFailure::new(FrameFailureCode::MalformedFrame))?;
    let [
        magic_a,
        magic_b,
        magic_c,
        magic_d,
        version_a,
        version_b,
        algorithm_a,
        algorithm_b,
        sequence_a,
        sequence_b,
        sequence_c,
        sequence_d,
        sequence_e,
        sequence_f,
        sequence_g,
        sequence_h,
        length_a,
        length_b,
        length_c,
        length_d,
    ] = *header;
    if [magic_a, magic_b, magic_c, magic_d] != FRAME_MAGIC {
        return Err(FrameFailure::new(FrameFailureCode::MalformedFrame));
    }
    if u16::from_be_bytes([version_a, version_b]) != FRAME_VERSION {
        return Err(FrameFailure::new(FrameFailureCode::UnsupportedVersion));
    }
    if u16::from_be_bytes([algorithm_a, algorithm_b]) != AES_256_GCM_ALGORITHM {
        return Err(FrameFailure::new(FrameFailureCode::UnsupportedAlgorithm));
    }
    let sequence = FrameSequence::new(u64::from_be_bytes([
        sequence_a, sequence_b, sequence_c, sequence_d, sequence_e, sequence_f, sequence_g,
        sequence_h,
    ]));
    let declared_ciphertext_bytes = u32::from_be_bytes([length_a, length_b, length_c, length_d]);
    if declared_ciphertext_bytes < AES_256_GCM_TAG_BYTES {
        return Err(FrameFailure::new(FrameFailureCode::MalformedFrame));
    }
    let declared_encoded_bytes = FRAME_HEADER_BYTES
        .checked_add(declared_ciphertext_bytes)
        .ok_or_else(|| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
    if declared_encoded_bytes > limits.max_encoded_bytes {
        return Err(FrameFailure::new(FrameFailureCode::LimitExceeded));
    }
    let checksum: [u8; 32] = encoded
        .get(20..52)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| FrameFailure::new(FrameFailureCode::MalformedFrame))?;
    let ciphertext = encoded
        .get(52..)
        .ok_or_else(|| FrameFailure::new(FrameFailureCode::MalformedFrame))?;
    let actual_ciphertext_bytes = u32::try_from(ciphertext.len())
        .map_err(|_| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
    if actual_ciphertext_bytes != declared_ciphertext_bytes {
        return Err(FrameFailure::new(FrameFailureCode::MalformedFrame));
    }
    Ok(ParsedFrame {
        authenticated_header: header,
        sequence,
        checksum,
        ciphertext,
    })
}

pub(super) fn encode_authenticated_header(
    sequence: FrameSequence,
    ciphertext_bytes: u32,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(20);
    header.extend_from_slice(&FRAME_MAGIC);
    header.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    header.extend_from_slice(&AES_256_GCM_ALGORITHM.to_be_bytes());
    header.extend_from_slice(&sequence.0.to_be_bytes());
    header.extend_from_slice(&ciphertext_bytes.to_be_bytes());
    header
}

pub(super) fn encode_associated_data(header: &[u8], context: FrameContext) -> Vec<u8> {
    let mut associated_data = Vec::with_capacity(93);
    associated_data.extend_from_slice(header);
    associated_data.extend_from_slice(FRAME_AAD_DOMAIN);
    context.object.encode(context.purpose, &mut associated_data);
    associated_data
}

pub(super) const fn nonce_for(sequence: FrameSequence) -> [u8; 12] {
    let [a, b, c, d, e, f, g, h] = sequence.0.to_be_bytes();
    let [i, j, k, l] = FRAME_NONCE_DOMAIN;
    [i, j, k, l, a, b, c, d, e, f, g, h]
}
