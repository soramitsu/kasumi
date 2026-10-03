//! Canonical chunk framing. The complete DTO hash is checked across chunks by
//! the reader before any payload is lent to a decoding consumer.
use super::*;
pub(super) const HEADER: usize = 140;
pub(super) const PAYLOAD: usize = 65_536;
pub(super) const BYTES: usize = HEADER + PAYLOAD;

fn payload_len(reference: OverflowRef, ordinal: u64) -> Result<usize> {
    let count = codec(records::chunk_count(reference.encoded_bytes))?;
    ensure!(ordinal < count, "primary chunk ordinal exceeds object");
    let start = ordinal
        .checked_mul(PAYLOAD as u64)
        .context("primary chunk offset overflow")?;
    usize::try_from((reference.encoded_bytes - start).min(PAYLOAD as u64)).map_err(Into::into)
}
pub(super) fn kind_tag(kind: ResourceKind) -> Result<u8> {
    match kind {
        ResourceKind::Live => Ok(0),
        ResourceKind::Archived => Ok(1),
        ResourceKind::Definition => Ok(2),
        _ => anyhow::bail!("resource is not a chunked DTO"),
    }
}
pub(super) fn frame(
    out: &mut [u8],
    scope: [u8; 32],
    tree: [u8; 16],
    reference: OverflowRef,
    kind: ResourceKind,
    ordinal: u64,
) -> Result<()> {
    codec(reference.id.check())?;
    ensure!(tree != [0; 16], "primary tree identity absent");
    let bytes = payload_len(reference, ordinal)?;
    ensure!(
        out.len() == HEADER + bytes,
        "primary output chunk width differs"
    );
    let tag = kind_tag(kind)?;
    out[..HEADER].fill(0);
    out[..8].copy_from_slice(b"KSPCHN01");
    out[8..10].copy_from_slice(&1_u16.to_le_bytes());
    out[10] = tag;
    out[12..44].copy_from_slice(&scope);
    out[44..60].copy_from_slice(&tree);
    reference.id.write(&mut out[60..84]);
    out[84..92].copy_from_slice(&reference.encoded_bytes.to_le_bytes());
    out[92..100].copy_from_slice(&ordinal.to_le_bytes());
    out[100..104].copy_from_slice(&(bytes as u32).to_le_bytes());
    out[108..140].copy_from_slice(&reference.sha256);
    Ok(())
}
pub(super) fn parse(
    bytes: &[u8],
    scope: [u8; 32],
    tree: [u8; 16],
    reference: OverflowRef,
    kind: ResourceKind,
    ordinal: u64,
) -> Result<&[u8]> {
    codec(reference.id.check())?;
    ensure!(tree != [0; 16], "primary tree identity absent");
    let expected = payload_len(reference, ordinal)?;
    ensure!(
        bytes.len() == HEADER + expected,
        "primary chunk length differs"
    );
    ensure!(
        &bytes[..8] == b"KSPCHN01" && u16_at(bytes, 8) == 1,
        "primary chunk format differs"
    );
    ensure!(
        bytes[10] == kind_tag(kind)? && bytes[11] == 0 && bytes[104..108] == [0; 4],
        "primary chunk tag or reserved bytes differ"
    );
    ensure!(
        bytes[12..44] == scope
            && bytes[44..60] == tree
            && ObjectId::read(&bytes[60..84]) == reference.id,
        "primary chunk identity differs"
    );
    ensure!(
        u64_at(bytes, 84) == reference.encoded_bytes
            && u64_at(bytes, 92) == ordinal
            && u32::from_le_bytes(bytes[100..104].try_into().expect("fixed field")) as usize
                == expected
            && bytes[108..140] == reference.sha256,
        "primary chunk descriptor differs"
    );
    Ok(&bytes[HEADER..])
}
pub(super) fn key(id: ObjectId, ordinal: u64) -> [u8; 32] {
    let mut out = [0; 32];
    id.write(&mut out[..24]);
    out[24..].copy_from_slice(&ordinal.to_le_bytes());
    out
}
