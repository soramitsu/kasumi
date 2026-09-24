//! Closed snapshot chunks publish in the same encrypted transaction as permanent
//! custody tables, the projection and the exact applied cursor.
use crate::control::META;
use crate::custody_machine::CLOSED_SNAPSHOT;
use anyhow::{Context, Result, ensure};
use kasumi_store::{CustodyStore, EncryptedSpool, EncryptedTable, SnapshotImage, WriteOp};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
const CHUNK: usize = 64 << 10;
const MANIFEST: &[u8] = b"closed_snapshot_manifest";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    bytes: u64,
    chunks: u64,
    sha256: String,
}
fn decode_manifest(bytes: &[u8]) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_slice(bytes)?;
    ensure!(
        serde_json::to_vec(&manifest)? == bytes,
        "noncanonical closed snapshot manifest"
    );
    ensure!(
        manifest.version == 1
            && manifest.bytes > 0
            && manifest.chunks == manifest.bytes.div_ceil(CHUNK as u64),
        "invalid closed snapshot manifest"
    );
    kasumi_types::validate_sha256(&manifest.sha256)?;
    Ok(manifest)
}
pub(crate) fn check_format(custody: &CustodyStore) -> Result<()> {
    let view = custody.store().read_view()?;
    if let Some(bytes) = view.get(META, MANIFEST, 4096)? {
        decode_manifest(&bytes)?;
    } else {
        view.visit(CLOSED_SNAPSHOT, 1, |_, _| {
            anyhow::bail!("unsupported closed snapshot storage format")
        })
        .context("unsupported closed snapshot storage without a chunk manifest")?;
    }
    Ok(())
}
pub(crate) fn stage(image: &SnapshotImage, limit: u64) -> Result<(EncryptedTable, WriteOp)> {
    ensure!(
        image.len() <= limit,
        "closed snapshot exceeds configured disk budget"
    );
    let table = EncryptedTable::new(
        image.disk(),
        image
            .len()
            .checked_mul(4)
            .and_then(|n| n.checked_add(64 << 20))
            .context("closed snapshot staging overflow")?,
    )?;
    let manifest = Manifest {
        version: 1,
        bytes: image.len(),
        chunks: image.len().div_ceil(CHUNK as u64),
        sha256: image.sha256().into(),
    };
    let mut reader = image.reader();
    let mut remaining = image.len();
    let mut buffer = vec![0u8; CHUNK];
    for index in 0..manifest.chunks {
        let size = remaining.min(CHUNK as u64) as usize;
        reader.read_exact(&mut buffer[..size])?;
        table.insert(&index.to_be_bytes(), &buffer[..size])?;
        remaining -= size as u64;
    }
    ensure!(remaining == 0, "closed snapshot chunks incomplete");
    Ok((
        table,
        WriteOp::put(META, MANIFEST, serde_json::to_vec(&manifest)?),
    ))
}
pub(crate) fn load_image(custody: &CustodyStore, limit: u64) -> Result<Option<SnapshotImage>> {
    let store = custody.store();
    let view = store.read_view()?;
    let Some(bytes) = view.get(META, MANIFEST, 4096)? else {
        check_format(custody)?;
        return Ok(None);
    };
    let manifest = decode_manifest(&bytes)?;
    ensure!(
        manifest.bytes <= limit,
        "closed snapshot exceeds byte limit"
    );
    let mut spool = EncryptedSpool::new(store.scratch_disk(), limit)?;
    for index in 0..manifest.chunks {
        let bytes = view
            .get(CLOSED_SNAPSHOT, &index.to_be_bytes(), CHUNK)?
            .context("closed snapshot chunk missing")?;
        let expected = (manifest.bytes - spool.len()).min(CHUNK as u64) as usize;
        ensure!(
            bytes.len() == expected,
            "closed snapshot chunk size differs"
        );
        spool.write_all(&bytes)?;
    }
    let mut count = 0u64;
    view.visit(CLOSED_SNAPSHOT, CHUNK, |key, _| {
        let index = u64::from_be_bytes(
            key.try_into()
                .context("invalid closed snapshot chunk key")?,
        );
        ensure!(index < manifest.chunks, "unowned closed snapshot chunk");
        count = count
            .checked_add(1)
            .context("closed snapshot count overflow")?;
        Ok(())
    })?;
    ensure!(
        count == manifest.chunks,
        "closed snapshot chunk count differs"
    );
    let image = SnapshotImage::freeze(spool)?;
    ensure!(
        image.len() == manifest.bytes && image.sha256() == manifest.sha256,
        "closed snapshot digest differs"
    );
    // The caller's publication lock prevents a second generation from changing
    // coverage between this pinned image and its independently keyed metadata.
    let coverage = crate::storage::load_snapshot_coverage(store)?
        .context("closed snapshot coverage absent")?;
    ensure!(
        coverage.snapshot_sha256 == manifest.sha256,
        "closed snapshot manifest coverage differs"
    );
    Ok(Some(image))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::tests::fixture;
    use kasumi_store::test_utils::FaultBackend;

    #[tokio::test]
    async fn closed_manifest_requires_exact_writer_json_and_valid_metadata() -> Result<()> {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
        let scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let (domains, _, _, _) = fixture(FaultBackend::new(), true, scratch).await?;
        let store = domains.custody().store();
        let manifest = Manifest {
            version: 1,
            bytes: 73,
            chunks: 1,
            sha256: "a".repeat(64),
        };
        let canonical = serde_json::to_vec(&manifest)?;
        store.write_batch(&[WriteOp::put(META, MANIFEST, canonical.clone())])?;
        check_format(domains.custody())?;
        let mut whitespace = vec![b' '];
        whitespace.extend_from_slice(&canonical);
        let mut unknown = canonical.clone();
        assert_eq!(unknown.pop(), Some(b'}'));
        unknown.extend_from_slice(b",\"legacy\":true}");
        let reordered = format!(
            "{{\"sha256\":\"{}\",\"chunks\":1,\"bytes\":73,\"version\":1}}",
            manifest.sha256
        )
        .into_bytes();
        for bytes in [whitespace, unknown, reordered] {
            store.write_batch(&[WriteOp::put(META, MANIFEST, bytes)])?;
            assert!(check_format(domains.custody()).is_err());
            assert!(load_image(domains.custody(), 1024).is_err());
        }
        let mut invalid = manifest;
        invalid.sha256 = "AA".repeat(32);
        store.write_batch(&[WriteOp::put(META, MANIFEST, serde_json::to_vec(&invalid)?)])?;
        assert!(check_format(domains.custody()).is_err());
        invalid.sha256 = "a".repeat(64);
        invalid.chunks = 2;
        store.write_batch(&[WriteOp::put(META, MANIFEST, serde_json::to_vec(&invalid)?)])?;
        assert!(check_format(domains.custody()).is_err());
        Ok(())
    }
}
