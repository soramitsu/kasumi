//! Authenticate a stored original envelope without materializing an encrypted
//! copy of the whole envelope alongside the decoded backend.
use super::*;
use kasumi_store::{PlaintextValue, TenantReadView};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor};

pub(super) fn load(
    domains: &TenantStorageSet,
    limit: u64,
) -> Result<Option<SnapshotEnvelope>, ScratchOperationFailure> {
    let store = domains.application();
    let view = store.read_view()?;
    let Some(bytes) = view.get(SNAPSHOT, b"current", MAX_SNAPSHOT_COVERAGE_BYTES)? else {
        view.close()?;
        return Ok(None);
    };
    let manifest: SnapshotManifest = decode_snapshot_record_admitted(&bytes, |_| Ok(()))?;
    drop(bytes);
    validate_snapshot_manifest(&manifest, limit)?;

    // Both passes use one pinned native root. No envelope record reaches the
    // decoder before the complete stored manifest digest has been verified.
    let mut digest = Sha256::new();
    for index in 0..manifest.chunks {
        digest.update(chunk(&view, &manifest, index)?.as_ref());
    }
    ensure!(
        hex::encode(digest.finalize()) == manifest.sha256,
        "snapshot content digest differs"
    );

    let mut chunks = Chunks {
        view: &view,
        manifest: &manifest,
        next: 0,
        current: None,
        failure: None,
    };
    let decoded = SnapshotEnvelope::decode_bounded(
        store.scratch_disk(),
        &mut chunks,
        limit,
        Some(manifest.bytes),
    );
    // Read only returns io::Error. Give the caller the actual storage error,
    // including typed access and capacity denials, when the decoder saw one.
    if let Some(original) = chunks.failure.take() {
        return Err(original.into());
    }
    drop(chunks);
    let snapshot = decoded?;
    view.close()?;
    let current = load_manifest(store, b"current", limit)?.context("recovery snapshot absent")?;
    ensure!(
        manifest == current,
        "original snapshot changed during recovery"
    );
    validate_selected_snapshot_coverage(domains, &snapshot, &current)?;
    Ok(Some(snapshot))
}

fn chunk(view: &TenantReadView, manifest: &SnapshotManifest, index: u64) -> Result<PlaintextValue> {
    // Manifest validation binds the exact chunk count to the capped length.
    let remaining = manifest.bytes - index * SNAPSHOT_CHUNK_BYTES as u64;
    let expected = remaining.min(SNAPSHOT_CHUNK_BYTES as u64) as usize;
    let bytes = view
        .get(SNAPSHOT, &chunk_key(manifest, index), expected)?
        .context("missing snapshot chunk")?;
    ensure!(bytes.len() == expected, "snapshot chunk length mismatch");
    Ok(bytes)
}

struct Chunks<'a> {
    view: &'a TenantReadView,
    manifest: &'a SnapshotManifest,
    next: u64,
    current: Option<Cursor<PlaintextValue>>,
    failure: Option<anyhow::Error>,
}

impl Read for Chunks<'_> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        if let Some(current) = &mut self.current {
            let n = current.read(dst)?;
            if n != 0 {
                return Ok(n);
            }
        }
        // Retire the current native plaintext grant before acquiring the next.
        self.current = None;
        if self.next == self.manifest.chunks {
            return Ok(0);
        }
        let bytes = chunk(self.view, self.manifest, self.next).map_err(|original| {
            self.failure = Some(original);
            io::Error::other("original snapshot chunk read failed")
        })?;
        self.next += 1;
        let cursor = self.current.insert(Cursor::new(bytes));
        cursor.read(dst)
    }
}
