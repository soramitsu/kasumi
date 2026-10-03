//! Producer fingerprints supplement the full selected Raft proof. In particular,
//! a CoveredReplay proof may describe newer custody than the actual producer;
//! callers must not substitute that custody fingerprint for the rebuilt root.
use super::{Boundary, CodecError, Hash};
use kasumi_raft::{ApplicationBoundaryRef, SelectedAppliedRef};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fingerprint {
    pub(crate) kind: Boundary,
    pub(crate) sha256: Hash,
}

pub(crate) fn raw_digest(value: &str) -> Result<Hash, CodecError> {
    if value.len() != 64 {
        return Err(CodecError::Digest);
    }
    fn digit(value: u8) -> Result<u8, CodecError> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(CodecError::Digest),
        }
    }
    let mut out = [0; 32];
    for (out, pair) in out.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *out = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(out)
}
struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn digest(value: &impl Serialize) -> Result<Hash, CodecError> {
    let mut writer = HashWriter(Sha256::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| CodecError::Format)?;
    Ok(writer.0.finalize().into())
}
fn entry(
    log_id: &impl Serialize,
    previous: &impl Serialize,
    membership: &impl Serialize,
    command_sha256: &str,
) -> Result<Fingerprint, CodecError> {
    raw_digest(command_sha256)?;
    Ok(Fingerprint {
        kind: Boundary::Entry,
        sha256: digest(&(
            "kasumi.primary.entry.v1",
            log_id,
            previous,
            membership,
            command_sha256,
        ))?,
    })
}
fn checkpoint(
    backend_sha256: &str,
    last_log_id: &impl Serialize,
    last_membership: &impl Serialize,
) -> Result<Fingerprint, CodecError> {
    raw_digest(backend_sha256)?;
    Ok(Fingerprint {
        kind: Boundary::Snapshot,
        // Exactly SnapshotRestoreContext::checkpoint_sha256, without a body
        // Vec or hex String. Snapshot ID/envelope digest are intentionally not
        // part of that existing checkpoint contract; full Raft proof checks them.
        sha256: digest(&(
            "kasumi.backend-checkpoint.v1",
            backend_sha256,
            last_log_id,
            last_membership,
        ))?,
    })
}
pub(crate) fn producer(boundary: ApplicationBoundaryRef<'_>) -> Result<Fingerprint, CodecError> {
    match boundary {
        ApplicationBoundaryRef::Bootstrap(image) => Ok(Fingerprint {
            kind: Boundary::Bootstrap,
            sha256: raw_digest(image.sha256())?,
        }),
        ApplicationBoundaryRef::Entry(position) => entry(
            &position.log_id,
            &position.previous,
            &position.membership,
            &position.command_sha256,
        ),
        ApplicationBoundaryRef::Snapshot(context) => checkpoint(
            &context.backend_sha256,
            &context.meta.last_log_id,
            &context.meta.last_membership,
        ),
    }
}
/// Compare only at an exact producer/custody boundary. Reconstruction retains
/// its actual producer token separately from potentially newer covered custody.
pub(crate) fn selected(
    applied: Option<SelectedAppliedRef<'_>>,
    bootstrap_sha256: &str,
) -> Result<Fingerprint, CodecError> {
    match applied {
        None => Ok(Fingerprint {
            kind: Boundary::Bootstrap,
            sha256: raw_digest(bootstrap_sha256)?,
        }),
        Some(SelectedAppliedRef::Entry {
            log_id,
            previous,
            membership,
            command_sha256,
        }) => entry(&log_id, &previous, membership, command_sha256),
        Some(SelectedAppliedRef::Snapshot {
            meta,
            backend_sha256,
            ..
        }) => checkpoint(backend_sha256, &meta.last_log_id, &meta.last_membership),
    }
}
