//! Public capture and staged restore own admitted blocking work. Publishing a
//! generation is exclusively the responsibility of the Raft/storage coordinator.
use super::{TenantEngine, snapshot_bundle};
use crate::{
    admission::{CancelOnDrop, NodeAdmission, Reservation},
    backup_verify::VerificationDeadline,
};
use kasumi_query::QueryCancellation;
use kasumi_store::{SnapshotImage, TenantStore};
use kasumi_types::{Error, ErrorCode, Result};
use std::{
    io::{Read, Write},
    sync::Arc,
};

const WORKSPACE: u64 = 64 << 20;

/// A fully verified backend image, staged without changing live state or Raft
/// applied position. Installation still requires its enclosing Raft snapshot
/// metadata and the owning coordinator's atomic publication path.
pub struct PreparedSnapshotRestore {
    image: SnapshotImage,
    tenant: String,
    incarnation: String,
    revision: u64,
}
impl PreparedSnapshotRestore {
    pub fn image(&self) -> &SnapshotImage {
        &self.image
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn incarnation(&self) -> &str {
        &self.incarnation
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
}
struct Work {
    store: Arc<TenantStore>,
    token: QueryCancellation,
    deadline: VerificationDeadline,
    reservation: Reservation,
}
impl Work {
    fn check(&self) -> anyhow::Result<()> {
        self.deadline.check()?;
        self.token.check()?;
        self.store.check_access()
    }
}
struct CheckedIo<'a, T> {
    io: T,
    work: &'a Work,
}
impl<T: Read> Read for CheckedIo<'_, T> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.work.check().map_err(std::io::Error::other)?;
        self.io.read(bytes)
    }
}
impl<T: Write> Write for CheckedIo<'_, T> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.work.check().map_err(std::io::Error::other)?;
        self.io.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.work.check().map_err(std::io::Error::other)?;
        self.io.flush()
    }
}
fn error(error: anyhow::Error) -> Error {
    error
        .downcast_ref::<Error>()
        .cloned()
        .unwrap_or_else(|| Error::new(ErrorCode::Corruption, error.to_string()))
}
impl TenantEngine {
    /// Capture a complete backend bundle, including retained audit ciphertext.
    /// This image is not a Raft LogId/membership envelope and cannot independently
    /// overwrite a running group. Timeout/cancellation drains owned work rather
    /// than releasing storage ownership or its byte charge prematurely.
    pub async fn snapshot(
        &self,
        admission: Arc<NodeAdmission>,
        timeout_ms: u64,
    ) -> Result<SnapshotImage> {
        let deadline = VerificationDeadline::new(timeout_ms).map_err(error)?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let store =
            self.snapshot_store.get().cloned().ok_or_else(|| {
                Error::new(ErrorCode::Unavailable, "snapshot storage not installed")
            })?;
        let generation = self.generation()?;
        let logical = u64::try_from(generation.snapshot_bytes()?)
            .map_err(|_| Error::new(ErrorCode::ResourceExhausted, "snapshot size overflow"))?;
        let retention = &generation.state.audit_retention;
        let maximum = logical
            .checked_add(retention.archive_bytes)
            .and_then(|bytes| bytes.checked_add(logical.div_ceil(64 << 10).checked_mul(9)?))
            .and_then(|bytes| bytes.checked_add(retention.archive_segments.checked_mul(9)?))
            .and_then(|bytes| bytes.checked_add((64 << 10) + 128))
            .ok_or_else(|| Error::new(ErrorCode::ResourceExhausted, "snapshot size overflow"))?;
        let work = Work {
            store,
            token: token.clone(),
            deadline,
            reservation: admission.reserve(WORKSPACE, Some(token))?,
        };
        let output = deadline
            .run(tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                work.check()?;
                let image = SnapshotImage::capture(work.store.scratch_disk(), maximum, |writer| {
                    let mut checked = CheckedIo {
                        io: writer,
                        work: &work,
                    };
                    snapshot_bundle::write(&generation, &work.store, &mut checked)
                })?;
                work.check()?;
                Ok((image, work))
            }))
            .await
            .map_err(error)?
            .map_err(|e| error(e.into()))?
            .map_err(error)?;
        output.1.check().map_err(error)?;
        Ok(output.0)
    }

    /// Verify and stage a complete backend snapshot without publishing it. The
    /// logical allocation budget comes from a complete bounded framing pass,
    /// never from an unauthenticated claimed length alone. The owning Raft or
    /// stopped-installation coordinator remains responsible for installation.
    pub async fn prepare_snapshot_restore(
        self: &Arc<Self>,
        image: SnapshotImage,
        admission: Arc<NodeAdmission>,
        timeout_ms: u64,
    ) -> Result<PreparedSnapshotRestore> {
        let deadline = VerificationDeadline::new(timeout_ms).map_err(error)?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let store =
            self.snapshot_store.get().cloned().ok_or_else(|| {
                Error::new(ErrorCode::Unavailable, "snapshot storage not installed")
            })?;
        let engine = self.clone();
        let mut work = Work {
            store,
            token: token.clone(),
            deadline,
            reservation: admission.reserve(WORKSPACE, Some(token))?,
        };
        let output = deadline
            .run(tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                work.check()?;
                let logical = snapshot_bundle::inspect(&mut CheckedIo {
                    io: image.reader(),
                    work: &work,
                })?;
                let additional = logical
                    .checked_mul(3)
                    .ok_or_else(|| anyhow::anyhow!("snapshot workspace overflow"))?;
                work.reservation.reserve_additional(additional)?;
                let generation = snapshot_bundle::read(
                    &engine,
                    &mut CheckedIo {
                        io: image.reader(),
                        work: &work,
                    },
                )?;
                work.check()?;
                let prepared = PreparedSnapshotRestore {
                    image,
                    tenant: generation.state.tenant.clone(),
                    incarnation: generation.state.incarnation.clone(),
                    revision: generation.state.revision,
                };
                // The unpublished logical state drops before returning a small image
                // handle; its proportional reservation does not become a long lease.
                drop(generation);
                Ok((prepared, work))
            }))
            .await
            .map_err(error)?
            .map_err(|e| error(e.into()))?
            .map_err(error)?;
        output.1.check().map_err(error)?;
        Ok(output.0)
    }

    pub(crate) fn verify_bootstrap_dependencies_checked(
        &self,
        check: impl Fn() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let generation = self.generation()?;
        if generation.state.audit_retention.archive_head.is_some() {
            let store = self
                .snapshot_store
                .get()
                .ok_or_else(|| anyhow::anyhow!("bootstrap archive store not installed"))?;
            snapshot_bundle::verify_local_checked(&generation, store, check)?;
        }
        Ok(())
    }
    pub(crate) async fn verify_bootstrap_dependencies_owned(
        self: &Arc<Self>,
        admission: Arc<NodeAdmission>,
    ) -> anyhow::Result<()> {
        if self
            .generation()?
            .state
            .audit_retention
            .archive_head
            .is_none()
        {
            return Ok(());
        }
        let deadline = VerificationDeadline::new(600_000)?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let store = self
            .snapshot_store
            .get()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("bootstrap archive store not installed"))?;
        let engine = self.clone();
        let work = Work {
            store,
            token: token.clone(),
            deadline,
            reservation: admission.reserve(WORKSPACE, Some(token))?,
        };
        let (_, work) = deadline
            .run(tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                work.check()?;
                engine.verify_bootstrap_dependencies_checked(|| work.check())?;
                work.check()?;
                Ok(((), work))
            }))
            .await???;
        work.check()
    }
}
