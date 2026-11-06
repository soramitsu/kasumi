//! Capture a preowned source while the committed native writer is still held.
//! The source is borrowed, so the publication coordinator keeps its actual
//! prepared/captured owner through every original commit or capture failure.
use super::*;

impl TenantStore {
    /// Atomically publish this domain and capture the already prepared native
    /// root while the original native writer token is held. The caller retains the source and
    /// consumes capture() only after handling this original publication result.
    /// No source right, reader or point backing is admitted here.
    pub fn write_batch_capturing_source(
        &self,
        operations: &[WriteOp],
        source: &mut crate::PreparedRegisteredSource,
    ) -> Result<()> {
        self.write_batch_with_source(operations, Some(source))
    }

    pub(crate) fn write_batch_with_source(
        &self,
        operations: &[WriteOp],
        mut source: Option<&mut crate::PreparedRegisteredSource>,
    ) -> Result<()> {
        crate::deferred_batch::before_write(&self.node)?;
        let _access = AccessGuard(self);
        validate_batch(&[operations])?;
        reject_unpaired_identity_ops(operations)?;
        self.check_access()?;
        let _mutation = self.mutations.lock();
        let _fence = self.cached_rows.fence_operations(operations);
        if let Some(source) = source.as_deref() {
            source.require_prepared_store(self)?;
        }
        self.node.with_registered_write(
            &mut source,
            |tx, source| {
                if let Some(source) = source.as_deref() {
                    source.require_prepared_store(self)?;
                }
                // Key access is needed to encrypt, not while waiting for the
                // writer or synchronizing its publication. Holding it through
                // those waits prevents a successful live probe from renewing
                // the lease on a slow disk.
                {
                    let state = self.state.read();
                    self.require_access(&state)?;
                    let catalog = self.catalog.read();
                    write_domain(tx, self, &state, &catalog, operations)?;
                }
                self.check_access()
            },
            |source| {
                if let Some(source) = source.as_deref_mut() {
                    source.capture_published_store(self)?;
                }
                self.check_access().context(
                    "batch committed but key access was lost before acknowledgment; outcome unknown",
                )
            },
        )
    }
}
