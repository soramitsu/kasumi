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
        source: Option<&mut crate::PreparedRegisteredSource>,
    ) -> Result<()> {
        let _access = AccessGuard(self);
        validate_batch(&[operations])?;
        reject_unpaired_identity_ops(operations)?;
        self.check_access()?;
        let _mutation = self.mutations.lock();
        if let Some(source) = source.as_deref() {
            source.require_prepared_store(self)?;
        }
        let state = self.state.read();
        self.require_access(&state)?;
        let catalog = self.catalog.read();
        let tx = self.node.db.begin_write()?;
        if let Some(source) = source.as_deref() {
            source.require_prepared_store(self)?;
        }
        write_domain(&tx, self, &state, &catalog, operations)?;
        self.require_access(&state)?;
        // Keep the native transaction's actual writer token through capture,
        // proving the exact committed root independently of facade lifecycles.
        let _committed_writer = if source.is_some() {
            Some(
                tx.commit_holding_writer()
                    .context("durable encrypted batch commit failed; outcome may be unknown")?,
            )
        } else {
            tx.commit()
                .context("durable encrypted batch commit failed; outcome may be unknown")?;
            None
        };
        if let Some(source) = source {
            source.capture_published_store(self)?;
        }
        // Expiry during fsync is an unknown-outcome write, never a false rollback claim.
        self.require_access(&state).context(
            "batch committed but key access was lost before acknowledgment; outcome unknown",
        )
    }
}
