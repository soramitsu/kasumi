//! A consuming point session over one exact registered tenant snapshot.
use super::*;
use crate::point_read_backing::{EncryptedPointBacking, point_buffer_layout};

/// Reuses admitted native ciphertext and plaintext backing while keeping one
/// selected root. Every loan still authenticates the record and current access.
pub struct PreparedTenantReadPoints {
    workspace: PreparedTenantReadWorkspace,
    view: TenantReadView,
}

/// Reusable admitted point backing bound to one exact installed tenant Store.
/// It owns no read root; each loan uses the supplied registered snapshot.
pub struct PreparedTenantReadWorkspace {
    backing: EncryptedPointBacking,
    store: Arc<TenantStore>,
}

impl TenantReadView {
    pub fn prepare_point_reads(
        self,
        namespace_bytes: usize,
        key_bytes: usize,
        value_bytes: usize,
    ) -> Result<PreparedTenantReadPoints> {
        match PreparedTenantReadWorkspace::new(&self, namespace_bytes, key_bytes, value_bytes) {
            Ok(workspace) => Ok(PreparedTenantReadPoints {
                workspace,
                view: self,
            }),
            Err(error) => self.finish_point_session(Err(error)),
        }
    }

    fn finish_point_session<T>(self, result: Result<T>) -> Result<T> {
        self.finish_point_retirement(result, Ok(()))
    }

    fn finish_point_retirement<T>(
        mut self,
        result: Result<T>,
        retirement: std::thread::Result<()>,
    ) -> Result<T> {
        self.transaction
            .take()
            .expect("live tenant point view")
            .finish_point_retirement(&self.store.node, result, retirement)
    }
}

impl PreparedTenantReadPoints {
    pub fn registered_reader_id(&self) -> Option<StorageOwnerId> {
        self.view.registered_reader_id()
    }

    pub fn get(
        &mut self,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&[u8]>> {
        self.workspace
            .get(&self.view, namespace, key, max_value_bytes)
    }

    /// Quote an allocation bound from this exact root; this is not authenticated
    /// body evidence. A following get must still verify all encrypted bytes.
    pub fn value_bound(
        &mut self,
        namespace: &str,
        key: &[u8],
        maximum: usize,
    ) -> Result<Option<usize>> {
        self.workspace.backing.clear_plaintext();
        let _access = AccessGuard(&self.view.store);
        self.view.store.check_access()?;
        let bound = self.workspace.backing.value_bound(
            &self.view.store,
            self.view
                .transaction
                .as_ref()
                .expect("live tenant point view"),
            namespace,
            key,
            maximum,
        )?;
        self.view.store.check_access()?;
        Ok(bound)
    }

    /// Prepare a larger actual backing before acceptance/publication. The old
    /// and new grants overlap; refusal leaves this original workspace usable.
    pub fn ensure_capacity(&mut self, namespace: usize, key: usize, value: usize) -> Result<()> {
        let previous = self.workspace.backing.bounds();
        let next = (
            namespace.max(previous.0),
            key.max(previous.1),
            value.max(previous.2),
        );
        if next != previous {
            let replacement = PreparedTenantReadWorkspace::new(&self.view, next.0, next.1, next.2)?;
            let previous = std::mem::replace(&mut self.workspace, replacement);
            if let Err(payload) = previous.retire() {
                return Err(self
                    .view
                    .transaction
                    .as_ref()
                    .expect("live tenant point view")
                    .point_retirement_failure(payload));
            }
        }
        Ok(())
    }

    /// Retire this exact planning snapshot and transfer only its admitted bytes.
    /// Preserve the original operation and actual retirement outcomes together.
    pub fn finish_with_workspace<T>(
        self,
        result: Result<T>,
    ) -> Result<(T, PreparedTenantReadWorkspace)> {
        let Self {
            mut workspace,
            view,
        } = self;
        workspace.backing.clear_plaintext();
        match result {
            Ok(value) => match view.finish_point_session(Ok(value)) {
                Ok(value) => Ok((value, workspace)),
                Err(error) => match workspace.retire() {
                    Ok(()) => Err(error),
                    Err(payload) => Err(PointRetirementFailure::new(error, payload).into()),
                },
            },
            Err(error) => {
                let retirement = workspace.retire();
                view.finish_point_retirement(Err(error), retirement)
            }
        }
    }

    pub fn close(self) -> Result<()> {
        self.finish(Ok(()))
    }

    /// Retire the real backing, then settle the original result and reader.
    /// Any failed native close remains inspectable in its registered census.
    pub fn finish<T>(self, result: Result<T>) -> Result<T> {
        let Self { workspace, view } = self;
        let retirement = workspace.retire();
        view.finish_point_retirement(result, retirement)
    }
}

impl PreparedTenantReadWorkspace {
    fn new(view: &TenantReadView, namespace: usize, key: usize, value: usize) -> Result<Self> {
        view.store.check_access()?;
        let key_id_bytes = view
            .store
            .state
            .read()
            .keys
            .keys()
            .map(String::len)
            .max()
            .unwrap_or(0);
        let layout = point_buffer_layout(
            namespace,
            key,
            value,
            view.store.tenant.len(),
            key_id_bytes,
            crate::disk_memory::size::<PreparedTenantReadPoints>()?,
        )?;
        let backing = EncryptedPointBacking::new(
            view.transaction.as_ref().expect("live tenant point view"),
            view.store.persistent_disk().memory(),
            layout,
        )?;
        view.store.check_access()?;
        Ok(Self {
            backing,
            store: view.store.clone(),
        })
    }

    /// A caught destructor panic is an unknown retirement, never clean release.
    pub fn retire(self) -> std::thread::Result<()> {
        retire_point_backing(self)
    }

    /// Require the exact installed Store, including its incarnation/key owner.
    pub fn require_store(&self, store: &Arc<TenantStore>) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.store, store),
            "prepared point backing belongs to another Store"
        );
        Ok(())
    }

    fn require_memory(&self, expected: &Arc<dyn NodeDiskMemoryAdmission>) -> Result<()> {
        ensure!(
            Arc::ptr_eq(expected, self.store.persistent_disk().memory())
                && Arc::ptr_eq(expected, self.store.scratch_disk().memory()),
            "selected view and workspace memory owners differ"
        );
        Ok(())
    }

    fn get(
        &mut self,
        view: &TenantReadView,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&[u8]>> {
        self.backing.clear_plaintext();
        let _access = AccessGuard(&view.store);
        let result = (|| {
            self.require_store(&view.store)?;
            view.store.check_access()?;
            let range = self.backing.read(
                &view.store,
                view.transaction.as_ref().expect("live tenant point view"),
                namespace,
                key,
                max_value_bytes,
            )?;
            // The read key-state guard has retired before access may seal.
            view.store.check_access()?;
            Ok(range)
        })();
        if result.is_err() {
            self.backing.clear_plaintext();
        }
        result.map(|range| range.map(|range| &self.backing.plaintext[range]))
    }
}

#[path = "prepared_source_points.rs"]
mod source_points;
pub use source_points::{PreparedTenantReadSource, PreparedTenantReadSourceLoan};

#[cfg(test)]
#[path = "prepared_points_tests.rs"]
mod tests;
