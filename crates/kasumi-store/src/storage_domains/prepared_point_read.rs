//! One ordinary-funded encrypted point session over an actual paired snapshot.
//! Construction owns all point buffers. Native descriptors and optional cache
//! retention retain their separate accounting; this is not standing source funding.
use super::*;
use std::io;

/// Point loans borrow this exact selected pair and its reusable admitted backing.
/// The native page/output and decrypt buffers coexist and are charged separately.
/// Dropping the session clears plaintext before closing its registered reader.
pub struct PreparedTenantPointReads {
    workspace: PreparedTenantPointWorkspace,
    view: TenantStorageReadView,
}
/// Reusable admitted encrypted point backing for one exact installed domain pair.
/// It owns no snapshot: each loan reads only the supplied registered view. Move
/// this actual backing across publication; it never opens or forks a reader.
pub struct PreparedTenantPointWorkspace {
    backing: crate::point_read_backing::EncryptedPointBacking,
    application: Arc<TenantStore>,
    custody: Arc<TenantStore>,
}

pub(super) fn point_buffer_layout(
    namespace_bytes: usize,
    key_bytes: usize,
    value_bytes: usize,
    tenant_bytes: usize,
    key_id_bytes: usize,
) -> io::Result<crate::point_read_backing::PointBufferLayout> {
    crate::point_read_backing::point_buffer_layout(
        namespace_bytes,
        key_bytes,
        value_bytes,
        tenant_bytes,
        key_id_bytes,
        crate::disk_memory::size::<PreparedTenantPointReads>()?,
    )
}

impl TenantStorageReadView {
    /// Consume this exact selected root and construct reusable ordinary-funded
    /// point backing before the first read. Bounds constrain allocated capacity,
    /// not the permitted records or identity; all inputs are checked each time.
    pub fn prepare_point_reads(
        self,
        namespace_bytes: usize,
        key_bytes: usize,
        value_bytes: usize,
    ) -> Result<PreparedTenantPointReads> {
        let workspace =
            PreparedTenantPointWorkspace::new(&self, namespace_bytes, key_bytes, value_bytes);
        match workspace {
            Ok(workspace) => Ok(PreparedTenantPointReads {
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
            .expect("live paired point view")
            .finish_point_retirement(&self.application.node, result, retirement)
    }
}

impl PreparedTenantPointWorkspace {
    /// Consume the actual backing and preserve any destructor panic for its
    /// caller's existing error owner. A panic is not proof of clean retirement.
    pub fn retire(self) -> std::thread::Result<()> {
        read_view::retire_point_backing(self)
    }

    fn new(
        view: &TenantStorageReadView,
        namespace_bytes: usize,
        key_bytes: usize,
        value_bytes: usize,
    ) -> Result<Self> {
        ensure!(
            (1..=1024).contains(&namespace_bytes) && key_bytes <= 4096 && value_bytes <= MAX_RECORD,
            "prepared encrypted point bounds exceed store limits"
        );
        ensure!(
            Arc::ptr_eq(&view.application.node, &view.custody.node),
            "prepared point domains use different native owners"
        );
        let provider = view.application.persistent_disk().memory();
        view.require_memory(provider)?;
        view.application.check_access()?;
        view.custody.check_access()?;
        // Key rotation produces UUID IDs. Bind actual retained catalog widths
        // plus that producer width; each read rechecks under the key-state guard.
        let key_id_bytes = [&view.application, &view.custody]
            .into_iter()
            .map(|store| {
                store
                    .state
                    .read()
                    .keys
                    .keys()
                    .map(String::len)
                    .max()
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0)
            .max(uuid::fmt::Hyphenated::LENGTH);
        let layout = point_buffer_layout(
            namespace_bytes,
            key_bytes,
            value_bytes,
            view.application.tenant.len().max(view.custody.tenant.len()),
            key_id_bytes,
        )?;
        let backing = crate::point_read_backing::EncryptedPointBacking::new(
            view.transaction.as_ref().expect("live paired point view"),
            provider,
            layout,
        )?;
        view.application.check_access()?;
        view.custody.check_access()?;
        Ok(Self {
            application: view.application.clone(),
            custody: view.custody.clone(),
            backing,
        })
    }

    /// Bind handoff to the original installed pair before durable publication.
    /// This is identity validation, not an access or snapshot authorization.
    pub fn require_stores(&self, stores: &TenantStorageSet) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.application, stores.application())
                && Arc::ptr_eq(&self.custody, stores.custody().store()),
            "prepared point backing belongs to another storage pair"
        );
        Ok(())
    }

    fn value_bound(
        &mut self,
        view: &TenantStorageReadView,
        application: bool,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<usize>> {
        self.backing.clear_plaintext();
        let _app_access = AccessGuard(&view.application);
        let _custody_access = AccessGuard(&view.custody);
        view.require_domains(&self.application, &self.custody)?;
        view.require_memory(self.application.persistent_disk().memory())?;
        view.application.check_access()?;
        view.custody.check_access()?;
        let store = if application {
            &view.application
        } else {
            &view.custody
        };
        let bound = self.backing.value_bound(
            store,
            view.transaction.as_ref().expect("live paired point view"),
            namespace,
            key,
            max_value_bytes,
        )?;
        view.application.check_access()?;
        view.custody.check_access()?;
        Ok(bound)
    }

    fn bounds(&self) -> (usize, usize, usize) {
        self.backing.bounds()
    }

    pub fn application_get<'a>(
        &'a mut self,
        view: &TenantStorageReadView,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&'a [u8]>> {
        self.get(view, true, namespace, key, max_value_bytes)
    }
    pub fn custody_get<'a>(
        &'a mut self,
        view: &TenantStorageReadView,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&'a [u8]>> {
        self.get(view, false, namespace, key, max_value_bytes)
    }
    fn get(
        &mut self,
        view: &TenantStorageReadView,
        application: bool,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&[u8]>> {
        self.backing.clear_plaintext();
        let _app_access = AccessGuard(&view.application);
        let _custody_access = AccessGuard(&view.custody);
        let result = (|| {
            view.require_domains(&self.application, &self.custody)?;
            view.require_memory(self.application.persistent_disk().memory())?;
            view.application.check_access()?;
            view.custody.check_access()?;
            let store = if application {
                &view.application
            } else {
                &view.custody
            };
            let range = self.backing.read(
                store,
                view.transaction.as_ref().expect("live paired point view"),
                namespace,
                key,
                max_value_bytes,
            )?;
            // Key-state read guard has retired before either domain may seal.
            view.application.check_access()?;
            view.custody.check_access()?;
            Ok(range)
        })();
        if result.is_err() {
            self.backing.clear_plaintext();
        }
        result.map(|range| range.map(|range| &self.backing.plaintext[range]))
    }
}

/// Borrow only the existing ordinary prepared directory for constructor
/// extent observations. This exposes neither a raw root nor a source loan.
pub struct PreparedTenantPointBounds<'a> {
    workspace: &'a mut PreparedTenantPointWorkspace,
    view: &'a TenantStorageReadView,
}
impl PreparedTenantPointBounds<'_> {
    pub fn application_value_bound(
        &mut self,
        namespace: &str,
        key: &[u8],
        maximum: usize,
    ) -> Result<Option<usize>> {
        self.workspace
            .value_bound(self.view, true, namespace, key, maximum)
    }
    pub fn custody_value_bound(
        &mut self,
        namespace: &str,
        key: &[u8],
        maximum: usize,
    ) -> Result<Option<usize>> {
        self.workspace
            .value_bound(self.view, false, namespace, key, maximum)
    }
}

impl PreparedTenantPointReads {
    pub fn require_domains(
        &self,
        application: &Arc<TenantStore>,
        custody: &Arc<TenantStore>,
    ) -> Result<()> {
        self.view.require_domains(application, custody)
    }

    pub fn require_memory(&self, expected: &Arc<dyn NodeDiskMemoryAdmission>) -> Result<()> {
        self.view.require_memory(expected)
    }

    /// Constructor-only ordinary scan on the same root as prepared point reads.
    /// The caller keeps its actual workspace through both pre-decode admission
    /// and the decoded-row callback. This is not a protected-source loan.
    pub fn custody_visit_with_workspace<W>(
        &mut self,
        namespace: &str,
        max_value_bytes: usize,
        workspace: &mut W,
        mut prepare: impl FnMut(&mut W, u64) -> Result<()>,
        mut visitor: impl FnMut(&mut W, &mut PreparedTenantPointBounds<'_>, &[u8], &[u8]) -> Result<()>,
    ) -> Result<()> {
        self.workspace.backing.clear_plaintext();
        let view = &self.view;
        let mut context = (workspace, &mut self.workspace);
        view.custody_visit_with_workspace(
            namespace,
            max_value_bytes,
            &mut context,
            |context, bytes| prepare(&mut *context.0, bytes),
            |context, key, value| {
                visitor(
                    &mut *context.0,
                    &mut PreparedTenantPointBounds {
                        workspace: &mut *context.1,
                        view,
                    },
                    key,
                    value,
                )
            },
        )
    }

    /// Preflight only the directory extent at this exact registered root. This
    /// supplies an allocation bound; it grants no authenticated content proof.
    pub fn application_value_bound(
        &mut self,
        namespace: &str,
        key: &[u8],
        maximum: usize,
    ) -> Result<Option<usize>> {
        self.workspace
            .value_bound(&self.view, true, namespace, key, maximum)
    }
    pub fn custody_value_bound(
        &mut self,
        namespace: &str,
        key: &[u8],
        maximum: usize,
    ) -> Result<Option<usize>> {
        self.workspace
            .value_bound(&self.view, false, namespace, key, maximum)
    }

    pub fn registered_reader_id(&self) -> Option<StorageOwnerId> {
        self.view.registered_reader_id()
    }

    pub fn application_get(
        &mut self,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&[u8]>> {
        self.get(true, namespace, key, max_value_bytes)
    }
    pub fn custody_get(
        &mut self,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&[u8]>> {
        self.get(false, namespace, key, max_value_bytes)
    }
    fn get(
        &mut self,
        application: bool,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&[u8]>> {
        self.workspace
            .get(&self.view, application, namespace, key, max_value_bytes)
    }

    /// Grow once after the producer knows its final proof records, before
    /// publication. Old and new grants coexist until successful replacement;
    /// refusal leaves the original backing and its reader intact.
    pub fn ensure_capacity(&mut self, namespace: usize, key: usize, value: usize) -> Result<()> {
        let previous = self.workspace.bounds();
        let next = (
            namespace.max(previous.0),
            key.max(previous.1),
            value.max(previous.2),
        );
        if next != previous {
            let replacement =
                PreparedTenantPointWorkspace::new(&self.view, next.0, next.1, next.2)?;
            let previous = std::mem::replace(&mut self.workspace, replacement);
            if let Err(payload) = previous.retire() {
                return Err(self
                    .view
                    .transaction
                    .as_ref()
                    .expect("live paired point view")
                    .point_retirement_failure(payload));
            }
        }
        Ok(())
    }

    /// Close this planning root and transfer only its actual admitted buffers.
    /// Failed operation/close outcomes remain owned by the registered reader.
    pub fn finish_with_workspace<T>(
        self,
        result: Result<T>,
    ) -> Result<(T, PreparedTenantPointWorkspace)> {
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
                    Err(payload) => Err(crate::PointRetirementFailure::new(error, payload).into()),
                },
            },
            Err(error) => {
                let retirement = workspace.retire();
                view.finish_point_retirement(Err(error), retirement)
            }
        }
    }

    /// Retire plaintext/native point backing, then settle the actual reader.
    /// Its registered census preserves any uncertain close outcome.
    pub fn close(self) -> Result<()> {
        self.finish(Ok(()))
    }

    /// Preserve the original operation error together with any registered close
    /// failure; returned data must already be owned independently of the loan.
    pub fn finish<T>(self, result: Result<T>) -> Result<T> {
        let Self { workspace, view } = self;
        let retirement = workspace.retire();
        view.finish_point_retirement(result, retirement)
    }
}

#[cfg(test)]
#[path = "prepared_point_read_tests.rs"]
mod tests;

#[path = "prepared_source_points.rs"]
mod source_points;
pub use source_points::{
    PreparedTenantSourcePointLoan, PreparedTenantSourcePointReads, PreparedTenantSourceReadView,
    SourceHistoryDisposition,
};
