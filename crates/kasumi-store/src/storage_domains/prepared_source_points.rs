//! Encrypted loans over the real protected source, using preowned byte backing.
use super::*;

/// The source keeps its protected captured pin and registered history owner.
/// This transparent wrapper adds no backing or admission beyond the existing
/// paired point session. It exposes neither ordinary growth nor a raw view.
#[repr(transparent)]
pub struct PreparedTenantSourcePointReads(PreparedTenantPointReads);

impl PreparedTenantPointWorkspace {
    /// Bind existing actual point backing to an already captured protected read.
    /// All identities and canonical table tags are checked before the first
    /// plaintext loan. No ordinary begin, point grant, or fallback is attempted.
    pub fn bind_source(
        self,
        stores: &TenantStorageSet,
        reader: RegisteredNodeRead,
    ) -> Result<PreparedTenantSourcePointReads> {
        let mut session = PreparedTenantPointReads {
            workspace: self,
            view: TenantStorageReadView {
                application: stores.application.clone(),
                custody: stores.custody.store.clone(),
                transaction: Some(read_view::ViewTransaction::Registered(reader)),
            },
        };
        let result = (|| {
            let _application = AccessGuard(&session.view.application);
            let _custody = AccessGuard(&session.view.custody);
            session.workspace.require_stores(stores)?;
            session.view.application.check_access()?;
            session.view.custody.check_access()?;
            let transaction = session
                .view
                .transaction
                .as_ref()
                .expect("owned source reader");
            let reader = match transaction {
                read_view::ViewTransaction::Registered(reader) => reader,
                #[cfg(any(test, feature = "test-utils"))]
                read_view::ViewTransaction::Fixture(_) => {
                    anyhow::bail!("source binder requires a registered reader")
                }
            };
            session.view.require_memory(&reader.provider())?;
            session
                .view
                .application
                .node
                .body()
                .db
                .require_registered_read(reader)?;
            session
                .workspace
                .backing
                .verify_source_tables(reader)
                .map_err(|error| transaction.preserve_report(error.into()))?;
            session.view.application.check_access()?;
            session.view.custody.check_access()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(PreparedTenantSourcePointReads(session)),
            Err(error) => session.finish(Err(error)),
        }
    }
}

impl PreparedTenantSourcePointReads {
    /// Check the exact installed domains without exposing the protected view.
    pub fn require_domains(
        &self,
        application: &Arc<TenantStore>,
        custody: &Arc<TenantStore>,
    ) -> Result<()> {
        self.0.view.require_domains(application, custody)
    }
    /// Check both actual persistent and scratch owners of the protected pair.
    pub fn require_memory(&self, expected: &Arc<dyn NodeDiskMemoryAdmission>) -> Result<()> {
        self.0.view.require_memory(expected)
    }

    /// The actual owned plaintext ceiling, not a caller-supplied authorization
    /// or a growth request. Readers may use a stricter logical record limit.
    pub fn value_capacity(&self) -> usize {
        self.0.workspace.backing.bounds().2
    }
    pub fn registered_reader_id(&self) -> StorageOwnerId {
        self.0
            .registered_reader_id()
            .expect("registered protected source")
    }
    pub fn application_get(
        &mut self,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&[u8]>> {
        self.0.application_get(namespace, key, max_value_bytes)
    }
    pub fn custody_get(
        &mut self,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&[u8]>> {
        self.0.custody_get(namespace, key, max_value_bytes)
    }
    /// Fund this actual captured root as ordinary retained history before its
    /// first public escape. True is a positive native/metadata/census commit;
    /// false means its exact existing transition is still pending. A clean
    /// capacity refusal returns its original typed cause after restoring current.
    pub fn retain_history(&mut self) -> Result<bool> {
        retain_source_history(&self.0.view)
    }
    /// Separate immutable captured-root custody from the actual reusable byte
    /// backing after loans end. No reader is closed, cloned, reopened or forked.
    pub fn into_source(self) -> (PreparedTenantSourceReadView, PreparedTenantPointWorkspace) {
        let PreparedTenantPointReads { workspace, view } = self.0;
        (PreparedTenantSourceReadView(view), workspace)
    }
    pub fn close(self) -> Result<()> {
        self.0.close()
    }
    pub fn finish<T>(self, result: Result<T>) -> Result<T> {
        self.0.finish(result)
    }
}

/// Exact captured source custody without point buffers. An Engine cohort lends
/// its single actual backing for each serialized operation; historical roots
/// retain their registered snapshot/report independently of that scratch.
#[repr(transparent)]
pub struct PreparedTenantSourceReadView(TenantStorageReadView);

/// A temporary borrow of an actual protected root and actual admitted backing.
/// The loan has no raw transaction, close, fork, growth or ownership escape.
pub struct PreparedTenantSourcePointLoan<'a> {
    source: &'a PreparedTenantSourceReadView,
    workspace: &'a mut PreparedTenantPointWorkspace,
}
impl PreparedTenantSourceReadView {
    pub fn point_reads<'a>(
        &'a self,
        workspace: &'a mut PreparedTenantPointWorkspace,
    ) -> Result<PreparedTenantSourcePointLoan<'a>> {
        self.0
            .require_domains(&workspace.application, &workspace.custody)?;
        self.0.require_memory(workspace.application.node.memory())?;
        self.0.application.check_access()?;
        self.0.custody.check_access()?;
        Ok(PreparedTenantSourcePointLoan {
            source: self,
            workspace,
        })
    }
    pub fn registered_reader_id(&self) -> StorageOwnerId {
        let reader = match self.0.transaction.as_ref().expect("protected source") {
            read_view::ViewTransaction::Registered(reader) => reader,
            #[cfg(any(test, feature = "test-utils"))]
            read_view::ViewTransaction::Fixture(_) => {
                unreachable!("protected source requires a registered reader")
            }
        };
        reader.id()
    }
    pub fn retain_history(&self) -> Result<bool> {
        retain_source_history(&self.0)
    }
    pub fn close(self) -> Result<()> {
        self.0.close()
    }
}
impl PreparedTenantSourcePointLoan<'_> {
    pub fn require_domains(
        &self,
        application: &Arc<TenantStore>,
        custody: &Arc<TenantStore>,
    ) -> Result<()> {
        self.source.0.require_domains(application, custody)
    }
    pub fn require_memory(&self, expected: &Arc<dyn NodeDiskMemoryAdmission>) -> Result<()> {
        self.source.0.require_memory(expected)
    }
    pub fn value_capacity(&self) -> usize {
        self.workspace.backing.bounds().2
    }
    pub fn application_get(
        &mut self,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&[u8]>> {
        self.workspace
            .application_get(&self.source.0, namespace, key, max_value_bytes)
    }
    pub fn custody_get(
        &mut self,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<&[u8]>> {
        self.workspace
            .custody_get(&self.source.0, namespace, key, max_value_bytes)
    }
}
fn retain_source_history(view: &TenantStorageReadView) -> Result<bool> {
    let _application = AccessGuard(&view.application);
    let _custody = AccessGuard(&view.custody);
    view.application.check_access()?;
    view.custody.check_access()?;
    let transaction = view.transaction.as_ref().expect("protected source view");
    let reader = match transaction {
        read_view::ViewTransaction::Registered(reader) => reader,
        #[cfg(any(test, feature = "test-utils"))]
        read_view::ViewTransaction::Fixture(_) => {
            anyhow::bail!("protected source requires a registered reader")
        }
    };
    if !reader.source_history_complete() {
        reader.source_prepare_history();
        reader.source_commit_history();
    }
    if reader.source_history_complete() {
        view.application.check_access()?;
        view.custody.check_access()?;
        return Ok(true);
    }
    match reader.abort_source_history() {
        crate::SourceHistoryAbort::Restored {
            refusal: Some(refusal),
        } => Err(refusal.into()),
        crate::SourceHistoryAbort::Restored { refusal: None }
        | crate::SourceHistoryAbort::Pending => Ok(false),
        crate::SourceHistoryAbort::Retained if !reader.report().has_failures() => Ok(false),
        crate::SourceHistoryAbort::Retained => Err(crate::NodeScopedReadFailure::from_view(
            reader,
            NodeReadAccessError::Reported.into(),
        )
        .into()),
    }
}

impl TenantStorageSet {
    /// Queue the real registered source installation for this exact paired
    /// owner. The returned construction retains all partial installation state.
    pub fn queue_source_capacity(&self) -> Result<crate::RegisteredSourceCapacity> {
        let _application = AccessGuard(&self.application);
        let _custody = AccessGuard(&self.custody.store);
        self.application.check_access()?;
        self.custody.store.check_access()?;
        ensure!(
            NodeStore::ptr_eq(&self.application.node, &self.custody.store.node),
            "source capacity domains use different native owners"
        );
        let expected = self.application.node.memory();
        for store in [&self.application, &self.custody.store] {
            ensure!(
                Arc::ptr_eq(expected, store.node.memory())
                    && Arc::ptr_eq(expected, store.scratch_disk().memory()),
                "source capacity domains use different providers"
            );
        }
        Ok(self.application.node.body().db.queue_source_capacity()?)
    }
}

/// Callback-free observation for the Engine's separately admitted history
/// credit. In particular a postcommit access error must never refund a grant
/// whose native source has already become retained history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceHistoryDisposition {
    Current,
    Transition,
    History,
    Retained,
}
impl PreparedTenantSourceReadView {
    pub fn history_disposition(&self) -> SourceHistoryDisposition {
        let reader = match self.0.transaction.as_ref().expect("protected source") {
            read_view::ViewTransaction::Registered(reader) => reader,
            #[cfg(any(test, feature = "test-utils"))]
            read_view::ViewTransaction::Fixture(_) => return SourceHistoryDisposition::Retained,
        };
        if reader.source_history_complete() {
            SourceHistoryDisposition::History
        } else if reader.report().has_failures() {
            SourceHistoryDisposition::Retained
        } else if reader.phase() == crate::NodeReadPhase::SourceCaptured {
            SourceHistoryDisposition::Current
        } else {
            SourceHistoryDisposition::Transition
        }
    }
}
