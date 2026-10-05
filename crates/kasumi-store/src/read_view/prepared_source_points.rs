//! Exact single-domain protected sources using one preowned point workspace.
use super::*;

/// The actual registered captured root, independent of reusable point backing.
/// This is one Store; no synthetic application/custody pair is constructed.
#[repr(transparent)]
pub struct PreparedTenantReadSource(TenantReadView);

/// A temporary borrow of the actual protected root and its admitted backing.
/// It cannot open, fork, grow or detach a reader or retain a plaintext loan.
pub struct PreparedTenantReadSourceLoan<'a> {
    source: &'a PreparedTenantReadSource,
    workspace: &'a mut PreparedTenantReadWorkspace,
}

impl PreparedTenantReadWorkspace {
    /// Bind preowned point bytes to an already captured protected source.
    /// Every failure settles this actual reader and backing; no ordinary read
    /// or point admission is attempted during binding.
    pub fn bind_source(
        self,
        store: &Arc<TenantStore>,
        reader: RegisteredNodeRead,
    ) -> Result<(PreparedTenantReadSource, Self)> {
        let mut session = PreparedTenantReadPoints {
            workspace: self,
            view: TenantReadView {
                store: store.clone(),
                transaction: Some(ViewTransaction::Registered(reader)),
            },
        };
        let result = (|| {
            session.workspace.backing.clear_plaintext();
            let _access = AccessGuard(&session.view.store);
            session.workspace.require_store(store)?;
            store.check_access()?;
            let transaction = session
                .view
                .transaction
                .as_ref()
                .expect("owned source reader");
            let reader = match transaction {
                ViewTransaction::Registered(reader) => reader,
                #[cfg(any(test, feature = "test-utils"))]
                ViewTransaction::Fixture(_) => {
                    anyhow::bail!("source binder requires a registered reader")
                }
            };
            session.workspace.require_memory(&reader.provider())?;
            store.node.body().db.require_registered_read(reader)?;
            session
                .workspace
                .backing
                .verify_source_tables(reader)
                .map_err(|error| transaction.preserve_report(error.into()))?;
            store.check_access()?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                let PreparedTenantReadPoints { workspace, view } = session;
                Ok((PreparedTenantReadSource(view), workspace))
            }
            Err(error) => session.finish(Err(error)),
        }
    }
}

impl PreparedTenantReadSource {
    /// Borrow this exact captured root without acquiring ordinary capacity.
    /// Access is rechecked even before a loan that will only observe absence.
    pub fn point_reads<'a>(
        &'a self,
        workspace: &'a mut PreparedTenantReadWorkspace,
    ) -> Result<PreparedTenantReadSourceLoan<'a>> {
        workspace.backing.clear_plaintext();
        let _access = AccessGuard(&self.0.store);
        workspace.require_store(&self.0.store)?;
        let reader = self.reader();
        workspace.require_memory(&reader.provider())?;
        self.0.store.check_access()?;
        Ok(PreparedTenantReadSourceLoan {
            source: self,
            workspace,
        })
    }

    pub fn registered_reader_id(&self) -> StorageOwnerId {
        self.reader().id()
    }

    fn reader(&self) -> &RegisteredNodeRead {
        match self.0.transaction.as_ref().expect("protected source") {
            ViewTransaction::Registered(reader) => reader,
            #[cfg(any(test, feature = "test-utils"))]
            ViewTransaction::Fixture(_) => {
                unreachable!("protected source requires registered reader")
            }
        }
    }

    /// Settle this actual reader. Its source-capacity owner separately proves
    /// final pool/census retirement; closing a loan does not establish that.
    pub fn close(self) -> Result<()> {
        self.0.close()
    }
}

impl PreparedTenantReadSourceLoan<'_> {
    pub fn value_capacity(&self) -> usize {
        self.workspace.backing.bounds().2
    }

    pub fn get(&mut self, namespace: &str, key: &[u8], maximum: usize) -> Result<Option<&[u8]>> {
        self.workspace.get(&self.source.0, namespace, key, maximum)
    }
}

impl TenantStore {
    /// Queue actual protected source funding for this sole installed domain.
    /// The real registered opening retains partial installation outcomes.
    pub fn queue_source_capacity(&self) -> Result<crate::RegisteredSourceCapacity> {
        let _access = AccessGuard(self);
        self.check_access()?;
        ensure!(
            Arc::ptr_eq(self.node.memory(), self.scratch_disk().memory()),
            "source capacity domain uses different providers"
        );
        Ok(self.node.body().db.queue_source_capacity()?)
    }
}
