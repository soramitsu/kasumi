//! Preadmitted paired-view census custody, with native root acquisition deferred.
use super::*;

/// Owns the exact registered read request before a paired publication. This
/// reserves its report and census entry, not a native snapshot slot or pin.
/// `begin` selects the root current at that later call and rechecks both domains.
pub struct PreparedTenantStorageReadView {
    application: Arc<TenantStore>,
    custody: Arc<TenantStore>,
    queued: Option<Queued>,
}

enum Queued {
    Registered(RegisteredNodeRead),
    #[cfg(any(test, feature = "test-utils"))]
    Fixture,
}

impl TenantStorageSet {
    pub fn prepare_read_view(&self) -> Result<PreparedTenantStorageReadView> {
        self.check_access()?;
        #[cfg(any(test, feature = "test-utils"))]
        if self
            .application
            .node
            .body()
            .db
            .has_fixture_direct_database()
        {
            return Ok(PreparedTenantStorageReadView {
                application: self.application.clone(),
                custody: self.custody.store.clone(),
                queued: Some(Queued::Fixture),
            });
        }
        let queued = self.application.node.body().db.queue_registered_read()?;
        if let Err(error) = self.check_access() {
            return self
                .application
                .node
                .cancel_queued_registered_read(queued, Err(error));
        }
        Ok(PreparedTenantStorageReadView {
            application: self.application.clone(),
            custody: self.custody.store.clone(),
            queued: Some(Queued::Registered(queued)),
        })
    }
}

impl PreparedTenantStorageReadView {
    pub fn registered_reader_id(&self) -> Option<StorageOwnerId> {
        match self.queued.as_ref().expect("live queued paired view") {
            Queued::Registered(reader) => Some(reader.id()),
            #[cfg(any(test, feature = "test-utils"))]
            Queued::Fixture => None,
        }
    }

    pub fn begin(mut self) -> Result<TenantStorageReadView> {
        let queued = self.queued.take().expect("live queued paired view");
        let access = self
            .application
            .check_access()
            .and_then(|_| self.custody.check_access());
        let transaction = match queued {
            Queued::Registered(reader) => {
                if let Err(error) = access {
                    return self
                        .application
                        .node
                        .cancel_queued_registered_read(reader, Err(error));
                }
                read_view::ViewTransaction::Registered(
                    self.application
                        .node
                        .begin_prepared_registered_read(reader)?,
                )
            }
            #[cfg(any(test, feature = "test-utils"))]
            Queued::Fixture => {
                access?;
                read_view::ViewTransaction::begin(&self.application.node)?
            }
        };
        if let Err(error) = self
            .application
            .check_access()
            .and_then(|_| self.custody.check_access())
        {
            return match transaction {
                read_view::ViewTransaction::Registered(reader) => self
                    .application
                    .node
                    .settle_registered_read(reader, Err(error)),
                #[cfg(any(test, feature = "test-utils"))]
                read_view::ViewTransaction::Fixture(_) => Err(error),
            };
        }
        Ok(TenantStorageReadView {
            application: self.application.clone(),
            custody: self.custody.clone(),
            transaction: Some(transaction),
        })
    }

    pub fn cancel(mut self) -> Result<()> {
        let deadline = std::time::Instant::now() + crate::NATIVE_READ_TIMEOUT;
        self.cancel_inner_until(Some(deadline))
    }

    fn cancel_inner(&mut self) -> Result<()> {
        self.cancel_inner_until(None)
    }

    fn cancel_inner_until(&mut self, deadline: Option<std::time::Instant>) -> Result<()> {
        match self.queued.take() {
            Some(Queued::Registered(reader)) => self
                .application
                .node
                .cancel_queued_registered_read_until(reader, Ok(()), deadline),
            #[cfg(any(test, feature = "test-utils"))]
            Some(Queued::Fixture) => Ok(()),
            None => Ok(()),
        }
    }
}

impl Drop for PreparedTenantStorageReadView {
    fn drop(&mut self) {
        // The exact registered owner retains any uncertain cancellation outcome.
        // Callers needing the original diagnostic use explicit cancel instead.
        let _ = self.cancel_inner();
    }
}
