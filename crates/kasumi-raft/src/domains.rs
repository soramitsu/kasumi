//! Runtime key ownership, selected only from validated installed lifecycle state.
use anyhow::{Context, Result, ensure};
use kasumi_store::{CustodyStore, TenantStorageSet, TenantStore, WriteOp};
use std::sync::Arc;

pub(crate) enum Domains {
    Serving(Arc<TenantStorageSet>),
    Custody(Arc<CustodyStore>),
}
impl Domains {
    pub fn custody(&self) -> &Arc<CustodyStore> {
        match self {
            Self::Serving(store) => store.custody(),
            Self::Custody(store) => store,
        }
    }
    pub fn serving(&self) -> Option<&Arc<TenantStorageSet>> {
        match self {
            Self::Serving(store) => Some(store),
            Self::Custody(_) => None,
        }
    }
    pub fn application(&self) -> Result<&Arc<TenantStore>> {
        Ok(self
            .serving()
            .context("retired custody has no application key domain")?
            .application())
    }
    pub fn write_batch(&self, application: &[WriteOp], custody: &[WriteOp]) -> Result<()> {
        match self {
            Self::Serving(store) => store.write_batch(application, custody),
            Self::Custody(store) => {
                ensure!(
                    application.is_empty(),
                    "application mutation forbidden in retired custody"
                );
                store.store().write_batch(custody)
            }
        }
    }
}
