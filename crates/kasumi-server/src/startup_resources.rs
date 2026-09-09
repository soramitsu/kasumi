//! Resources retained before a runtime value can own them. These handles come
//! only from freshly claimed, exclusive physical node opens in the startup task;
//! this scope cannot accept another serving runtime's borrowed cached stores.
use anyhow::Result;
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct Resources {
    pub(crate) standalone_lock: Option<kasumi_store::private_files::ExclusiveLock>,
    pub(crate) nodes: Vec<Arc<kasumi_store::NodeStore>>,
    pub(crate) stores: Vec<Arc<kasumi_store::TenantStore>>,
    pub(crate) audits: Vec<Arc<kasumi_engine::SecurityAudit>>,
    pub(crate) verifiers: Vec<Arc<crate::signer_runtime::InstalledSignerVerifier>>,
    pub(crate) databases: Vec<Arc<kasumi_engine::Database>>,
    pub(crate) authorities: Vec<Arc<kasumi_authority::IndependentAuthority>>,
}
impl Resources {
    pub(crate) async fn close(&self) -> Result<()> {
        let mut failure = None;
        for authority in &self.authorities {
            if let Err(error) = authority.shutdown().await {
                failure.get_or_insert(error);
            }
        }
        for database in &self.databases {
            if let Err(error) = database.shutdown().await {
                failure.get_or_insert(error);
            }
        }
        for audit in &self.audits {
            audit.shutdown().await;
        }
        for store in &self.stores {
            store.shutdown().await;
        }
        for verifier in &self.verifiers {
            verifier.shutdown().await;
        }
        for node in &self.nodes {
            if let Err(error) = node.drain_initializers().await {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

impl crate::startup_owner::Runtime for Resources {
    fn close(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(Resources::close(self))
    }
}
