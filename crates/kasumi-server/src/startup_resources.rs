//! Unpublished owned resources from an exclusive node open or explicit new
//! catalogs on an already owned node. A borrowed node is retained only to join
//! its initializers; borrowed serving stores/databases never enter this scope.
use kasumi_types::drain::{DrainFailure, DrainReport, DrainResult};
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct Resources {
    report: tokio::sync::Mutex<DrainReport>,
    pub(crate) nodes: Vec<Arc<kasumi_store::NodeStore>>,
    pub(crate) stores: Vec<Arc<kasumi_store::TenantStore>>,
    pub(crate) audits: Vec<Arc<kasumi_engine::SecurityAudit>>,
    pub(crate) verifiers: Vec<Arc<crate::signer_runtime::InstalledSignerVerifier>>,
    pub(crate) databases: Vec<Arc<kasumi_engine::Database>>,
    pub(crate) authorities: Vec<Arc<kasumi_authority::IndependentAuthority>>,
    // Fields drop in declaration order: exclusive installation ownership must
    // outlive every retained worker and physical node handle.
    pub(crate) standalone_lock: Option<kasumi_store::private_files::ExclusiveLock>,
}
impl Resources {
    pub(crate) async fn close(&self) -> DrainResult {
        let mut report = self.report.lock().await;
        let mut retained = None;
        for (index, authority) in self.authorities.iter().enumerate() {
            if let Err(error) = authority.shutdown().await {
                // Until this child returns typed completion, keep its exact owner.
                retained = Some(DrainFailure::retained(report.record(
                    "authority",
                    index,
                    error,
                )));
            }
        }
        for (index, database) in self.databases.iter().enumerate() {
            if let Err(error) = database.shutdown().await {
                retained = Some(DrainFailure::retained(
                    report.record("database", index, error),
                ));
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
        for (index, node) in self.nodes.iter().enumerate() {
            if let Err(error) = node.drain_initializers().await {
                // This API returns a failure only after all registered handles
                // have actually joined. Preserve it without retrying forever.
                report.record("node initializers", index, error);
            }
        }
        report.outcome(retained)
    }
}

impl crate::startup_owner::Runtime for Resources {
    fn close(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = DrainResult> + Send + '_>> {
        Box::pin(Resources::close(self))
    }
}
